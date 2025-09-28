"""ChatOps integration primitives."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import shlex
import ssl
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterable, Literal, Mapping, Protocol, Sequence
from urllib.parse import urlparse

import msgspec

from .dependency import DependencyScope
from .observability import Observability
from .serialization import json_encode
from .tenancy import TenantContext, TenantScope

if TYPE_CHECKING:  # pragma: no cover - used for typing only
    from .requests import Request


class ChatOpsError(RuntimeError):
    """Raised when chat notifications cannot be delivered."""


class ChatMessage(msgspec.Struct, frozen=True):
    """Typed representation of a chat notification payload."""

    text: str
    channel: str | None = None
    username: str | None = None
    icon_emoji: str | None = None
    thread_ts: str | None = None
    attachments: tuple[dict[str, Any], ...] = msgspec.field(default_factory=tuple)
    blocks: tuple[dict[str, Any], ...] = msgspec.field(default_factory=tuple)
    extra: dict[str, Any] = msgspec.field(default_factory=dict)


class SlackWebhookConfig(msgspec.Struct, frozen=True):
    """Configuration for a Slack incoming webhook."""

    webhook_url: str
    default_channel: str | None = None
    username: str | None = None
    icon_emoji: str | None = None
    timeout: float = 5.0
    allowed_hosts: tuple[str, ...] = ()
    certificate_pins: tuple[str, ...] = ()


class ChatOpsRoute(msgspec.Struct, frozen=True):
    """Route chat notifications based on tenant scope or identifier."""

    config: SlackWebhookConfig
    tenant: str | None = None
    scope: TenantScope | None = None

    def matches(self, tenant: TenantContext) -> bool:
        if self.tenant is not None and self.tenant != tenant.tenant:
            return False
        if self.scope is not None and self.scope is not tenant.scope:
            return False
        return True


class ChatOpsConfig(msgspec.Struct, frozen=True):
    """Declarative ChatOps routing configuration."""

    enabled: bool = False
    default: SlackWebhookConfig | None = None
    routes: tuple[ChatOpsRoute, ...] = ()

    def config_for(self, tenant: TenantContext) -> SlackWebhookConfig | None:
        """Return the webhook configuration for ``tenant`` if available."""

        if not self.enabled:
            return None
        for route in self.routes:
            if route.matches(tenant):
                return route.config
        return self.default


TransportCallable = Callable[[SlackWebhookConfig, bytes, Mapping[str, str]], Awaitable[None] | None]


SlashCommandVisibility = Literal["admin", "public"]


class ChatOpsSlashCommand(msgspec.Struct, frozen=True):
    """Declarative metadata describing a slash command surface."""

    name: str
    description: str
    visibility: SlashCommandVisibility = "admin"
    aliases: tuple[str, ...] = msgspec.field(default_factory=tuple)


class ChatOpsCommandContext(msgspec.Struct, frozen=True):
    """Context passed to ChatOps command handlers."""

    request: "Request"
    payload: ChatOpsSlashCommandInvocation
    args: Mapping[str, str]
    actor: str
    dependencies: DependencyScope


class ChatOpsCommandHandler(Protocol):
    """Callable signature for ChatOps command handlers."""

    async def __call__(self, context: ChatOpsCommandContext) -> Mapping[str, Any] | Any:  # pragma: no cover - protocol
        ...


class ChatOpsCommandBinding(msgspec.Struct, frozen=True):
    """Associates a slash command definition with its handler."""

    command: ChatOpsSlashCommand
    handler: ChatOpsCommandHandler
    name: str


class ChatOpsCommandRegistry:
    """Registry tracking ChatOps slash command bindings."""

    def __init__(self) -> None:
        self._bindings: list[ChatOpsCommandBinding] = []

    def register(self, binding: ChatOpsCommandBinding) -> None:
        self._bindings = [b for b in self._bindings if b.name != binding.name]
        self._bindings.append(binding)

    def bindings(self) -> tuple[ChatOpsCommandBinding, ...]:
        return tuple(self._bindings)

    def commands(self) -> tuple[ChatOpsSlashCommand, ...]:
        return tuple(binding.command for binding in self._bindings)

    def binding_by_name(self, name: str) -> ChatOpsCommandBinding:
        for binding in self._bindings:
            if binding.name == name:
                return binding
        raise LookupError(f"No ChatOps binding registered with name '{name}'")

    def binding_for(self, command: ChatOpsSlashCommand) -> ChatOpsCommandBinding:
        for binding in self._bindings:
            if binding.command is command:
                return binding
            if (
                binding.command.name == command.name
                and binding.command.visibility == command.visibility
                and binding.command.aliases == command.aliases
            ):
                return binding
        raise LookupError(f"No ChatOps binding registered for command '{command.name}'")


class ChatOpsCommandResolutionError(ChatOpsError):
    """Raised when a slash command cannot be resolved for a tenant."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ChatOpsInvocationError(ChatOpsError):
    """Raised when a chat invocation payload cannot be parsed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ChatOpsSlashCommandInvocation(Protocol):
    """Protocol describing the attributes required for invocation parsing."""

    text: str
    command: str | None


def parse_slash_command_args(text: str) -> dict[str, str]:
    """Parse ``key=value`` arguments from ``text`` into a dictionary."""

    args: dict[str, str] = {}
    try:
        tokens = shlex.split(text, posix=True)
        advanced = True
    except ValueError:  # pragma: no cover - defensive parsing guard
        tokens = text.split()
        advanced = False
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        normalized_key = key.strip().lower()
        if not normalized_key:
            continue
        if advanced:
            args[normalized_key] = value
        else:
            args[normalized_key] = value.strip().strip("\"'")
    return args


class SlackWebhookClient:
    """Send messages to a Slack webhook endpoint."""

    def __init__(self, config: SlackWebhookConfig, *, transport: TransportCallable | None = None) -> None:
        self.config = config
        self._transport = transport or _default_transport
        self._allowed_hosts = tuple(host.lower() for host in config.allowed_hosts)
        parsed = urlparse(config.webhook_url)
        scheme = (parsed.scheme or "").lower()
        if scheme != "https":
            raise ChatOpsError("Slack webhook URLs must use HTTPS")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ChatOpsError("Slack webhook URL must include a host")
        if self._allowed_hosts and host not in self._allowed_hosts:
            raise ChatOpsError(f"Slack webhook host '{host}' is not allowed")
        self._host = host

    async def send(self, message: ChatMessage) -> None:
        payload = self._encode(message)
        headers = {"content-type": "application/json; charset=utf-8"}
        await _invoke_transport(self._transport, self.config, payload, headers)

    def _encode(self, message: ChatMessage) -> bytes:
        payload: dict[str, Any] = {"text": message.text}
        channel = message.channel or self.config.default_channel
        if channel:
            payload["channel"] = channel
        username = message.username or self.config.username
        if username:
            payload["username"] = username
        icon = message.icon_emoji or self.config.icon_emoji
        if icon:
            payload["icon_emoji"] = icon
        if message.thread_ts:
            payload["thread_ts"] = message.thread_ts
        if message.attachments:
            payload["attachments"] = [dict(attachment) for attachment in message.attachments]
        if message.blocks:
            payload["blocks"] = [dict(block) for block in message.blocks]
        if message.extra:
            payload.update(message.extra)
        return json_encode(payload)


class ChatOpsService:
    """High level ChatOps helper aware of tenancy."""

    def __init__(
        self,
        config: ChatOpsConfig,
        *,
        transport: TransportCallable | None = None,
        observability: Observability | None = None,
    ) -> None:
        self.config = config
        self._transport = transport
        self._clients: dict[str, SlackWebhookClient] = {}
        self._observability = observability or Observability()

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def is_configured(self, tenant: TenantContext) -> bool:
        return self.config.config_for(tenant) is not None

    def normalize_command_token(self, raw: str) -> str:
        """Return a normalized command token suitable for comparison."""

        token = raw.strip().lower()
        if token.startswith("/"):
            token = token[1:]
        return token

    def resolve_slash_command(
        self,
        token: str,
        commands: Sequence[ChatOpsSlashCommand],
        *,
        tenant: TenantContext,
        workspace_id: str | None,
        admin_workspace: str | None,
    ) -> ChatOpsSlashCommand:
        """Resolve ``token`` against ``commands`` honoring visibility rules."""

        normalized = self.normalize_command_token(token)
        for command in commands:
            candidates = (command.name, *command.aliases)
            for candidate in candidates:
                if self.normalize_command_token(candidate) != normalized:
                    continue
                if command.visibility == "admin":
                    if tenant.scope is not TenantScope.ADMIN:
                        raise ChatOpsCommandResolutionError("admin_command")
                    if admin_workspace is None or workspace_id is None or workspace_id != admin_workspace:
                        raise ChatOpsCommandResolutionError("workspace_forbidden")
                else:
                    if tenant.scope is not TenantScope.ADMIN and not self.is_configured(tenant):
                        raise ChatOpsCommandResolutionError("chatops_unconfigured")
                return command
        raise ChatOpsCommandResolutionError("unknown_command")

    def extract_command_from_invocation(
        self,
        payload: ChatOpsSlashCommandInvocation,
        *,
        bot_user_id: str | None,
    ) -> tuple[str, str]:
        """Return the command token and remaining argument text from ``payload``."""

        if payload.command:
            normalized_command = self.normalize_command_token(payload.command)
            return normalized_command, payload.text
        tokens = payload.text.split()
        if not tokens:
            raise ChatOpsInvocationError("missing_command")
        if bot_user_id is None:
            raise ChatOpsInvocationError("bot_user_unconfigured")
        mention = tokens.pop(0)
        mention_id: str | None
        if mention.startswith("<@") and mention.endswith(">"):
            mention_id = mention[2:-1].split("|", 1)[0]
        elif mention.startswith("@"):
            mention_id = mention[1:]
        else:
            mention_id = mention
        if mention_id != bot_user_id:
            raise ChatOpsInvocationError("invalid_bot_mention")
        if not tokens:
            raise ChatOpsInvocationError("missing_command")
        command_token = tokens.pop(0)
        command_name = self.normalize_command_token(command_token)
        arg_text = " ".join(tokens)
        return command_name, arg_text

    async def send(self, tenant: TenantContext, message: ChatMessage) -> None:
        config = self._require_config(tenant)
        client = self._client_for(config)
        context = await _maybe_await(self._observability.on_chatops_send_start(tenant, message, config))
        try:
            await client.send(message)
        except Exception as exc:
            await _maybe_await(self._observability.on_chatops_send_error(context, exc))
            raise
        else:
            await _maybe_await(self._observability.on_chatops_send_success(context))

    async def broadcast(self, tenants: Iterable[TenantContext], message: ChatMessage) -> None:
        await asyncio.gather(*(self.send(tenant, message) for tenant in tenants))

    def _require_config(self, tenant: TenantContext) -> SlackWebhookConfig:
        config = self.config.config_for(tenant)
        if config is None:
            raise ChatOpsError(f"No ChatOps configuration for tenant '{tenant.key()}'")
        return config

    def _client_for(self, config: SlackWebhookConfig) -> SlackWebhookClient:
        key = config.webhook_url
        client = self._clients.get(key)
        if client is None:
            client = SlackWebhookClient(config, transport=self._transport)
            self._clients[key] = client
        return client


def _webhook_host(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:  # pragma: no cover - defensive parsing guard
        return None
    return parsed.hostname or parsed.netloc or None


async def _maybe_await(result: Any) -> Any:
    if inspect.isawaitable(result):
        return await result
    return result


async def _invoke_transport(
    transport: TransportCallable,
    config: SlackWebhookConfig,
    payload: bytes,
    headers: Mapping[str, str],
) -> None:
    result = transport(config, payload, headers)
    if inspect.isawaitable(result):
        await result


async def _default_transport(
    config: SlackWebhookConfig,
    payload: bytes,
    headers: Mapping[str, str],
) -> None:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        config.webhook_url,
        data=payload,
        headers=dict(headers),
        method="POST",
    )

    def _send() -> None:
        try:
            context = ssl.create_default_context()
            base_host = _webhook_host(config.webhook_url)
            allowed_redirect_hosts = {value.lower() for value in config.allowed_hosts}
            if base_host:
                allowed_redirect_hosts.add(base_host.lower())

            class _RedirectValidator(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
                    parsed = urlparse(newurl)
                    scheme = (parsed.scheme or "").lower()
                    if scheme != "https":
                        raise ChatOpsError("Slack webhook redirected to a non-HTTPS endpoint")
                    host = (parsed.hostname or "").lower()
                    if not host:
                        raise ChatOpsError("Slack webhook redirect missing destination host")
                    if allowed_redirect_hosts and host not in allowed_redirect_hosts:
                        raise ChatOpsError(f"Slack webhook redirect to disallowed host '{host}'")
                    raise ChatOpsError(
                        f"Slack webhook redirect to '{host}' is not supported",
                    )

            https_handler = urllib.request.HTTPSHandler(context=context)
            opener = urllib.request.build_opener(_RedirectValidator(), https_handler)
            with opener.open(request, timeout=config.timeout) as response:
                _ensure_tls_destination(response, config)
                if config.certificate_pins:
                    _validate_certificate_pin(response, config.certificate_pins)
                status = getattr(response, "status", response.getcode())
                if status >= 400:
                    raise ChatOpsError(
                        f"Slack webhook {config.webhook_url!r} returned unexpected status {status}",
                    )
        except urllib.error.HTTPError as exc:  # pragma: no cover - depends on network I/O
            raise ChatOpsError(
                f"Slack webhook {config.webhook_url!r} failed with status {exc.code}",
            ) from exc
        except urllib.error.URLError as exc:  # pragma: no cover - depends on network I/O
            raise ChatOpsError(f"Failed to reach Slack webhook {config.webhook_url!r}: {exc.reason}") from exc

    await asyncio.to_thread(_send)


def _ensure_tls_destination(response: Any, config: SlackWebhookConfig) -> None:
    final_url = response.geturl()
    parsed = urlparse(final_url)
    scheme = (parsed.scheme or "").lower()
    if scheme != "https":
        raise ChatOpsError("Slack webhook redirected to a non-HTTPS endpoint")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ChatOpsError("Slack webhook response missing destination host")
    allowed = {value.lower() for value in config.allowed_hosts}
    if not allowed:
        base_host = _webhook_host(config.webhook_url)
        if base_host:
            allowed.add(base_host.lower())
    if allowed and host not in allowed:
        raise ChatOpsError(f"Slack webhook resolved to disallowed host '{host}'")


def _validate_certificate_pin(response: Any, pins: Iterable[str]) -> None:
    raw = getattr(getattr(response, "fp", None), "raw", None)
    sslobj = getattr(raw, "_sslobj", None)
    if sslobj is None:
        raise ChatOpsError("TLS connection does not expose certificate for pinning")
    try:
        certificate = sslobj.getpeercert(True)
    except Exception as exc:  # pragma: no cover - depends on ssl implementation
        raise ChatOpsError("Unable to read TLS certificate for pinning") from exc
    fingerprint = hashlib.sha256(certificate).hexdigest().lower()
    normalized = {pin.lower() for pin in pins}
    if fingerprint not in normalized:
        raise ChatOpsError("Slack webhook certificate pin mismatch")


__all__ = [
    "ChatMessage",
    "ChatOpsCommandResolutionError",
    "ChatOpsConfig",
    "ChatOpsError",
    "ChatOpsInvocationError",
    "ChatOpsRoute",
    "ChatOpsService",
    "ChatOpsSlashCommand",
    "ChatOpsSlashCommandInvocation",
    "SlackWebhookConfig",
    "SlashCommandVisibility",
    "parse_slash_command_args",
]
