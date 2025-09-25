"""ChatOps integration primitives."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import ssl
from typing import Any, Awaitable, Callable, Iterable, Mapping
from urllib.parse import urlparse

import msgspec

from .observability import Observability
from .serialization import json_encode
from .tenancy import TenantContext, TenantScope


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
            with urllib.request.urlopen(request, timeout=config.timeout, context=context) as response:
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
    "ChatOpsConfig",
    "ChatOpsError",
    "ChatOpsRoute",
    "ChatOpsService",
    "SlackWebhookConfig",
]
