"""ChatOps integration primitives."""

from __future__ import annotations

import asyncio
import inspect
import time
from contextlib import ExitStack
from typing import Any, Awaitable, Callable, Iterable, Mapping
from urllib.parse import urlparse

import msgspec

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


class ChatOpsInstrumentationConfig(msgspec.Struct, frozen=True):
    """Observability options for :class:`ChatOpsService`."""

    opentelemetry_enabled: bool = True
    opentelemetry_tracer: str = "artemis.chatops"
    opentelemetry_span_name: str = "artemis.chatops.send"
    sentry_enabled: bool = True
    sentry_record_breadcrumbs: bool = True
    sentry_capture_exceptions: bool = True
    sentry_breadcrumb_category: str = "chatops"
    sentry_breadcrumb_level: str = "info"
    datadog_enabled: bool = True
    datadog_metric_sent: str = "artemis.chatops.sent"
    datadog_metric_error: str = "artemis.chatops.errors"
    datadog_metric_timing: str = "artemis.chatops.duration"
    datadog_tags: tuple[tuple[str, str], ...] = ()


class ChatOpsConfig(msgspec.Struct, frozen=True):
    """Declarative ChatOps routing configuration."""

    enabled: bool = False
    default: SlackWebhookConfig | None = None
    routes: tuple[ChatOpsRoute, ...] = ()
    instrumentation: ChatOpsInstrumentationConfig = ChatOpsInstrumentationConfig()

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


class _InstrumentationContext:
    __slots__ = ("datadog_tags", "span", "stack", "start")

    def __init__(
        self,
        *,
        start: float,
        stack: ExitStack,
        span: Any | None,
        datadog_tags: tuple[str, ...],
    ) -> None:
        self.start = start
        self.stack = stack
        self.span = span
        self.datadog_tags = datadog_tags


class _NullInstrumentor:
    def on_send_start(
        self,
        tenant: TenantContext,
        message: ChatMessage,
        config: SlackWebhookConfig,
    ) -> _InstrumentationContext | None:
        return None  # pragma: no cover - trivial no-op

    def on_send_success(self, context: _InstrumentationContext | None) -> None:
        return None  # pragma: no cover - trivial no-op

    def on_send_error(self, context: _InstrumentationContext | None, error: BaseException) -> None:
        return None  # pragma: no cover - trivial no-op


class ChatOpsInstrumentor(_NullInstrumentor):
    """Integrate ChatOps events with tracing and monitoring systems."""

    def __init__(self, config: ChatOpsInstrumentationConfig | None = None) -> None:
        self.config = config or ChatOpsInstrumentationConfig()
        self._tracer = None
        self._span_kind = None
        self._status_cls = None
        self._status_code_cls = None
        self._status_ok = None
        self._status_error = None
        self._sentry_hub = None
        self._statsd = None
        self._prepare_opentelemetry()
        self._prepare_sentry()
        self._prepare_datadog()
        self._enabled = any((self._tracer, self._sentry_hub, self._statsd))

    # ------------------------------------------------------------------ lifecycle
    def _prepare_opentelemetry(self) -> None:
        if not self.config.opentelemetry_enabled:
            return
        try:
            from opentelemetry import trace  # type: ignore[import-not-found]
        except ImportError:  # pragma: no cover - optional dependency
            return
        self._tracer = trace.get_tracer(self.config.opentelemetry_tracer)
        try:
            from opentelemetry.trace import SpanKind  # type: ignore[import-not-found]
        except ImportError:  # pragma: no cover - optional dependency
            SpanKind = None
        self._span_kind = getattr(SpanKind, "CLIENT", None) if SpanKind is not None else None
        try:
            from opentelemetry.trace import Status, StatusCode  # type: ignore[import-not-found]
        except ImportError:  # pragma: no cover - optional dependency
            self._status_cls = None
            self._status_code_cls = None
        else:
            self._status_cls = Status
            self._status_code_cls = StatusCode
            self._status_ok = getattr(StatusCode, "OK", None)
            self._status_error = getattr(StatusCode, "ERROR", None)

    def _prepare_sentry(self) -> None:
        if not self.config.sentry_enabled:
            return
        try:
            import sentry_sdk  # type: ignore[import-not-found]
        except ImportError:  # pragma: no cover - optional dependency
            return
        self._sentry_hub = sentry_sdk.Hub.current

    def _prepare_datadog(self) -> None:
        if not self.config.datadog_enabled:
            return
        statsd = None
        try:
            from datadog import statsd as datadog_statsd  # type: ignore[import-not-found]
        except ImportError:  # pragma: no cover - optional dependency
            try:
                from ddtrace import statsd as ddtrace_statsd  # type: ignore[import-not-found]
            except ImportError:  # pragma: no cover - optional dependency
                ddtrace_statsd = None
            statsd = ddtrace_statsd
        else:
            statsd = datadog_statsd
        if statsd is not None:
            self._statsd = statsd

    # ------------------------------------------------------------------ helpers
    @property
    def enabled(self) -> bool:
        return self._enabled

    def _status(self, code: Any, description: str | None = None) -> Any | None:
        if self._status_cls is None or code is None:
            return None
        if description is None:
            return self._status_cls(code)
        return self._status_cls(code, description=description)

    def _datadog_tags(
        self,
        tenant: TenantContext,
        message: ChatMessage,
        config: SlackWebhookConfig,
    ) -> list[str]:
        tags = [
            f"tenant:{tenant.tenant}",
            f"scope:{tenant.scope.value}",
            f"site:{tenant.site}",
        ]
        channel = message.channel or config.default_channel
        if channel:
            tags.append(f"channel:{channel}")
        host = _webhook_host(config.webhook_url)
        if host:
            tags.append(f"webhook_host:{host}")
        for key, value in self.config.datadog_tags:
            tags.append(f"{key}:{value}")
        return tags

    def _breadcrumb_data(
        self,
        tenant: TenantContext,
        message: ChatMessage,
        config: SlackWebhookConfig,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "tenant": tenant.tenant,
            "scope": tenant.scope.value,
            "site": tenant.site,
        }
        channel = message.channel or config.default_channel
        if channel:
            data["channel"] = channel
        host = _webhook_host(config.webhook_url)
        if host:
            data["webhook_host"] = host
        data["message_length"] = len(message.text)
        return data

    def _decorate_span(
        self,
        span: Any,
        tenant: TenantContext,
        message: ChatMessage,
        config: SlackWebhookConfig,
    ) -> None:
        span.set_attribute("chatops.tenant", tenant.tenant)
        span.set_attribute("chatops.scope", tenant.scope.value)
        span.set_attribute("chatops.site", tenant.site)
        span.set_attribute("chatops.transport", "slack.webhook")
        host = _webhook_host(config.webhook_url)
        if host:
            span.set_attribute("chatops.webhook.host", host)
        channel = message.channel or config.default_channel
        if channel:
            span.set_attribute("chatops.channel", channel)
        span.set_attribute("chatops.message.length", len(message.text))

    def _configure_sentry_scope(
        self,
        scope: Any,
        tenant: TenantContext,
        message: ChatMessage,
        config: SlackWebhookConfig,
    ) -> None:
        if hasattr(scope, "set_tag"):
            scope.set_tag("chatops.tenant", tenant.tenant)
            scope.set_tag("chatops.scope", tenant.scope.value)
            host = _webhook_host(config.webhook_url)
            if host:
                scope.set_tag("chatops.webhook_host", host)
        if hasattr(scope, "set_extra"):
            channel = message.channel or config.default_channel or ""
            scope.set_extra("chatops.channel", channel)
            scope.set_extra("chatops.message_length", len(message.text))

    # ------------------------------------------------------------------ instrumentation API
    def on_send_start(
        self,
        tenant: TenantContext,
        message: ChatMessage,
        config: SlackWebhookConfig,
    ) -> _InstrumentationContext | None:
        if not self._enabled:
            return None
        tags = self._datadog_tags(tenant, message, config)
        stack = ExitStack()
        span = None
        if self._tracer is not None:
            span = stack.enter_context(
                self._tracer.start_as_current_span(
                    self.config.opentelemetry_span_name,
                    kind=self._span_kind,
                ),
            )
            self._decorate_span(span, tenant, message, config)
        if self._sentry_hub is not None:
            if self.config.sentry_record_breadcrumbs:
                self._sentry_hub.add_breadcrumb(
                    category=self.config.sentry_breadcrumb_category,
                    level=self.config.sentry_breadcrumb_level,
                    message=message.text,
                    data=self._breadcrumb_data(tenant, message, config),
                )
            scope = self._sentry_hub.push_scope()
            scope = stack.enter_context(scope)
            self._configure_sentry_scope(scope, tenant, message, config)
        return _InstrumentationContext(
            start=time.perf_counter(),
            stack=stack,
            span=span,
            datadog_tags=tuple(tags),
        )

    def on_send_success(self, context: _InstrumentationContext | None) -> None:
        if context is None:
            return
        if self._statsd is not None:
            tags = list(context.datadog_tags)
            self._statsd.increment(self.config.datadog_metric_sent, tags=tags)
            duration_ms = (time.perf_counter() - context.start) * 1000.0
            self._statsd.timing(self.config.datadog_metric_timing, duration_ms, tags=tags)
        if context.span is not None:
            context.span.set_attribute("chatops.result", "success")
            status = self._status(self._status_ok)
            if status is not None:
                context.span.set_status(status)
        context.stack.__exit__(None, None, None)

    def on_send_error(self, context: _InstrumentationContext | None, error: BaseException) -> None:
        if context is None:
            if self._sentry_hub is not None and self.config.sentry_capture_exceptions:
                self._sentry_hub.capture_exception(error)
            return
        if context.span is not None:
            context.span.set_attribute("chatops.result", "error")
            if hasattr(context.span, "record_exception"):
                context.span.record_exception(error)
            status = self._status(self._status_error, description=str(error))
            if status is not None:
                context.span.set_status(status)
        if self._statsd is not None:
            self._statsd.increment(self.config.datadog_metric_error, tags=list(context.datadog_tags))
        if self._sentry_hub is not None and self.config.sentry_capture_exceptions:
            self._sentry_hub.capture_exception(error)
        context.stack.__exit__(type(error), error, error.__traceback__)


class ChatOpsService:
    """High level ChatOps helper aware of tenancy."""

    def __init__(
        self,
        config: ChatOpsConfig,
        *,
        transport: TransportCallable | None = None,
        instrumentation: ChatOpsInstrumentor | None = None,
    ) -> None:
        self.config = config
        self._transport = transport
        self._clients: dict[str, SlackWebhookClient] = {}
        self._instrumentation: _NullInstrumentor = instrumentation or ChatOpsInstrumentor(config.instrumentation)

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def is_configured(self, tenant: TenantContext) -> bool:
        return self.config.config_for(tenant) is not None

    async def send(self, tenant: TenantContext, message: ChatMessage) -> None:
        config = self._require_config(tenant)
        client = self._client_for(config)
        context = await _maybe_await(self._instrumentation.on_send_start(tenant, message, config))
        try:
            await client.send(message)
        except Exception as exc:
            await _maybe_await(self._instrumentation.on_send_error(context, exc))
            raise
        else:
            await _maybe_await(self._instrumentation.on_send_success(context))

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
            with urllib.request.urlopen(request, timeout=config.timeout) as response:
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


__all__ = [
    "ChatMessage",
    "ChatOpsConfig",
    "ChatOpsError",
    "ChatOpsInstrumentationConfig",
    "ChatOpsInstrumentor",
    "ChatOpsRoute",
    "ChatOpsService",
    "SlackWebhookConfig",
]
