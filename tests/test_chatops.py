from __future__ import annotations

import asyncio
import sys
import types
from typing import Any

import pytest

from artemis import (
    AppConfig,
    ArtemisApp,
    ChatMessage,
    ChatOpsConfig,
    ChatOpsError,
    ChatOpsInstrumentationConfig,
    ChatOpsInstrumentor,
    ChatOpsRoute,
    ChatOpsService,
    SlackWebhookConfig,
    TenantContext,
    TenantScope,
    TestClient,
)
from artemis.chatops import _default_transport, _maybe_await, _webhook_host
from artemis.serialization import json_decode


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[SlackWebhookConfig, bytes, dict[str, str]]] = []

    async def __call__(
        self,
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str] | None,
    ) -> None:
        await asyncio.sleep(0)
        self.calls.append((config, payload, dict(headers or {})))


class StubSpan:
    def __init__(self, name: str, kind: Any) -> None:
        self.name = name
        self.kind = kind
        self.attributes: dict[str, Any] = {}
        self.status: Any | None = None
        self.exceptions: list[BaseException] = []
        self.exit_exception: BaseException | None = None
        self.ended = False

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def record_exception(self, exc: BaseException) -> None:
        self.exceptions.append(exc)

    def set_status(self, status: Any) -> None:
        self.status = status


class StubSpanContext:
    def __init__(self, span: StubSpan) -> None:
        self.span = span

    def __enter__(self) -> StubSpan:
        return self.span

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.span.ended = True
        if exc is not None:
            self.span.exit_exception = exc
        return False


class StubTracer:
    def __init__(self) -> None:
        self.spans: list[StubSpan] = []

    def start_as_current_span(self, name: str, kind: Any | None = None) -> StubSpanContext:
        span = StubSpan(name, kind)
        self.spans.append(span)
        return StubSpanContext(span)


class StubScope:
    def __init__(self) -> None:
        self.tags: dict[str, Any] = {}
        self.extra: dict[str, Any] = {}

    def __enter__(self) -> StubScope:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def set_tag(self, key: str, value: Any) -> None:
        self.tags[key] = value

    def set_extra(self, key: str, value: Any) -> None:
        self.extra[key] = value


class StubSentryHub:
    def __init__(self) -> None:
        self.breadcrumbs: list[dict[str, Any]] = []
        self.captured: list[BaseException] = []
        self.scopes: list[StubScope] = []

    def add_breadcrumb(self, **breadcrumb: Any) -> None:
        self.breadcrumbs.append(breadcrumb)

    def capture_exception(self, exc: BaseException) -> None:
        self.captured.append(exc)

    def push_scope(self) -> StubScope:
        scope = StubScope()
        self.scopes.append(scope)
        return scope


class StubStatsd:
    def __init__(self) -> None:
        self.increments: list[tuple[str, float, tuple[str, ...]]] = []
        self.timings: list[tuple[str, float, tuple[str, ...]]] = []

    def increment(self, metric: str, value: float = 1.0, tags: list[str] | None = None) -> None:
        self.increments.append((metric, value, tuple(tags or ())))

    def timing(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        self.timings.append((metric, value, tuple(tags or ())))


def setup_stub_opentelemetry(monkeypatch: pytest.MonkeyPatch) -> StubTracer:
    tracer = StubTracer()
    trace_module = types.ModuleType("opentelemetry.trace")
    trace_module.get_tracer = lambda name: tracer
    trace_module.SpanKind = types.SimpleNamespace(CLIENT="client")

    class Status:
        def __init__(self, status_code: Any, description: str | None = None) -> None:
            self.status_code = status_code
            self.description = description

    trace_module.Status = Status
    trace_module.StatusCode = types.SimpleNamespace(OK="ok", ERROR="error")
    otel_module = types.ModuleType("opentelemetry")
    otel_module.trace = trace_module
    monkeypatch.setitem(sys.modules, "opentelemetry", otel_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace_module)
    return tracer


def setup_stub_opentelemetry_without_status(monkeypatch: pytest.MonkeyPatch) -> StubTracer:
    tracer = StubTracer()
    trace_module = types.ModuleType("opentelemetry.trace")
    trace_module.get_tracer = lambda name: tracer
    trace_module.SpanKind = types.SimpleNamespace(CLIENT="client")
    otel_module = types.ModuleType("opentelemetry")
    otel_module.trace = trace_module
    monkeypatch.setitem(sys.modules, "opentelemetry", otel_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace_module)
    return tracer


class NoRecordSpan:
    def __init__(self, name: str, kind: Any | None) -> None:
        self.name = name
        self.kind = kind
        self.attributes: dict[str, Any] = {}
        self.status: Any | None = None
        self.ended = False

    def __enter__(self) -> "NoRecordSpan":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.ended = True
        return False

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def set_status(self, status: Any) -> None:
        self.status = status


class NoRecordTracer:
    def __init__(self) -> None:
        self.spans: list[NoRecordSpan] = []

    def start_as_current_span(self, name: str, kind: Any | None = None) -> NoRecordSpan:
        span = NoRecordSpan(name, kind)
        self.spans.append(span)
        return span


def setup_stub_opentelemetry_without_record(monkeypatch: pytest.MonkeyPatch) -> NoRecordTracer:
    tracer = NoRecordTracer()
    trace_module = types.ModuleType("opentelemetry.trace")
    trace_module.get_tracer = lambda name: tracer
    trace_module.SpanKind = types.SimpleNamespace(CLIENT="client")

    class Status:
        def __init__(self, status_code: Any, description: str | None = None) -> None:
            self.status_code = status_code
            self.description = description

    trace_module.Status = Status
    trace_module.StatusCode = types.SimpleNamespace(OK="ok", ERROR="error")
    otel_module = types.ModuleType("opentelemetry")
    otel_module.trace = trace_module
    monkeypatch.setitem(sys.modules, "opentelemetry", otel_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace_module)
    return tracer


def setup_stub_sentry(monkeypatch: pytest.MonkeyPatch) -> StubSentryHub:
    hub = StubSentryHub()

    class Hub:
        current = hub

    sentry_module = types.ModuleType("sentry_sdk")
    sentry_module.Hub = Hub
    monkeypatch.setitem(sys.modules, "sentry_sdk", sentry_module)
    return hub


def setup_stub_datadog(monkeypatch: pytest.MonkeyPatch) -> StubStatsd:
    statsd = StubStatsd()
    datadog_module = types.ModuleType("datadog")
    datadog_module.statsd = statsd
    monkeypatch.setitem(sys.modules, "datadog", datadog_module)
    return statsd


@pytest.mark.asyncio
async def test_chatops_routes_per_tenant() -> None:
    transport = RecordingTransport()
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(
            webhook_url="https://hooks.slack.com/services/default",
            default_channel="#general",
            username="artemis",
        ),
        routes=(
            ChatOpsRoute(
                tenant="acme",
                config=SlackWebhookConfig(
                    webhook_url="https://hooks.slack.com/services/acme",
                    default_channel="#acme",
                    username="acme-bot",
                    icon_emoji=":rocket:",
                ),
            ),
            ChatOpsRoute(
                scope=TenantScope.ADMIN,
                config=SlackWebhookConfig(
                    webhook_url="https://hooks.slack.com/services/admin",
                    default_channel="#admins",
                ),
            ),
        ),
    )
    service = ChatOpsService(config, transport=transport)

    acme = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    beta = TenantContext(tenant="beta", site="demo", domain="example.com", scope=TenantScope.TENANT)
    admin = TenantContext(tenant="admin", site="demo", domain="example.com", scope=TenantScope.ADMIN)

    await service.send(acme, ChatMessage(text="Acme ready"))
    await service.send(
        beta,
        ChatMessage(
            text="Beta update",
            channel="#beta",
            icon_emoji=":beta:",
            thread_ts="123.45",
            attachments=({"type": "section", "text": {"type": "mrkdwn", "text": "Beta"}},),
            blocks=({"type": "context", "elements": [{"type": "mrkdwn", "text": "Context"}]},),
            extra={"metadata": {"event_type": "beta"}},
        ),
    )
    await service.send(admin, ChatMessage(text="Admin alert"))

    assert [call[0].webhook_url for call in transport.calls] == [
        "https://hooks.slack.com/services/acme",
        "https://hooks.slack.com/services/default",
        "https://hooks.slack.com/services/admin",
    ]

    acme_payload = json_decode(transport.calls[0][1])
    assert acme_payload["channel"] == "#acme"
    assert acme_payload["username"] == "acme-bot"
    assert acme_payload["icon_emoji"] == ":rocket:"
    beta_payload = json_decode(transport.calls[1][1])
    assert beta_payload["channel"] == "#beta"
    assert beta_payload["icon_emoji"] == ":beta:"
    assert beta_payload["thread_ts"] == "123.45"
    assert beta_payload["attachments"] == [
        {"type": "section", "text": {"type": "mrkdwn", "text": "Beta"}},
    ]
    assert beta_payload["blocks"] == [
        {"type": "context", "elements": [{"type": "mrkdwn", "text": "Context"}]},
    ]
    assert beta_payload["metadata"] == {"event_type": "beta"}
    admin_payload = json_decode(transport.calls[2][1])
    assert admin_payload["channel"] == "#admins"


@pytest.mark.asyncio
async def test_chatops_requires_route() -> None:
    service = ChatOpsService(ChatOpsConfig(enabled=True))
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    with pytest.raises(ChatOpsError):
        await service.send(tenant, ChatMessage(text="missing"))


@pytest.mark.asyncio
async def test_chatops_disabled_config() -> None:
    config = ChatOpsConfig(
        enabled=False,
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default"),
    )
    service = ChatOpsService(config)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    assert not service.enabled
    assert not service.is_configured(tenant)
    with pytest.raises(ChatOpsError):
        await service.send(tenant, ChatMessage(text="disabled"))


@pytest.mark.asyncio
async def test_chatops_dependency_integration() -> None:
    transport = RecordingTransport()
    chatops_config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(
            webhook_url="https://hooks.slack.com/services/default",
            default_channel="#general",
        ),
    )
    config = AppConfig(
        site="demo",
        domain="example.com",
        allowed_tenants=("acme", "beta"),
        chatops=chatops_config,
    )
    chatops_service = ChatOpsService(chatops_config, transport=transport)
    app = ArtemisApp(config=config, chatops=chatops_service)

    @app.post("/notify")
    async def notify(chatops: ChatOpsService, tenant: TenantContext) -> dict[str, Any]:
        await chatops.send(tenant, ChatMessage(text=f"update::{tenant.tenant}"))
        return {"ok": True}

    async with TestClient(app) as client:
        acme = await client.post("/notify", tenant="acme")
        beta = await client.post("/notify", tenant="beta")

    assert json_decode(acme.body) == {"ok": True}
    assert json_decode(beta.body) == {"ok": True}
    assert [json_decode(call[1])["text"] for call in transport.calls] == [
        "update::acme",
        "update::beta",
    ]


@pytest.mark.asyncio
async def test_chatops_broadcast_and_sync_transport() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def sync_transport(config: SlackWebhookConfig, payload: bytes, headers: dict[str, str]) -> None:
        calls.append((config.webhook_url, json_decode(payload)))

    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(
            webhook_url="https://hooks.slack.com/services/default",
            default_channel="#general",
        ),
    )
    service = ChatOpsService(config, transport=sync_transport)
    tenants = [
        TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
        TenantContext(tenant="beta", site="demo", domain="example.com", scope=TenantScope.TENANT),
    ]

    await service.broadcast(tenants, ChatMessage(text="broadcast"))

    assert [call[0] for call in calls] == [
        "https://hooks.slack.com/services/default",
        "https://hooks.slack.com/services/default",
    ]
    assert all(payload["text"] == "broadcast" for _, payload in calls)


@pytest.mark.asyncio
async def test_chatops_instrumentation_success(monkeypatch: pytest.MonkeyPatch) -> None:
    tracer = setup_stub_opentelemetry(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)

    transport = RecordingTransport()
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(
            webhook_url="https://hooks.slack.com/services/default-token",
            default_channel="#ops",
        ),
        instrumentation=ChatOpsInstrumentationConfig(datadog_tags=(("env", "test"),)),
    )
    service = ChatOpsService(config, transport=transport)

    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    admin = TenantContext(tenant="admin", site="demo", domain="example.com", scope=TenantScope.ADMIN)

    await service.send(tenant, ChatMessage(text="tenant alert", channel="#alerts"))
    await service.send(admin, ChatMessage(text="admin alert"))

    assert [span.name for span in tracer.spans] == ["artemis.chatops.send", "artemis.chatops.send"]
    first_span, second_span = tracer.spans
    assert first_span.attributes["chatops.tenant"] == "acme"
    assert first_span.attributes["chatops.scope"] == "tenant"
    assert first_span.attributes["chatops.channel"] == "#alerts"
    assert first_span.attributes["chatops.webhook.host"] == "hooks.slack.com"
    assert getattr(first_span.status, "status_code", None) == "ok"
    assert first_span.ended

    assert second_span.attributes["chatops.tenant"] == "admin"
    assert second_span.attributes["chatops.scope"] == "admin"
    assert second_span.attributes["chatops.channel"] == "#ops"
    assert getattr(second_span.status, "status_code", None) == "ok"
    assert second_span.ended

    assert [crumb["data"]["tenant"] for crumb in hub.breadcrumbs] == ["acme", "admin"]
    assert hub.scopes[0].tags["chatops.scope"] == "tenant"
    assert hub.scopes[1].tags["chatops.scope"] == "admin"
    assert hub.captured == []

    assert [metric for metric, _, _ in statsd.increments] == [
        config.instrumentation.datadog_metric_sent,
        config.instrumentation.datadog_metric_sent,
    ]
    first_tags = statsd.increments[0][2]
    assert "tenant:acme" in first_tags
    assert "channel:#alerts" in first_tags
    assert "env:test" in first_tags
    assert [metric for metric, _, _ in statsd.timings] == [
        config.instrumentation.datadog_metric_timing,
        config.instrumentation.datadog_metric_timing,
    ]


@pytest.mark.asyncio
async def test_chatops_instrumentation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    tracer = setup_stub_opentelemetry(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)

    async def failing_transport(
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        raise RuntimeError("transport boom")

    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(
            webhook_url="https://hooks.slack.com/services/default-token",
            default_channel="#ops",
        ),
    )
    service = ChatOpsService(config, transport=failing_transport)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    with pytest.raises(RuntimeError) as exc_info:
        await service.send(tenant, ChatMessage(text="boom"))

    assert len(tracer.spans) == 1
    span = tracer.spans[0]
    assert span.attributes["chatops.result"] == "error"
    assert getattr(span.status, "status_code", None) == "error"
    assert span.exceptions and span.exceptions[0] is exc_info.value
    assert hub.captured == [exc_info.value]
    assert statsd.timings == []
    assert statsd.increments[-1][0] == config.instrumentation.datadog_metric_error
    error_tags = statsd.increments[-1][2]
    assert "tenant:acme" in error_tags
    assert "scope:tenant" in error_tags


@pytest.mark.asyncio
async def test_chatops_instrumentation_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https:///token"),
        instrumentation=ChatOpsInstrumentationConfig(
            opentelemetry_enabled=False,
            sentry_enabled=False,
            datadog_enabled=False,
        ),
    )

    async def failing_transport(
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        raise ChatOpsError("disabled")

    service = ChatOpsService(config, transport=failing_transport)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    assert not service._instrumentation.enabled  # type: ignore[attr-defined]

    with pytest.raises(ChatOpsError):
        await service.send(tenant, ChatMessage(text="fail"))

    idle_service = ChatOpsService(config, transport=RecordingTransport())
    await idle_service.send(tenant, ChatMessage(text="ok"))


@pytest.mark.asyncio
async def test_chatops_instrumentation_datadog_only(monkeypatch: pytest.MonkeyPatch) -> None:
    statsd = setup_stub_datadog(monkeypatch)
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https:///token"),
        instrumentation=ChatOpsInstrumentationConfig(
            opentelemetry_enabled=False,
            sentry_enabled=False,
            datadog_enabled=True,
        ),
    )
    service = ChatOpsService(config, transport=RecordingTransport())
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="no span"))

    assert service._instrumentation.enabled  # type: ignore[attr-defined]
    assert [metric for metric, _, _ in statsd.increments] == [config.instrumentation.datadog_metric_sent]
    tags = statsd.increments[0][2]
    assert "tenant:acme" in tags
    assert "channel" not in {tag.split(":", 1)[0] for tag in tags}
    assert "webhook_host" not in {tag.split(":", 1)[0] for tag in tags}
    assert statsd.timings and statsd.timings[0][0] == config.instrumentation.datadog_metric_timing


@pytest.mark.asyncio
async def test_chatops_instrumentation_sentry_options(monkeypatch: pytest.MonkeyPatch) -> None:
    hub = setup_stub_sentry(monkeypatch)

    class MinimalScope:
        def __enter__(self) -> "MinimalScope":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def minimal_scope() -> MinimalScope:
        scope = MinimalScope()
        hub.scopes.append(scope)
        return scope

    hub.push_scope = minimal_scope  # type: ignore[assignment]

    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https:///token"),
        instrumentation=ChatOpsInstrumentationConfig(
            opentelemetry_enabled=False,
            datadog_enabled=False,
            sentry_enabled=True,
            sentry_record_breadcrumbs=False,
            sentry_capture_exceptions=False,
        ),
    )
    transport = RecordingTransport()
    service = ChatOpsService(config, transport=transport)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="silent"))

    assert hub.breadcrumbs == []
    assert isinstance(hub.scopes[0], MinimalScope)

    async def failing_transport(
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        raise RuntimeError("fail")

    service_error = ChatOpsService(config, transport=failing_transport)
    with pytest.raises(RuntimeError):
        await service_error.send(tenant, ChatMessage(text="boom"))

    assert hub.captured == []


@pytest.mark.asyncio
async def test_chatops_instrumentation_sentry_breadcrumbs_without_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracer = setup_stub_opentelemetry(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https:///token"),
        instrumentation=ChatOpsInstrumentationConfig(datadog_enabled=False),
    )
    service = ChatOpsService(config, transport=RecordingTransport())
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="breadcrumb"))

    crumb = hub.breadcrumbs[-1]
    assert "channel" not in crumb["data"]
    assert "webhook_host" not in crumb["data"]
    span = tracer.spans[-1]
    assert "chatops.channel" not in span.attributes
    assert "chatops.webhook.host" not in span.attributes


@pytest.mark.asyncio
async def test_chatops_instrumentation_tracer_without_status(monkeypatch: pytest.MonkeyPatch) -> None:
    tracer = setup_stub_opentelemetry_without_status(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/token"),
        instrumentation=ChatOpsInstrumentationConfig(datadog_enabled=False),
    )
    service = ChatOpsService(config, transport=RecordingTransport())
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="statusless"))

    assert tracer.spans[-1].status is None

    async def failing_transport(
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        raise RuntimeError("fail")

    service_error = ChatOpsService(config, transport=failing_transport)
    with pytest.raises(RuntimeError):
        await service_error.send(tenant, ChatMessage(text="boom"))

    assert tracer.spans[-1].status is None
    assert hub.captured  # error still reported to sentry hub


@pytest.mark.asyncio
async def test_chatops_instrumentation_span_without_record_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracer = setup_stub_opentelemetry_without_record(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/token"),
        instrumentation=ChatOpsInstrumentationConfig(datadog_enabled=False),
    )
    service = ChatOpsService(config, transport=RecordingTransport())
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="no-record"))

    async def failing_transport(
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        raise RuntimeError("fail")

    service_error = ChatOpsService(config, transport=failing_transport)
    with pytest.raises(RuntimeError):
        await service_error.send(tenant, ChatMessage(text="boom"))

    span = tracer.spans[-1]
    assert not hasattr(span, "record_exception")
    assert span.ended
    assert hub.captured[-1].args[0] == "fail"


def test_chatops_instrumentation_error_without_context(monkeypatch: pytest.MonkeyPatch) -> None:
    hub = setup_stub_sentry(monkeypatch)
    instrumentor = ChatOpsInstrumentor(
        ChatOpsInstrumentationConfig(
            opentelemetry_enabled=False,
            datadog_enabled=False,
            sentry_enabled=True,
        ),
    )

    exc = RuntimeError("manual")
    instrumentor.on_send_error(None, exc)

    assert hub.captured[-1] is exc


@pytest.mark.asyncio
async def test_chatops_maybe_await() -> None:
    await _maybe_await(asyncio.sleep(0))


def test_chatops_webhook_host_helper() -> None:
    assert _webhook_host("https://hooks.slack.com/services/abc") == "hooks.slack.com"
    assert _webhook_host("https:///token") is None
    assert _webhook_host("not-a-url") is None


@pytest.mark.asyncio
async def test_chatops_minimal_payload() -> None:
    recorded: list[dict[str, Any]] = []

    def transport(config: SlackWebhookConfig, payload: bytes, headers: dict[str, str]) -> None:
        recorded.append(json_decode(payload))

    config = ChatOpsConfig(
        enabled=True, default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default")
    )
    service = ChatOpsService(config, transport=transport)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="minimal"))

    assert recorded == [{"text": "minimal"}]


@pytest.mark.asyncio
async def test_default_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, float, dict[str, str]]] = []

    class DummyResponse:
        def __init__(self, status: int) -> None:
            self.status = status

        def getcode(self) -> int:
            return self.status

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_urlopen(request, timeout: float) -> DummyResponse:
        captured.append((request.full_url, timeout, dict(request.headers)))
        return DummyResponse(status=202)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        default_channel="#general",
        timeout=3.0,
    )

    await _default_transport(config, b"{}", {"content-type": "application/json"})

    assert len(captured) == 1
    url, timeout, headers = captured[0]
    assert url == "https://hooks.slack.com/services/default"
    assert timeout == 3.0
    assert {k.lower(): v for k, v in headers.items()} == {"content-type": "application/json"}


@pytest.mark.asyncio
async def test_default_transport_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyResponse:
        def __init__(self, status: int) -> None:
            self.status = status

        def getcode(self) -> int:
            return self.status

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_urlopen(request, timeout: float) -> DummyResponse:
        return DummyResponse(status=503)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    config = SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default", timeout=1.0)

    with pytest.raises(ChatOpsError):
        await _default_transport(config, b"{}", {})
