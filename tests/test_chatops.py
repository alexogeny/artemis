from __future__ import annotations

import asyncio
import hashlib
import types
from typing import Any

import pytest

from artemis import (
    AppConfig,
    ArtemisApp,
    ChatMessage,
    ChatOpsConfig,
    ChatOpsError,
    ChatOpsRoute,
    ChatOpsService,
    Observability,
    ObservabilityConfig,
    SlackWebhookConfig,
    TenantContext,
    TenantScope,
    TestClient,
)
from artemis.chatops import (
    ChatOpsCommandResolutionError,
    ChatOpsInvocationError,
    ChatOpsSlashCommand,
    SlackWebhookClient,
    parse_slash_command_args,
    _default_transport,
    _ensure_tls_destination,
    _maybe_await,
    _validate_certificate_pin,
    _webhook_host,
)
from artemis.serialization import json_decode
from tests.observability_stubs import (
    setup_stub_datadog,
    setup_stub_opentelemetry,
    setup_stub_opentelemetry_without_record,
    setup_stub_opentelemetry_without_status,
    setup_stub_sentry,
)


def test_chatops_parse_slash_command_args() -> None:
    args = parse_slash_command_args('slug=alpha =ignored name="Alpha Beta" note=Trial flag extra="value" note2=" spaced "')
    assert args == {
        "slug": "alpha",
        "name": "Alpha Beta",
        "note": "Trial",
        "extra": "value",
        "note2": " spaced ",
    }

    fallback_args = parse_slash_command_args('slug=omega name="Alpha Beta note=Trial')
    assert fallback_args == {
        "slug": "omega",
        "name": "Alpha",
        "note": "Trial",
    }


def test_chatops_extract_command_from_invocation() -> None:
    class Invocation:
        def __init__(self, text: str, command: str | None = None) -> None:
            self.text = text
            self.command = command

    service = ChatOpsService(ChatOpsConfig(enabled=True))
    slash_payload = Invocation("/create-tenant slug=alpha name=Alpha", command="/create-tenant")
    token, remaining = service.extract_command_from_invocation(slash_payload, bot_user_id="U999")
    assert token == "create-tenant"
    assert remaining == slash_payload.text

    mention_payload = Invocation("<@U999> extend-trial slug=alpha days=30")
    token, remaining = service.extract_command_from_invocation(mention_payload, bot_user_id="U999")
    assert token == "extend-trial"
    assert remaining == "slug=alpha days=30"

    with pytest.raises(ChatOpsInvocationError):
        service.extract_command_from_invocation(Invocation(""), bot_user_id="U999")

    with pytest.raises(ChatOpsInvocationError):
        service.extract_command_from_invocation(Invocation("<@U888> extend"), bot_user_id="U999")


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
    )
    observability = Observability(
        ObservabilityConfig(datadog_tags=(("env", "test"),), sentry_record_breadcrumbs=True)
    )
    service = ChatOpsService(config, transport=transport, observability=observability)

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
    assert [crumb["message"] for crumb in hub.breadcrumbs] == [
        "ChatOps message (12 chars)",
        "ChatOps message (11 chars)",
    ]
    assert hub.scopes[0].tags["chatops.scope"] == "tenant"
    assert hub.scopes[1].tags["chatops.scope"] == "admin"
    assert hub.captured == []

    assert [metric for metric, _, _ in statsd.increments] == [
        observability.config.chatops.datadog_metric_sent,
        observability.config.chatops.datadog_metric_sent,
    ]
    first_tags = statsd.increments[0][2]
    assert "tenant:acme" in first_tags
    assert "channel:#alerts" in first_tags
    assert "env:test" in first_tags
    assert [metric for metric, _, _ in statsd.timings] == [
        observability.config.chatops.datadog_metric_timing,
        observability.config.chatops.datadog_metric_timing,
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
    observability = Observability()
    service = ChatOpsService(config, transport=failing_transport, observability=observability)
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
    assert statsd.increments[-1][0] == observability.config.chatops.datadog_metric_error
    error_tags = statsd.increments[-1][2]
    assert "tenant:acme" in error_tags
    assert "scope:tenant" in error_tags


@pytest.mark.asyncio
async def test_chatops_instrumentation_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/token"),
    )

    async def failing_transport(
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        raise ChatOpsError("disabled")

    observability = Observability(
        ObservabilityConfig(
            enabled=False,
            opentelemetry_enabled=False,
            sentry_enabled=False,
            datadog_enabled=False,
        )
    )
    service = ChatOpsService(config, transport=failing_transport, observability=observability)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    assert not service._observability.enabled

    with pytest.raises(ChatOpsError):
        await service.send(tenant, ChatMessage(text="fail"))

    idle_service = ChatOpsService(config, transport=RecordingTransport(), observability=observability)
    await idle_service.send(tenant, ChatMessage(text="ok"))


@pytest.mark.asyncio
async def test_chatops_instrumentation_datadog_only(monkeypatch: pytest.MonkeyPatch) -> None:
    statsd = setup_stub_datadog(monkeypatch)
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/token"),
    )
    observability = Observability(
        ObservabilityConfig(
            opentelemetry_enabled=False,
            sentry_enabled=False,
            datadog_enabled=True,
        )
    )
    service = ChatOpsService(config, transport=RecordingTransport(), observability=observability)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="no span"))

    assert service._observability.enabled
    assert [metric for metric, _, _ in statsd.increments] == [observability.config.chatops.datadog_metric_sent]
    tags = statsd.increments[0][2]
    assert "tenant:acme" in tags
    assert "channel" not in {tag.split(":", 1)[0] for tag in tags}
    assert "webhook_host:hooks.slack.com" in tags
    assert statsd.timings and statsd.timings[0][0] == observability.config.chatops.datadog_metric_timing


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
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/token"),
    )
    observability = Observability(
        ObservabilityConfig(
            datadog_enabled=False,
            sentry_record_breadcrumbs=False,
            sentry_capture_exceptions=False,
        )
    )
    transport = RecordingTransport()
    service = ChatOpsService(config, transport=transport, observability=observability)
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

    service_error = ChatOpsService(config, transport=failing_transport, observability=observability)
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
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/token"),
    )
    observability = Observability(
        ObservabilityConfig(datadog_enabled=False, sentry_record_breadcrumbs=True)
    )
    service = ChatOpsService(config, transport=RecordingTransport(), observability=observability)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    message = ChatMessage(text="breadcrumb")
    await service.send(tenant, message)

    crumb = hub.breadcrumbs[-1]
    assert crumb["message"] == f"ChatOps message ({len(message.text)} chars)"
    assert "channel" not in crumb["data"]
    assert "webhook_host" not in crumb["data"]
    span = tracer.spans[-1]
    assert "chatops.channel" not in span.attributes
    assert span.attributes["chatops.webhook.host"] == "hooks.slack.com"


@pytest.mark.asyncio
async def test_chatops_instrumentation_tracer_without_status(monkeypatch: pytest.MonkeyPatch) -> None:
    tracer = setup_stub_opentelemetry_without_status(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/token"),
    )
    observability = Observability(ObservabilityConfig(datadog_enabled=False))
    service = ChatOpsService(config, transport=RecordingTransport(), observability=observability)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="statusless"))

    assert tracer.spans[-1].status is None

    async def failing_transport(
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        raise RuntimeError("fail")

    service_error = ChatOpsService(config, transport=failing_transport, observability=observability)
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
    )
    observability = Observability(ObservabilityConfig(datadog_enabled=False))
    service = ChatOpsService(config, transport=RecordingTransport(), observability=observability)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="no-record"))

    async def failing_transport(
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        raise RuntimeError("fail")

    service_error = ChatOpsService(config, transport=failing_transport, observability=observability)
    with pytest.raises(RuntimeError):
        await service_error.send(tenant, ChatMessage(text="boom"))

    span = tracer.spans[-1]
    assert not hasattr(span, "record_exception")
    assert span.ended
    assert hub.captured[-1].args[0] == "fail"


@pytest.mark.asyncio
async def test_chatops_maybe_await() -> None:
    await _maybe_await(asyncio.sleep(0))


def test_chatops_webhook_host_helper() -> None:
    assert _webhook_host("https://hooks.slack.com/services/abc") == "hooks.slack.com"
    assert _webhook_host("https:///token") is None
    assert _webhook_host("not-a-url") is None


def test_slack_webhook_client_requires_https() -> None:
    config = SlackWebhookConfig(webhook_url="http://hooks.slack.com/services/test")
    with pytest.raises(ChatOpsError):
        SlackWebhookClient(config)


def test_slack_webhook_client_requires_host() -> None:
    config = SlackWebhookConfig(webhook_url="https:///missing")
    with pytest.raises(ChatOpsError):
        SlackWebhookClient(config)


def test_slack_webhook_client_validates_allowed_hosts() -> None:
    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/test",
        allowed_hosts=("example.com",),
    )
    with pytest.raises(ChatOpsError):
        SlackWebhookClient(config)


def test_slack_webhook_client_accepts_allowed_host() -> None:
    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/test",
        allowed_hosts=("hooks.slack.com",),
    )
    client = SlackWebhookClient(config)
    assert client.config.allowed_hosts == ("hooks.slack.com",)


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
        def __init__(self, status: int, url: str) -> None:
            self.status = status
            self._url = url

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self._url

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_build_opener(*handlers: Any) -> Any:
        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> DummyResponse:
                captured.append((request.full_url, timeout, dict(request.headers)))
                return DummyResponse(status=202, url=request.full_url)

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

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


def test_ensure_tls_destination_rejects_insecure_redirect() -> None:
    class DummyResponse:
        def geturl(self) -> str:
            return "http://malicious.example.com/hook"

    config = SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default")

    with pytest.raises(ChatOpsError):
        _ensure_tls_destination(DummyResponse(), config)


def test_ensure_tls_destination_requires_host() -> None:
    class DummyResponse:
        def geturl(self) -> str:
            return "https:///missing"

    config = SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default")

    with pytest.raises(ChatOpsError):
        _ensure_tls_destination(DummyResponse(), config)


def test_ensure_tls_destination_rejects_disallowed_host() -> None:
    class DummyResponse:
        def geturl(self) -> str:
            return "https://malicious.example.com/hook"

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        allowed_hosts=("hooks.slack.com",),
    )

    with pytest.raises(ChatOpsError):
        _ensure_tls_destination(DummyResponse(), config)


@pytest.mark.asyncio
async def test_default_transport_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyResponse:
        def __init__(self, status: int, url: str) -> None:
            self.status = status
            self._url = url

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self._url

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_build_opener(*handlers: Any) -> Any:
        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> DummyResponse:
                return DummyResponse(status=503, url=request.full_url)

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    config = SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default", timeout=1.0)

    with pytest.raises(ChatOpsError):
        await _default_transport(config, b"{}", {})


@pytest.mark.asyncio
async def test_default_transport_rejects_redirect_host(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummySSL:
        def getpeercert(self, binary_form: bool = True) -> bytes:
            return b""

    class DummyResponse:
        def __init__(self, url: str) -> None:
            self.status = 200
            self._url = url
            self.fp = types.SimpleNamespace(
                raw=types.SimpleNamespace(_sslobj=DummySSL()),
            )

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self._url

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_build_opener(*handlers: Any) -> Any:
        redirect_handler = handlers[0]

        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> DummyResponse:
                redirect_handler.redirect_request(
                    request,
                    None,
                    307,
                    "Temporary Redirect",
                    {},
                    "https://malicious.example.com/hook",
                )
                return DummyResponse(url="https://malicious.example.com/hook")

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        allowed_hosts=("hooks.slack.com",),
    )

    with pytest.raises(ChatOpsError):
        await _default_transport(config, b"{}", {})


@pytest.mark.asyncio
async def test_default_transport_handles_missing_base_host(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummySSL:
        def getpeercert(self, binary_form: bool = True) -> bytes:
            return b""

    class DummyResponse:
        def __init__(self) -> None:
            self.status = 200
            self._url = "https://hooks.slack.com/services/default"
            self.fp = types.SimpleNamespace(
                raw=types.SimpleNamespace(_sslobj=DummySSL()),
            )

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self._url

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_build_opener(*handlers: Any) -> Any:
        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> DummyResponse:
                return DummyResponse()

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)
    monkeypatch.setattr("artemis.chatops._webhook_host", lambda url: None)

    config = SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default")

    await _default_transport(config, b"{}", {})


@pytest.mark.asyncio
async def test_default_transport_rejects_redirect_even_if_host_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_build_opener(*handlers: Any) -> Any:
        redirect_handler = handlers[0]

        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> Any:
                redirect_handler.redirect_request(
                    request,
                    None,
                    307,
                    "Temporary Redirect",
                    {},
                    "https://hooks.slack.com/services/redirect",
                )
                pytest.fail("redirect_request should have raised")

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        allowed_hosts=("hooks.slack.com",),
    )

    with pytest.raises(ChatOpsError):
        await _default_transport(config, b"{}", {})


@pytest.mark.asyncio
async def test_default_transport_rejects_insecure_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_build_opener(*handlers: Any) -> Any:
        redirect_handler = handlers[0]

        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> Any:
                redirect_handler.redirect_request(
                    request,
                    None,
                    307,
                    "Temporary Redirect",
                    {},
                    "http://malicious.example.com/hook",
                )
                pytest.fail("redirect_request should have raised")

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        allowed_hosts=("hooks.slack.com",),
    )

    with pytest.raises(ChatOpsError):
        await _default_transport(config, b"{}", {})


@pytest.mark.asyncio
async def test_default_transport_rejects_redirect_without_host(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_build_opener(*handlers: Any) -> Any:
        redirect_handler = handlers[0]

        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> Any:
                redirect_handler.redirect_request(
                    request,
                    None,
                    307,
                    "Temporary Redirect",
                    {},
                    "https:///missing",
                )
                pytest.fail("redirect_request should have raised")

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        allowed_hosts=("hooks.slack.com",),
    )

    with pytest.raises(ChatOpsError):
        await _default_transport(config, b"{}", {})


@pytest.mark.asyncio
async def test_default_transport_validates_certificate_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    cert_bytes = b"certificate"
    fingerprint = hashlib.sha256(cert_bytes).hexdigest()

    class DummySSL:
        def getpeercert(self, binary_form: bool = True) -> bytes:
            return cert_bytes

    class DummyResponse:
        def __init__(self) -> None:
            self.status = 200
            self._url = "https://hooks.slack.com/services/default"
            self.fp = types.SimpleNamespace(raw=types.SimpleNamespace(_sslobj=DummySSL()))

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self._url

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_build_opener(*handlers: Any) -> Any:
        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> DummyResponse:
                return DummyResponse()

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        certificate_pins=(fingerprint,),
    )

    await _default_transport(config, b"{}", {"content-type": "application/json"})


@pytest.mark.asyncio
async def test_default_transport_rejects_bad_certificate_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummySSL:
        def getpeercert(self, binary_form: bool = True) -> bytes:
            return b"certificate"

    class DummyResponse:
        def __init__(self) -> None:
            self.status = 200
            self._url = "https://hooks.slack.com/services/default"
            self.fp = types.SimpleNamespace(raw=types.SimpleNamespace(_sslobj=DummySSL()))

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self._url

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_build_opener(*handlers: Any) -> Any:
        class DummyOpener:
            def open(self, request: Any, timeout: float, **_: Any) -> DummyResponse:
                return DummyResponse()

        return DummyOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        certificate_pins=("deadbeef",),
    )

    with pytest.raises(ChatOpsError):
        await _default_transport(config, b"{}", {"content-type": "application/json"})


def test_validate_certificate_pin_requires_ssl_object() -> None:
    class DummyResponse:
        def __init__(self) -> None:
            self.fp = types.SimpleNamespace(raw=None)

    with pytest.raises(ChatOpsError):
        _validate_certificate_pin(DummyResponse(), ("deadbeef",))


def test_ensure_tls_destination_allows_base_host_without_explicit_allowlist() -> None:
    class DummyResponse:
        def geturl(self) -> str:
            return "https://hooks.slack.com/services/default"

    config = SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default")

    _ensure_tls_destination(DummyResponse(), config)


def test_ensure_tls_destination_allows_missing_base_host(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyResponse:
        def geturl(self) -> str:
            return "https://hooks.slack.com/services/default"

    monkeypatch.setattr("artemis.chatops._webhook_host", lambda url: None)

    config = SlackWebhookConfig(webhook_url="https:///missing")

    _ensure_tls_destination(DummyResponse(), config)


def test_chatops_slash_command_resolution_rules() -> None:
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default"),
    )
    service = ChatOpsService(config)
    admin = TenantContext(tenant="admin", site="demo", domain="example.com", scope=TenantScope.ADMIN)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    commands = [
        ChatOpsSlashCommand(
            name="create-tenant",
            description="Create a tenant",
            visibility="admin",
            aliases=("quickstart-create-tenant",),
        ),
        ChatOpsSlashCommand(
            name="extend-trial",
            description="Extend a trial",
            visibility="public",
        ),
    ]

    assert service.normalize_command_token(" /Create-Tenant ") == "create-tenant"
    resolved_admin = service.resolve_slash_command(
        "/quickstart-create-tenant",
        commands,
        tenant=admin,
        workspace_id="T123",
        admin_workspace="T123",
    )
    assert resolved_admin is commands[0]

    with pytest.raises(ChatOpsCommandResolutionError) as admin_scope_error:
        service.resolve_slash_command(
            "create-tenant",
            commands,
            tenant=tenant,
            workspace_id="T123",
            admin_workspace="T123",
        )
    assert admin_scope_error.value.code == "admin_command"

    with pytest.raises(ChatOpsCommandResolutionError) as workspace_error:
        service.resolve_slash_command(
            "create-tenant",
            commands,
            tenant=admin,
            workspace_id="T999",
            admin_workspace="T123",
        )
    assert workspace_error.value.code == "workspace_forbidden"

    resolved_public = service.resolve_slash_command(
        "extend-trial",
        commands,
        tenant=tenant,
        workspace_id="T123",
        admin_workspace="T123",
    )
    assert resolved_public is commands[1]

    with pytest.raises(ChatOpsCommandResolutionError) as unknown_error:
        service.resolve_slash_command(
            "unknown",
            commands,
            tenant=admin,
            workspace_id="T123",
            admin_workspace="T123",
        )
    assert unknown_error.value.code == "unknown_command"

    disabled_service = ChatOpsService(ChatOpsConfig(enabled=True))
    with pytest.raises(ChatOpsCommandResolutionError) as unconfigured_error:
        disabled_service.resolve_slash_command(
            "extend-trial",
            commands,
            tenant=tenant,
            workspace_id="T123",
            admin_workspace="T123",
        )
    assert unconfigured_error.value.code == "chatops_unconfigured"
