from __future__ import annotations

import types
from typing import cast

import pytest

from artemis import (
    AppConfig,
    ArtemisApp,
    ChatMessage,
    Observability,
    ObservabilityConfig,
    Request,
    Response,
    SlackWebhookConfig,
    TenantContext,
    TenantScope,
    TestClient,
)
from tests.observability_stubs import (
    setup_stub_datadog,
    setup_stub_opentelemetry,
    setup_stub_opentelemetry_without_record,
    setup_stub_opentelemetry_without_status,
    setup_stub_sentry,
)


def test_observability_chatops_error_without_context(monkeypatch: pytest.MonkeyPatch) -> None:
    hub = setup_stub_sentry(monkeypatch)
    observability = Observability(
        ObservabilityConfig(
            opentelemetry_enabled=False,
            datadog_enabled=False,
            sentry_enabled=True,
        )
    )

    exc = RuntimeError("manual")
    observability.on_chatops_send_error(None, exc)

    assert hub.captured[-1] is exc


@pytest.mark.asyncio
async def test_request_observability_success(monkeypatch: pytest.MonkeyPatch) -> None:
    tracer = setup_stub_opentelemetry(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)

    observability = Observability(ObservabilityConfig(datadog_tags=(("env", "test"),)))
    config = AppConfig(
        site="demo",
        domain="example.com",
        allowed_tenants=("acme",),
        observability=observability.config,
    )
    app = ArtemisApp(config=config, observability=observability)

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    async with TestClient(app) as client:
        response = await client.get("/ping", tenant="acme")

    assert response.status == 200
    span = tracer.spans[-1]
    assert span.attributes["http.method"] == "GET"
    assert span.attributes["http.result"] == "success"
    assert span.attributes["http.status_code"] == 200
    assert hub.captured == []
    assert statsd.timings
    metric, _, tags = statsd.timings[-1]
    assert metric == observability.config.request.datadog_metric_timing
    assert "status:200" in tags
    assert "tenant:acme" in tags
    assert "env:test" in tags


@pytest.mark.asyncio
async def test_request_observability_error(monkeypatch: pytest.MonkeyPatch) -> None:
    tracer = setup_stub_opentelemetry(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)

    observability = Observability()
    config = AppConfig(
        site="demo",
        domain="example.com",
        allowed_tenants=("acme",),
        observability=observability.config,
    )
    app = ArtemisApp(config=config, observability=observability)

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("server boom")

    async with TestClient(app) as client:
        with pytest.raises(RuntimeError):
            await client.get("/boom", tenant="acme")

    span = tracer.spans[-1]
    assert span.attributes["http.result"] == "error"
    assert getattr(span.status, "status_code", None) == "error"
    assert hub.captured and isinstance(hub.captured[-1], RuntimeError)
    assert statsd.increments
    metric, _, tags = statsd.increments[-1]
    assert metric == observability.config.request.datadog_metric_error
    assert "status:500" in tags
    assert statsd.timings
    assert statsd.timings[-1][0] == observability.config.request.datadog_metric_timing


@pytest.mark.asyncio
async def test_observability_chatops_success_without_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_stub_opentelemetry(monkeypatch)
    setup_stub_sentry(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability()

    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    message = ChatMessage(text="noop")
    config = SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/token")

    context = observability.on_chatops_send_start(tenant, message, config)
    assert context is not None
    context.metric_success = None
    context.metric_timing = None

    observability.on_chatops_send_success(context)

    assert all(metric[0] != observability.config.chatops.datadog_metric_sent for metric in statsd.increments)


def test_observability_request_success_without_status(monkeypatch: pytest.MonkeyPatch) -> None:
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/ping",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    observability.on_request_success(context, cast(Response, types.SimpleNamespace()))

    assert statsd.timings


def test_observability_request_error_context_none(monkeypatch: pytest.MonkeyPatch) -> None:
    hub = setup_stub_sentry(monkeypatch)
    observability = Observability(ObservabilityConfig(datadog_enabled=False))
    error = RuntimeError("missing context")

    observability.on_request_error(None, error, status_code=400)

    assert hub.captured[-1] is error


def test_observability_request_error_without_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="POST",
        path="/boom",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None
    context.metric_error = None
    context.metric_timing = None

    before_counts = len(statsd.increments)
    observability.on_request_error(context, RuntimeError("boom"))

    assert len(statsd.increments) == before_counts


def test_observability_request_success_context_none() -> None:
    observability = Observability(ObservabilityConfig(datadog_enabled=False))
    observability.on_request_success(None, Response())


def test_observability_request_success_without_timing(monkeypatch: pytest.MonkeyPatch) -> None:
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/timeless",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None
    context.metric_timing = None

    before_timings = len(statsd.timings)
    observability.on_request_success(context, Response(status=204))

    assert len(statsd.timings) == before_timings


def test_observability_request_error_without_status(monkeypatch: pytest.MonkeyPatch) -> None:
    statsd = setup_stub_datadog(monkeypatch)
    setup_stub_opentelemetry(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="POST",
        path="/error",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    observability.on_request_error(context, RuntimeError("unstated"))

    metric, _, tags = statsd.increments[-1]
    assert metric == observability.config.request.datadog_metric_error
    assert all(not tag.startswith("status:") for tag in tags)


def test_observability_request_error_status_without_span(monkeypatch: pytest.MonkeyPatch) -> None:
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability(ObservabilityConfig(opentelemetry_enabled=False))
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/418",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    observability.on_request_error(context, RuntimeError("teapot"), status_code=418)

    assert any("status:418" in tags for _, _, tags in statsd.increments)


def test_observability_request_error_span_without_record_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_stub_opentelemetry_without_record(monkeypatch)
    hub = setup_stub_sentry(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/norecord",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    observability.on_request_error(context, RuntimeError("no-record"), status_code=502)

    assert statsd.increments[-1][0] == observability.config.request.datadog_metric_error
    assert hub.captured[-1].args[0] == "no-record"


def test_observability_request_success_without_status_with_span(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_stub_opentelemetry(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/span",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    observability.on_request_success(context, cast(Response, types.SimpleNamespace()))

    assert statsd.timings


def test_observability_request_success_without_status_support(monkeypatch: pytest.MonkeyPatch) -> None:
    setup_stub_opentelemetry_without_status(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/nostatus",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    observability.on_request_success(context, Response(status=200))

    assert statsd.timings


def test_observability_request_error_without_statsd(monkeypatch: pytest.MonkeyPatch) -> None:
    setup_stub_sentry(monkeypatch)
    observability = Observability(ObservabilityConfig(datadog_enabled=False))
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/nostats",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    observability.on_request_error(context, RuntimeError("nostats"))


def test_observability_request_error_status_without_status_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_stub_opentelemetry_without_status(monkeypatch)
    statsd = setup_stub_datadog(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/statusless",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    observability.on_request_error(context, RuntimeError("statusless"), status_code=503)

    metric, _, tags = statsd.increments[-1]
    assert metric == observability.config.request.datadog_metric_error
    assert "status:503" in tags
