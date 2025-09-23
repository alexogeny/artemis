from __future__ import annotations

import json
import logging
import secrets
import types
from typing import Any, Iterable, cast

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
    span = next(span for span in tracer.spans if span.name == observability.config.request.span_name)
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

    span = next(span for span in tracer.spans if span.name == observability.config.request.span_name)
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

    observability.on_request_success(context, Response())

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


def test_observability_uses_custom_id_generator() -> None:
    observability = Observability(
        ObservabilityConfig(
            opentelemetry_enabled=False,
            sentry_enabled=False,
            datadog_enabled=False,
        )
    )
    assert observability._id_generator is not secrets.token_hex
    token = observability._id_generator(8)
    assert isinstance(token, str)
    assert len(token) == 16


def test_observability_context_without_stack_when_inactive() -> None:
    config = ObservabilityConfig(opentelemetry_enabled=False, sentry_enabled=False, datadog_enabled=False)
    observability = Observability(config)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/health",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None
    assert context.stack is None


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

    observability.on_request_success(context, Response())

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


def test_observability_request_success_without_status_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracer = setup_stub_opentelemetry(monkeypatch)
    observability = Observability(ObservabilityConfig(datadog_enabled=False))
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/custom",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    context = observability.on_request_start(request)
    assert context is not None

    class HeaderOnlyResponse:
        def __init__(self) -> None:
            self.headers: tuple[tuple[str, str], ...] = ()

        def with_headers(self, headers: Iterable[tuple[str, str]]) -> HeaderOnlyResponse:
            self.headers = self.headers + tuple(headers)
            return self

    response = HeaderOnlyResponse()
    result = observability.on_request_success(context, cast(Response, response))
    assert result is response
    span = tracer.spans[-1]
    assert "http.status_code" not in span.attributes


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


class _DeterministicIds:
    def __init__(self) -> None:
        self._counter = 0

    def __call__(self, size: int) -> str:
        self._counter += 1
        return f"{self._counter:0{size * 2}x}"


@pytest.mark.asyncio
async def test_observability_emits_trace_headers_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    id_gen = _DeterministicIds()
    observability = Observability(
        ObservabilityConfig(
            opentelemetry_enabled=False,
            datadog_enabled=False,
            sentry_enabled=False,
        ),
        id_generator=id_gen,
    )
    config = AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",))
    app = ArtemisApp(config=config, observability=observability)

    async def passthrough(request: Request, handler):
        return await handler(request)

    app.add_middleware(passthrough)

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    incoming = "00-" + ("a" * 32) + "-" + ("b" * 16) + "-01"

    async with TestClient(app) as client:
        with caplog.at_level(logging.INFO, logger="artemis.observability"):
            response = await client.get("/ping", tenant="acme", headers={"traceparent": incoming})

    headers = {key: value for key, value in response.headers}
    assert headers["traceparent"] == "00-" + ("a" * 32) + "-0000000000000001-01"
    logs = [json.loads(record.message) for record in caplog.records]
    start_log = next(entry for entry in logs if entry["event"] == "request.start")
    success_log = next(entry for entry in logs if entry["event"] == "request.success")
    middleware_log = next(entry for entry in logs if entry["event"] == "middleware.start")
    assert start_log["trace_id"] == "a" * 32
    assert success_log["span_id"] == start_log["span_id"]
    assert middleware_log["request_id"] == start_log["request_id"]
    assert middleware_log["parent_span_id"] == start_log["span_id"]


def test_observability_request_start_includes_tracestate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    captured: dict[str, Any] = {}

    def fake_start(self: Observability, span_name: str, **kwargs: Any) -> None:
        captured["trace_context"] = kwargs.get("trace_context")
        captured["tracestate"] = kwargs.get("tracestate")
        return None

    monkeypatch.setattr(observability, "_start", fake_start.__get__(observability, Observability))
    incoming = "00-" + ("a" * 32) + "-" + ("b" * 16) + "-01"
    request = Request(
        method="GET",
        path="/trace",
        headers={"traceparent": incoming, "tracestate": "contrib=1"},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )

    assert observability.on_request_start(request) is None
    assert captured["trace_context"] == {"traceparent": incoming, "tracestate": "contrib=1"}
    assert captured["tracestate"] == "contrib=1"


def test_observability_request_start_handles_missing_traceparent_header() -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    incoming = "00-" + ("a" * 32) + "-" + ("b" * 16) + "-01"
    calls = {"count": 0}

    class StubRequest:
        def __init__(self) -> None:
            self.method = "GET"
            self.path = "/trace"
            self.tenant = tenant
            self.path_params = {}

        def header(self, name: str, default: str | None = None) -> str | None:
            if name == "traceparent":
                calls["count"] += 1
                if calls["count"] == 1:
                    return incoming
                if calls["count"] == 2:
                    return ""
                return incoming
            return default

    context = observability.on_request_start(cast(Request, StubRequest()))
    assert context is not None
    assert calls["count"] >= 2
    assert context.parent_span_id == "b" * 16
    assert context.traceparent is not None
    assert context.traceparent.startswith("00-" + ("a" * 32) + "-")


@pytest.mark.asyncio
async def test_observability_records_middleware_spans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracer = setup_stub_opentelemetry(monkeypatch)
    observability = Observability(ObservabilityConfig(datadog_enabled=False))
    config = AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",))
    app = ArtemisApp(config=config, observability=observability)

    async def middleware(request: Request, handler):
        return await handler(request)

    app.add_middleware(middleware)

    @app.get("/trace")
    async def traced() -> dict[str, str]:
        return {"status": "ok"}

    async with TestClient(app) as client:
        await client.get("/trace", tenant="acme")

    assert any(span.name.endswith(".middleware") for span in tracer.spans)
    assert any(span.name == observability.config.request.span_name for span in tracer.spans)


def test_observability_ensure_hex_behaviour() -> None:
    generator_calls: list[int] = []

    def generator(size: int) -> str:
        generator_calls.append(size)
        return "f" * (size * 2)

    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False),
        id_generator=generator,
    )
    assert observability._ensure_hex("ABC", 2) == "0abc"
    assert observability._ensure_hex(3, 1) == "03"
    assert observability._ensure_hex(object(), 1, default="be") == "be"
    assert observability._ensure_hex(object(), 1, default=None) == "ff"
    assert observability._ensure_hex("123456", 2) == "3456"
    assert generator_calls[-1] == 1


def test_observability_parse_traceparent_validation() -> None:
    assert Observability._parse_traceparent(None) is None
    assert Observability._parse_traceparent("invalid") is None
    assert Observability._parse_traceparent("00-" + "a" * 31 + "-" + "b" * 16 + "-01") is None
    assert Observability._parse_traceparent("00-" + "0" * 32 + "-" + "c" * 16 + "-01") is None
    assert Observability._parse_traceparent("00-" + "a" * 32 + "-" + "0" * 16 + "-01") is None
    valid = Observability._parse_traceparent("00-" + "a" * 32 + "-" + "b" * 16 + "-01")
    assert valid is not None and valid.trace_id == "a" * 32 and valid.parent_span_id == "b" * 16


def test_observability_log_disabled(caplog: pytest.LogCaptureFixture) -> None:
    observability = Observability(
        ObservabilityConfig(enabled=False, opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    with caplog.at_level(logging.INFO, logger="artemis.observability"):
        observability._log(None, "event", {"detail": True})
    assert caplog.records == []


def test_observability_log_without_context(caplog: pytest.LogCaptureFixture) -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    with caplog.at_level(logging.INFO, logger="artemis.observability"):
        observability._log(None, "standalone.event")
    record = json.loads(caplog.records[-1].message)
    assert record == {"event": "standalone.event"}


def test_observability_log_ignores_missing_context_fields(caplog: pytest.LogCaptureFixture) -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    context = observability._start("test", kind=None, attributes={}, datadog_tags=())
    assert context is not None
    context.request_id = None
    context.trace_id = None
    context.span_id = None
    context.parent_span_id = None
    context.log_fields.clear()
    with caplog.at_level(logging.INFO, logger="artemis.observability"):
        observability._log(context, "minimal.event")
    record = json.loads(caplog.records[-1].message)
    assert record == {"event": "minimal.event"}


def test_observability_log_includes_context_fields(caplog: pytest.LogCaptureFixture) -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    context = observability._start(
        "custom.span",
        kind=None,
        attributes={},
        datadog_tags=(),
        trace_context=None,
        request_id="req-1",
        trace_id="trace-1",
        parent_span_id="parent-1",
        trace_flags="01",
        traceparent="00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
        tracestate="contrib=1",
        log_fields={"custom": "value"},
    )
    assert context is not None
    context.span_id = "span-1"
    with caplog.at_level(logging.INFO, logger="artemis.observability"):
        observability._log(context, "custom.event", {"extra": "yes", "skip": None})
    record = json.loads(caplog.records[-1].message)
    assert record["custom"] == "value"
    assert record["request_id"] == "req-1"
    assert record["trace_id"] == "trace-1"
    assert record["span_id"] == "span-1"
    assert record["parent_span_id"] == "parent-1"
    assert record["extra"] == "yes"


def test_observability_attach_trace_headers_skips_existing() -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    context = observability._start("test", kind=None, attributes={}, datadog_tags=())
    assert context is not None
    response = Response(status=200, headers=(("traceparent", "existing"),))
    result = observability._attach_trace_headers(response, context)
    assert result is response


def test_observability_attach_trace_headers_adds_missing() -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    context = observability._start("test", kind=None, attributes={}, datadog_tags=())
    assert context is not None
    context.tracestate = "vendor=contrib"
    response = Response(status=200)
    result = observability._attach_trace_headers(response, context)
    assert result is not response
    header_map = {key: value for key, value in result.headers}
    assert header_map["traceparent"] == context.traceparent
    assert header_map["tracestate"] == "vendor=contrib"


def test_observability_middleware_name_fallback() -> None:
    class CustomMiddleware:
        async def __call__(self, request: Request, handler):  # pragma: no cover - not invoked
            return await handler(request)

    name = Observability._middleware_name(CustomMiddleware())
    assert name == "CustomMiddleware"


def test_observability_start_extracts_trace_context() -> None:
    class RecordingSpan:
        def __init__(self) -> None:
            self.attributes: dict[str, Any] = {}

        def __enter__(self) -> "RecordingSpan":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def set_attribute(self, key: str, value: Any) -> None:
            self.attributes[key] = value

        def get_span_context(self) -> Any:
            return types.SimpleNamespace(trace_id="1", span_id="2", trace_flags=1)

    class RecordingContext:
        def __init__(self, span: RecordingSpan) -> None:
            self.span = span

        def __enter__(self) -> RecordingSpan:
            return self.span

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    class RecordingTracer:
        def __init__(self) -> None:
            self.kwargs: dict[str, Any] | None = None
            self.kind: Any | None = None

        def start_as_current_span(self, name: str, kind: Any | None = None, **kwargs: Any) -> RecordingContext:
            self.kind = kind
            self.kwargs = kwargs
            return RecordingContext(RecordingSpan())

    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    observability._tracer = RecordingTracer()
    observability._otel_extract = lambda carrier: {"extracted": carrier}
    context = observability._start(
        "test.span",
        kind=None,
        attributes={},
        datadog_tags=(),
        trace_context={"traceparent": "00-aa-aa-aa", "tracestate": "contrib=1"},
    )
    assert context is not None
    assert observability._tracer.kind is None
    assert observability._tracer.kwargs == {
        "context": {"extracted": {"traceparent": "00-aa-aa-aa", "tracestate": "contrib=1"}}
    }


def test_observability_start_ignores_none_trace_context() -> None:
    class RecordingSpan:
        def __init__(self) -> None:
            self.attributes: dict[str, Any] = {}

        def __enter__(self) -> "RecordingSpan":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def set_attribute(self, key: str, value: Any) -> None:
            self.attributes[key] = value

        def get_span_context(self) -> Any:
            return types.SimpleNamespace(trace_id="1", span_id="2", trace_flags=1)

    class RecordingTracer:
        def __init__(self) -> None:
            self.kwargs: dict[str, Any] | None = None

        def start_as_current_span(self, name: str, kind: Any | None = None, **kwargs: Any) -> RecordingSpan:
            self.kwargs = kwargs
            return RecordingSpan()

    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    observability._tracer = RecordingTracer()
    observability._otel_extract = lambda carrier: None
    context = observability._start(
        "test.span",
        kind=None,
        attributes={},
        datadog_tags=(),
        trace_context={"traceparent": "00-aa-aa-aa"},
    )
    assert context is not None
    assert observability._tracer.kwargs == {}


@pytest.mark.asyncio
async def test_observability_middleware_error_logs_exception(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    tracer = setup_stub_opentelemetry(monkeypatch)
    observability = Observability()
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/fail",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    request_context = observability.on_request_start(request)
    assert request_context is not None
    middleware_context = observability.on_middleware_start(lambda req, handler: handler(req), request, request_context)
    assert middleware_context is not None
    with caplog.at_level(logging.INFO, logger="artemis.observability"):
        observability.on_middleware_error(middleware_context, RuntimeError("boom"))
    assert tracer.spans[-1].exceptions[-1].args[0] == "boom"
    log = json.loads(caplog.records[-1].message)
    assert log["event"] == "middleware.error"
    assert log["error_type"] == "RuntimeError"


def test_observability_middleware_error_without_status_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracer = setup_stub_opentelemetry_without_status(monkeypatch)
    observability = Observability(ObservabilityConfig(datadog_enabled=False))
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
    request_context = observability.on_request_start(request)
    assert request_context is not None
    middleware_context = observability.on_middleware_start(object(), request, request_context)
    assert middleware_context is not None
    observability.on_middleware_error(middleware_context, RuntimeError("boom"))
    assert tracer.spans[-1].status is None


@pytest.mark.asyncio
async def test_observability_middleware_success_logs(caplog: pytest.LogCaptureFixture) -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/ok",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    request_context = observability.on_request_start(request)
    middleware_context = observability.on_middleware_start(object(), request, request_context)
    assert middleware_context is not None
    with caplog.at_level(logging.INFO, logger="artemis.observability"):
        observability.on_middleware_success(middleware_context)
    events = [json.loads(record.message)["event"] for record in caplog.records]
    assert "middleware.success" in events


def test_observability_middleware_start_disabled() -> None:
    observability = Observability(
        ObservabilityConfig(enabled=False, opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/disabled",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    assert observability.on_middleware_start(object(), request, None) is None


def test_observability_middleware_success_none() -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    observability.on_middleware_success(None)


def test_observability_middleware_error_none() -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    observability.on_middleware_error(None, RuntimeError("noop"))


def test_observability_on_request_start_disabled() -> None:
    observability = Observability(
        ObservabilityConfig(enabled=False, opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
        body=b"",
    )
    assert observability.on_request_start(request) is None
