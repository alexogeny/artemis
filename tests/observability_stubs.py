from __future__ import annotations

import sys
import types
from typing import Any, cast

import pytest


class StubSpan:
    def __init__(self, name: str, kind: Any, *, trace_id: int, span_id: int) -> None:
        self.name = name
        self.kind = kind
        self.attributes: dict[str, Any] = {}
        self.status: Any | None = None
        self.exceptions: list[BaseException] = []
        self.exit_exception: BaseException | None = None
        self.ended = False
        self._trace_id = trace_id
        self._span_id = span_id
        self._trace_flags = 1

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def record_exception(self, exc: BaseException) -> None:
        self.exceptions.append(exc)

    def set_status(self, status: Any) -> None:
        self.status = status

    def get_span_context(self) -> Any:
        return types.SimpleNamespace(
            trace_id=self._trace_id,
            span_id=self._span_id,
            trace_flags=self._trace_flags,
        )


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
        self._counter = 1

    def start_as_current_span(self, name: str, kind: Any | None = None, **_: Any) -> StubSpanContext:
        span = StubSpan(name, kind, trace_id=self._counter, span_id=self._counter + 100)
        self._counter += 1
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
        self.scopes: list[Any] = []

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


class NoRecordSpan:
    def __init__(self, name: str, kind: Any | None) -> None:
        self.name = name
        self.kind = kind
        self.attributes: dict[str, Any] = {}
        self.status: Any | None = None
        self.ended = False

    def __enter__(self) -> NoRecordSpan:
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

    def start_as_current_span(self, name: str, kind: Any | None = None, **_: Any) -> NoRecordSpan:
        span = NoRecordSpan(name, kind)
        self.spans.append(span)
        return span


def setup_stub_opentelemetry(monkeypatch: pytest.MonkeyPatch) -> StubTracer:
    tracer = StubTracer()
    trace_module = cast(Any, types.ModuleType("opentelemetry.trace"))
    trace_module.get_tracer = lambda name: tracer
    trace_module.SpanKind = types.SimpleNamespace(CLIENT="client")

    class Status:
        def __init__(self, status_code: Any, description: str | None = None) -> None:
            self.status_code = status_code
            self.description = description

    trace_module.Status = Status
    trace_module.StatusCode = types.SimpleNamespace(OK="ok", ERROR="error")
    otel_module = cast(Any, types.ModuleType("opentelemetry"))
    otel_module.trace = trace_module
    propagate_module = cast(Any, types.ModuleType("opentelemetry.propagate"))

    def extract(carrier: Any, *_args: Any, **_kwargs: Any) -> Any:
        return carrier

    propagate_module.extract = extract
    otel_module.propagate = propagate_module
    monkeypatch.setitem(sys.modules, "opentelemetry", otel_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.propagate", propagate_module)
    return tracer


def setup_stub_opentelemetry_without_status(monkeypatch: pytest.MonkeyPatch) -> StubTracer:
    tracer = StubTracer()
    trace_module = cast(Any, types.ModuleType("opentelemetry.trace"))
    trace_module.get_tracer = lambda name: tracer
    trace_module.SpanKind = types.SimpleNamespace(CLIENT="client")
    otel_module = cast(Any, types.ModuleType("opentelemetry"))
    otel_module.trace = trace_module
    propagate_module = cast(Any, types.ModuleType("opentelemetry.propagate"))
    propagate_module.extract = lambda carrier, *_: carrier
    otel_module.propagate = propagate_module
    monkeypatch.setitem(sys.modules, "opentelemetry", otel_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.propagate", propagate_module)
    return tracer


def setup_stub_opentelemetry_without_record(monkeypatch: pytest.MonkeyPatch) -> NoRecordTracer:
    tracer = NoRecordTracer()
    trace_module = cast(Any, types.ModuleType("opentelemetry.trace"))
    trace_module.get_tracer = lambda name: tracer
    trace_module.SpanKind = types.SimpleNamespace(CLIENT="client")
    otel_module = cast(Any, types.ModuleType("opentelemetry"))
    otel_module.trace = trace_module
    propagate_module = cast(Any, types.ModuleType("opentelemetry.propagate"))
    propagate_module.extract = lambda carrier, *_: carrier
    otel_module.propagate = propagate_module
    monkeypatch.setitem(sys.modules, "opentelemetry", otel_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.propagate", propagate_module)
    return tracer


def setup_stub_sentry(monkeypatch: pytest.MonkeyPatch) -> StubSentryHub:
    hub = StubSentryHub()

    class Hub:
        current = hub

    sentry_module = cast(Any, types.ModuleType("sentry_sdk"))
    sentry_module.Hub = Hub
    monkeypatch.setitem(sys.modules, "sentry_sdk", sentry_module)
    return hub


def setup_stub_datadog(monkeypatch: pytest.MonkeyPatch) -> StubStatsd:
    statsd = StubStatsd()
    datadog_module = cast(Any, types.ModuleType("datadog"))
    datadog_module.statsd = statsd
    monkeypatch.setitem(sys.modules, "datadog", datadog_module)
    return statsd


__all__ = [
    "NoRecordSpan",
    "NoRecordTracer",
    "StubScope",
    "StubSentryHub",
    "StubSpan",
    "StubSpanContext",
    "StubStatsd",
    "StubTracer",
    "setup_stub_datadog",
    "setup_stub_opentelemetry",
    "setup_stub_opentelemetry_without_record",
    "setup_stub_opentelemetry_without_status",
    "setup_stub_sentry",
]
