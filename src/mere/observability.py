"""Observability integration for Mere services."""

from __future__ import annotations

import json
import logging
import secrets
import time
from contextlib import ExitStack
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping
from urllib.parse import urlparse

import msgspec

from .tenancy import TenantContext

if TYPE_CHECKING:
    from .chatops import ChatMessage, SlackWebhookConfig
    from .requests import Request
    from .responses import Response


class ChatOpsObservabilityConfig(msgspec.Struct, frozen=True):
    """ChatOps-specific metrics and tracing configuration."""

    span_name: str = "mere.chatops.send"
    datadog_metric_sent: str = "mere.chatops.sent"
    datadog_metric_error: str = "mere.chatops.errors"
    datadog_metric_timing: str = "mere.chatops.duration"


class RequestObservabilityConfig(msgspec.Struct, frozen=True):
    """HTTP request metrics and tracing configuration."""

    span_name: str = "mere.request"
    datadog_metric_error: str = "mere.request.errors"
    datadog_metric_timing: str = "mere.request.duration"


class ObservabilityConfig(msgspec.Struct, frozen=True):
    """Top-level observability configuration."""

    enabled: bool = True
    opentelemetry_enabled: bool = True
    opentelemetry_tracer: str = "mere"
    sentry_enabled: bool = True
    sentry_record_breadcrumbs: bool = False
    sentry_capture_exceptions: bool = True
    sentry_breadcrumb_category: str = "mere"
    sentry_breadcrumb_level: str = "info"
    datadog_enabled: bool = True
    datadog_tags: tuple[tuple[str, str], ...] = ()
    chatops: ChatOpsObservabilityConfig = ChatOpsObservabilityConfig()
    request: RequestObservabilityConfig = RequestObservabilityConfig()


class _ObservationContext:
    __slots__ = (
        "capture_exception",
        "datadog_tags",
        "error_attributes",
        "log_fields",
        "metric_error",
        "metric_success",
        "metric_timing",
        "parent_span_id",
        "request_id",
        "span",
        "span_id",
        "stack",
        "start",
        "success_attributes",
        "trace_flags",
        "trace_id",
        "traceparent",
        "tracestate",
    )

    def __init__(
        self,
        *,
        start: float,
        stack: ExitStack | None,
        span: Any | None,
        datadog_tags: tuple[str, ...],
        metric_success: str | None,
        metric_error: str | None,
        metric_timing: str | None,
        success_attributes: Mapping[str, Any] | None = None,
        error_attributes: Mapping[str, Any] | None = None,
        capture_exception: bool = True,
        request_id: str | None = None,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
        trace_flags: str | None = None,
        traceparent: str | None = None,
        tracestate: str | None = None,
        log_fields: Mapping[str, Any] | None = None,
    ) -> None:
        self.start = start
        self.stack = stack
        self.span = span
        self.datadog_tags = datadog_tags
        self.metric_success = metric_success
        self.metric_error = metric_error
        self.metric_timing = metric_timing
        self.success_attributes = dict(success_attributes or {})
        self.error_attributes = dict(error_attributes or {})
        self.capture_exception = capture_exception
        self.request_id = request_id
        self.trace_id = trace_id
        self.parent_span_id = parent_span_id
        self.span_id: str | None = None
        self.trace_flags = trace_flags or "01"
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.log_fields = dict(log_fields or {})

    def close(self, error: BaseException | None = None) -> None:
        if self.stack is None:
            return
        if error is None:
            self.stack.__exit__(None, None, None)
        else:
            self.stack.__exit__(type(error), error, error.__traceback__)


@dataclass(slots=True)
class _TraceParent:
    version: str
    trace_id: str
    parent_span_id: str
    trace_flags: str

    def header(self) -> str:
        return f"{self.version}-{self.trace_id}-{self.parent_span_id}-{self.trace_flags}"


_TRACEPARENT_ALLOWED = frozenset("0123456789abcdef")
_MAX_TRACEPARENT_LENGTH = 256
_MAX_TRACESTATE_LENGTH = 512


def _is_hex_segment(value: str, length: int) -> bool:
    if len(value) != length:
        return False
    return all(char in _TRACEPARENT_ALLOWED for char in value)


def _default_id_generator() -> Callable[[int], str]:
    def generate(size: int) -> str:
        if size <= 0:
            raise ValueError("size must be positive")
        while True:
            token = secrets.token_bytes(size)
            if any(token):
                return token.hex()

    return generate


class Observability:
    """Coordinate tracing, error tracking, metrics, and logging providers."""

    def __init__(
        self,
        config: ObservabilityConfig | None = None,
        *,
        id_generator: Callable[[int], str] | None = None,
    ) -> None:
        self.config = config or ObservabilityConfig()
        self._tracer = None
        self._client_span_kind = None
        self._server_span_kind = None
        self._internal_span_kind = None
        self._status_cls = None
        self._status_code_cls = None
        self._status_ok = None
        self._status_error = None
        self._sentry_hub = None
        self._statsd = None
        self._otel_extract: Callable[[Mapping[str, str]], Any] | None = None
        self._logger = logging.getLogger("mere.observability")
        self._id_generator = id_generator or _default_id_generator()
        self._base_datadog_tags = tuple(f"{key}:{value}" for key, value in self.config.datadog_tags)
        if self.config.enabled:
            self._prepare_opentelemetry()
            self._prepare_sentry()
            self._prepare_datadog()
        self._enabled = self.config.enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

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
        self._client_span_kind = getattr(SpanKind, "CLIENT", None) if SpanKind else None
        self._server_span_kind = getattr(SpanKind, "SERVER", None) if SpanKind else None
        self._internal_span_kind = getattr(SpanKind, "INTERNAL", None) if SpanKind else None
        try:
            from opentelemetry.trace import (  # type: ignore[import-not-found]
                Status,
                StatusCode,
            )
        except ImportError:  # pragma: no cover - optional dependency
            self._status_cls = None
            self._status_code_cls = None
        else:
            self._status_cls = Status
            self._status_code_cls = StatusCode
            self._status_ok = getattr(StatusCode, "OK", None)
            self._status_error = getattr(StatusCode, "ERROR", None)
        try:
            from opentelemetry.propagate import extract  # type: ignore[import-not-found]
        except ImportError:  # pragma: no cover - optional dependency
            self._otel_extract = None
        else:
            self._otel_extract = extract

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

    def _ensure_hex(self, value: Any, size: int, *, default: str | None = None) -> str:
        digits: str | None
        if isinstance(value, str):
            digits = value.lower()
        elif isinstance(value, int):
            digits = f"{value:0{size * 2}x}"
        else:
            digits = default
        if digits is None:
            digits = self._id_generator(size)
        if len(digits) < size * 2:
            digits = digits.rjust(size * 2, "0")
        elif len(digits) > size * 2:
            digits = digits[-size * 2 :]
        return digits.lower()

    def _status(self, code: Any, description: str | None = None) -> Any | None:
        if self._status_cls is None or code is None:
            return None
        if description is None:
            return self._status_cls(code)
        return self._status_cls(code, description=description)

    @staticmethod
    def _parse_traceparent(header: str | None) -> _TraceParent | None:
        if not header:
            return None
        candidate = header.strip()
        if not candidate or len(candidate) > _MAX_TRACEPARENT_LENGTH:
            return None
        if any(ord(char) < 32 or char == "\x7f" for char in candidate):
            return None
        parts = candidate.split("-")
        if len(parts) < 4:
            return None
        version, trace_id, parent_span_id, trace_flags, *_ = parts
        version = version.lower()
        trace_id = trace_id.lower()
        parent_span_id = parent_span_id.lower()
        trace_flags = trace_flags.lower()
        if not _is_hex_segment(version, 2):
            return None
        if not _is_hex_segment(trace_id, 32):
            return None
        if not _is_hex_segment(parent_span_id, 16):
            return None
        if not _is_hex_segment(trace_flags, 2):
            return None
        if trace_id == "0" * 32 or parent_span_id == "0" * 16:
            return None
        return _TraceParent(
            version=version,
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            trace_flags=trace_flags,
        )

    @staticmethod
    def _sanitize_tracestate(header: str | None) -> str | None:
        if not header:
            return None
        if any(ord(char) < 32 or char == "\x7f" for char in header):
            return None
        candidate = header.strip()
        if not candidate or len(candidate) > _MAX_TRACESTATE_LENGTH:
            return None
        return candidate

    def _log(self, context: _ObservationContext | None, event: str, extra: Mapping[str, Any] | None = None) -> None:
        if not self.config.enabled:
            return
        payload: dict[str, Any] = {"event": event}
        if context is not None:
            payload.update(context.log_fields)
            if context.request_id:
                payload.setdefault("request_id", context.request_id)
            if context.trace_id:
                payload.setdefault("trace_id", context.trace_id)
            if context.span_id:
                payload.setdefault("span_id", context.span_id)
            if context.parent_span_id:
                payload.setdefault("parent_span_id", context.parent_span_id)
        if extra:
            for key, value in extra.items():
                if value is not None:
                    payload[key] = value
        payload["event"] = event
        self._logger.info(json.dumps(payload, separators=(",", ":")))

    @staticmethod
    def _attach_trace_headers(response: "Response", context: _ObservationContext) -> "Response":
        extra_headers: list[tuple[str, str]] = []
        existing = {key.lower() for key, _ in response.headers}
        if context.traceparent and "traceparent" not in existing:
            extra_headers.append(("traceparent", context.traceparent))
        if context.tracestate and "tracestate" not in existing:
            extra_headers.append(("tracestate", context.tracestate))
        if not extra_headers:
            return response
        return response.with_headers(extra_headers)

    def _start(
        self,
        span_name: str,
        *,
        kind: Any | None,
        attributes: Mapping[str, Any],
        datadog_tags: Iterable[str] = (),
        metrics: tuple[str | None, str | None, str | None] = (None, None, None),
        breadcrumb_message: str | None = None,
        breadcrumb_data: Mapping[str, Any] | None = None,
        breadcrumb_category: str | None = None,
        breadcrumb_level: str | None = None,
        sentry_tags: Mapping[str, Any] | None = None,
        sentry_extra: Mapping[str, Any] | None = None,
        success_attributes: Mapping[str, Any] | None = None,
        error_attributes: Mapping[str, Any] | None = None,
        capture_exception: bool = True,
        trace_context: Mapping[str, str] | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
        trace_flags: str | None = None,
        traceparent: str | None = None,
        tracestate: str | None = None,
        log_fields: Mapping[str, Any] | None = None,
    ) -> _ObservationContext | None:
        if not self._enabled:
            return None
        stack: ExitStack | None = None

        def ensure_stack() -> ExitStack:
            nonlocal stack
            if stack is None:
                stack = ExitStack()
            return stack

        span = None
        span_id: str | None = None
        trace_id_value = trace_id
        trace_flags_value = (trace_flags or "01").lower()
        if self._tracer is not None:
            span_kwargs: dict[str, Any] = {"kind": kind}
            if trace_context and self._otel_extract is not None:
                try:
                    otel_context = self._otel_extract(trace_context)
                except Exception:  # pragma: no cover - defensive guard
                    otel_context = None
                if otel_context is not None:
                    span_kwargs["context"] = otel_context
            span = ensure_stack().enter_context(self._tracer.start_as_current_span(span_name, **span_kwargs))
            for key, value in attributes.items():
                span.set_attribute(key, value)
            if hasattr(span, "get_span_context"):
                span_context = span.get_span_context()
                trace_id_value = self._ensure_hex(getattr(span_context, "trace_id", None), 16, default=trace_id_value)
                span_id = self._ensure_hex(getattr(span_context, "span_id", None), 8)
                trace_flags_value = self._ensure_hex(
                    getattr(span_context, "trace_flags", None),
                    1,
                    default=trace_flags_value,
                )
        if trace_id_value is None:
            trace_id_value = self._id_generator(16)
        if span_id is None:
            span_id = self._id_generator(8)
        if request_id is None:
            request_id = self._id_generator(6)
        traceparent_value = f"00-{trace_id_value}-{span_id}-{trace_flags_value}"
        if self._sentry_hub is not None:
            if breadcrumb_message is not None and self.config.sentry_record_breadcrumbs:
                self._sentry_hub.add_breadcrumb(
                    category=breadcrumb_category or self.config.sentry_breadcrumb_category,
                    level=breadcrumb_level or self.config.sentry_breadcrumb_level,
                    message=breadcrumb_message,
                    data=dict(breadcrumb_data or {}),
                )
            scope = ensure_stack().enter_context(self._sentry_hub.push_scope())
            if sentry_tags and hasattr(scope, "set_tag"):
                for key, value in sentry_tags.items():
                    scope.set_tag(key, value)
            if sentry_extra and hasattr(scope, "set_extra"):
                for key, value in sentry_extra.items():
                    scope.set_extra(key, value)
        tags = list(self._base_datadog_tags)
        for tag in datadog_tags:
            tags.append(tag)
        success_metric, error_metric, timing_metric = metrics
        context = _ObservationContext(
            start=time.perf_counter(),
            stack=stack,
            span=span,
            datadog_tags=tuple(tags),
            metric_success=success_metric,
            metric_error=error_metric,
            metric_timing=timing_metric,
            success_attributes=success_attributes,
            error_attributes=error_attributes,
            capture_exception=capture_exception,
            request_id=request_id,
            trace_id=trace_id_value,
            parent_span_id=parent_span_id,
            trace_flags=trace_flags_value,
            traceparent=traceparent_value,
            tracestate=tracestate,
            log_fields=log_fields,
        )
        context.span_id = span_id
        return context

    def _capture_exception(self, error: BaseException) -> None:
        if self._sentry_hub is not None and self.config.sentry_capture_exceptions:
            self._sentry_hub.capture_exception(error)

    @staticmethod
    def _webhook_host(url: str) -> str | None:
        try:
            parsed = urlparse(url)
        except ValueError:  # pragma: no cover - defensive parsing guard
            return None
        return parsed.hostname or parsed.netloc or None

    def on_chatops_send_start(
        self,
        tenant: TenantContext,
        message: "ChatMessage",
        config: "SlackWebhookConfig",
    ) -> _ObservationContext | None:
        attributes: dict[str, Any] = {
            "chatops.tenant": tenant.tenant,
            "chatops.scope": tenant.scope.value,
            "chatops.site": tenant.site,
            "chatops.transport": "slack.webhook",
            "chatops.message.length": len(message.text),
        }
        datadog_tags = [
            f"tenant:{tenant.tenant}",
            f"scope:{tenant.scope.value}",
            f"site:{tenant.site}",
        ]
        host = self._webhook_host(config.webhook_url)
        if host:
            attributes["chatops.webhook.host"] = host
            datadog_tags.append(f"webhook_host:{host}")
        channel = message.channel or config.default_channel
        if channel:
            attributes["chatops.channel"] = channel
            datadog_tags.append(f"channel:{channel}")
        sentry_tags = {
            "chatops.tenant": tenant.tenant,
            "chatops.scope": tenant.scope.value,
        }
        if host:
            sentry_tags["chatops.webhook_host"] = host
        sentry_extra = {
            "chatops.channel": channel or "",
            "chatops.message_length": len(message.text),
        }
        breadcrumb_data = {
            "tenant": tenant.tenant,
            "scope": tenant.scope.value,
            "site": tenant.site,
            "message_length": len(message.text),
        }
        if channel:
            breadcrumb_data["channel"] = channel
        breadcrumb_message = f"ChatOps message ({len(message.text)} chars)"
        return self._start(
            self.config.chatops.span_name,
            kind=self._client_span_kind,
            attributes=attributes,
            datadog_tags=datadog_tags,
            metrics=(
                self.config.chatops.datadog_metric_sent,
                self.config.chatops.datadog_metric_error,
                self.config.chatops.datadog_metric_timing,
            ),
            breadcrumb_message=breadcrumb_message,
            breadcrumb_data=breadcrumb_data,
            sentry_tags=sentry_tags,
            sentry_extra=sentry_extra,
            success_attributes={"chatops.result": "success"},
            error_attributes={"chatops.result": "error"},
            capture_exception=self.config.sentry_capture_exceptions,
        )

    def on_chatops_send_success(self, context: _ObservationContext | None) -> None:
        if context is None:
            return
        if self._statsd is not None:
            tags = list(context.datadog_tags)
            if context.metric_success:
                self._statsd.increment(context.metric_success, tags=tags)
            if context.metric_timing:
                duration_ms = (time.perf_counter() - context.start) * 1000.0
                self._statsd.timing(context.metric_timing, duration_ms, tags=tags)
        if context.span is not None:
            for key, value in context.success_attributes.items():
                context.span.set_attribute(key, value)
            status = self._status(self._status_ok)
            if status is not None:
                context.span.set_status(status)
        context.close()

    def on_chatops_send_error(self, context: _ObservationContext | None, error: BaseException) -> None:
        if context is None:
            self._capture_exception(error)
            return
        if context.span is not None:
            for key, value in context.error_attributes.items():
                context.span.set_attribute(key, value)
            if hasattr(context.span, "record_exception"):
                context.span.record_exception(error)
            status = self._status(self._status_error, description=str(error))
            if status is not None:
                context.span.set_status(status)
        if self._statsd is not None and context.metric_error:
            self._statsd.increment(context.metric_error, tags=list(context.datadog_tags))
        self._capture_exception(error)
        context.close(error)

    @staticmethod
    def _middleware_name(middleware: Any) -> str:
        name = getattr(middleware, "__qualname__", None) or getattr(middleware, "__name__", None)
        if name:
            return str(name)
        return middleware.__class__.__name__

    def on_middleware_start(
        self,
        middleware: Any,
        request: "Request",
        request_context: _ObservationContext | None,
    ) -> _ObservationContext | None:
        name = self._middleware_name(middleware)
        attributes = {
            "middleware.name": name,
            "http.method": request.method,
            "http.path": request.path,
        }
        datadog_tags = list(request_context.datadog_tags if request_context else [])
        datadog_tags.append(f"middleware:{name}")
        context = self._start(
            f"{self.config.request.span_name}.middleware",
            kind=self._internal_span_kind,
            attributes=attributes,
            datadog_tags=datadog_tags,
            metrics=(None, None, None),
            success_attributes={"middleware.result": "success"},
            error_attributes={"middleware.result": "error"},
            capture_exception=False,
            request_id=request_context.request_id if request_context else None,
            trace_id=request_context.trace_id if request_context else None,
            parent_span_id=request_context.span_id if request_context else None,
            trace_flags=request_context.trace_flags if request_context else None,
            tracestate=request_context.tracestate if request_context else None,
            log_fields={"middleware": name},
        )
        if context is not None:
            self._log(context, "middleware.start", {"middleware": name})
        return context

    def on_middleware_success(self, context: _ObservationContext | None) -> None:
        if context is None:
            return
        duration_ms = (time.perf_counter() - context.start) * 1000.0
        self._log(context, "middleware.success", {"duration_ms": duration_ms})
        context.close()

    def on_middleware_error(self, context: _ObservationContext | None, error: BaseException) -> None:
        if context is None:
            return
        if context.span is not None and hasattr(context.span, "record_exception"):
            context.span.record_exception(error)
            status = self._status(self._status_error, description=str(error))
            if status is not None:
                context.span.set_status(status)
        self._log(
            context,
            "middleware.error",
            {
                "error_type": type(error).__name__,
                "error_message": str(error),
            },
        )
        context.close(error)

    def on_request_start(self, request: "Request") -> _ObservationContext | None:
        attributes: dict[str, Any] = {
            "http.method": request.method,
            "http.target": request.path,
            "http.tenant": request.tenant.tenant,
            "http.scope": request.tenant.scope.value,
            "http.site": request.tenant.site,
        }
        datadog_tags = [
            f"method:{request.method}",
            f"tenant:{request.tenant.tenant}",
            f"scope:{request.tenant.scope.value}",
            f"site:{request.tenant.site}",
        ]
        sentry_tags = {
            "http.method": request.method,
            "http.tenant": request.tenant.tenant,
            "http.scope": request.tenant.scope.value,
        }
        incoming_trace = self._parse_traceparent(request.header("traceparent"))
        tracestate = self._sanitize_tracestate(request.header("tracestate"))
        trace_context: dict[str, str] = {}
        if incoming_trace is not None:
            trace_context["traceparent"] = incoming_trace.header()
            if tracestate:
                trace_context["tracestate"] = tracestate
        context = self._start(
            self.config.request.span_name,
            kind=self._server_span_kind,
            attributes=attributes,
            datadog_tags=datadog_tags,
            metrics=(
                None,
                self.config.request.datadog_metric_error,
                self.config.request.datadog_metric_timing,
            ),
            sentry_tags=sentry_tags,
            success_attributes={"http.result": "success"},
            error_attributes={"http.result": "error"},
            capture_exception=True,
            trace_context=trace_context or None,
            request_id=None,
            trace_id=incoming_trace.trace_id if incoming_trace else None,
            parent_span_id=incoming_trace.parent_span_id if incoming_trace else None,
            trace_flags=incoming_trace.trace_flags if incoming_trace else None,
            traceparent=incoming_trace.header() if incoming_trace else None,
            tracestate=tracestate,
            log_fields={
                "http.method": request.method,
                "http.path": request.path,
                "tenant": request.tenant.tenant,
                "scope": request.tenant.scope.value,
            },
        )
        if context is not None:
            self._log(
                context,
                "request.start",
                {
                    "http.method": request.method,
                    "http.path": request.path,
                    "tenant": request.tenant.tenant,
                    "scope": request.tenant.scope.value,
                },
            )
        return context

    def on_request_success(self, context: _ObservationContext | None, response: "Response") -> "Response":
        if context is None:
            return response
        status = getattr(response, "status", None)
        tags = list(context.datadog_tags)
        duration_ms: float | None = None
        if status is not None:
            tags.append(f"status:{status}")
        if self._statsd is not None and context.metric_timing:
            duration_ms = (time.perf_counter() - context.start) * 1000.0
            self._statsd.timing(context.metric_timing, duration_ms, tags=tags)
        if context.span is not None:
            if status is not None:
                context.span.set_attribute("http.status_code", status)
            for key, value in context.success_attributes.items():
                context.span.set_attribute(key, value)
            status_obj = self._status(self._status_ok)
            if status_obj is not None:
                context.span.set_status(status_obj)
        response_with_headers = self._attach_trace_headers(response, context)
        self._log(
            context,
            "request.success",
            {
                "http.status": status,
                "duration_ms": duration_ms,
            },
        )
        context.close()
        return response_with_headers

    def on_request_error(
        self,
        context: _ObservationContext | None,
        error: BaseException,
        *,
        status_code: int | None = None,
    ) -> None:
        if context is None:
            self._capture_exception(error)
            return
        tags = list(context.datadog_tags)
        if status_code is not None:
            tags.append(f"status:{status_code}")
        if self._statsd is not None:
            if context.metric_error:
                self._statsd.increment(context.metric_error, tags=tags)
            if context.metric_timing:
                duration_ms = (time.perf_counter() - context.start) * 1000.0
                self._statsd.timing(context.metric_timing, duration_ms, tags=tags)
        if context.span is not None:
            if status_code is not None:
                context.span.set_attribute("http.status_code", status_code)
            for key, value in context.error_attributes.items():
                context.span.set_attribute(key, value)
            if hasattr(context.span, "record_exception"):
                context.span.record_exception(error)
            status_obj = self._status(self._status_error, description=str(error))
            if status_obj is not None:
                context.span.set_status(status_obj)
        self._log(
            context,
            "request.error",
            {
                "error_type": type(error).__name__,
                "error_message": str(error),
                "http.status": status_code,
            },
        )
        self._capture_exception(error)
        context.close(error)


__all__ = [
    "ChatOpsObservabilityConfig",
    "Observability",
    "ObservabilityConfig",
    "RequestObservabilityConfig",
]
