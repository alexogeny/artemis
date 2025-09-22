"""Observability integration for Artemis services."""

from __future__ import annotations

import time
from contextlib import ExitStack
from typing import TYPE_CHECKING, Any, Iterable, Mapping
from urllib.parse import urlparse

import msgspec

from .tenancy import TenantContext

if TYPE_CHECKING:
    from .chatops import ChatMessage, SlackWebhookConfig
    from .requests import Request
    from .responses import Response


class ChatOpsObservabilityConfig(msgspec.Struct, frozen=True):
    """ChatOps-specific metrics and tracing configuration."""

    span_name: str = "artemis.chatops.send"
    datadog_metric_sent: str = "artemis.chatops.sent"
    datadog_metric_error: str = "artemis.chatops.errors"
    datadog_metric_timing: str = "artemis.chatops.duration"


class RequestObservabilityConfig(msgspec.Struct, frozen=True):
    """HTTP request metrics and tracing configuration."""

    span_name: str = "artemis.request"
    datadog_metric_error: str = "artemis.request.errors"
    datadog_metric_timing: str = "artemis.request.duration"


class ObservabilityConfig(msgspec.Struct, frozen=True):
    """Top-level observability configuration."""

    enabled: bool = True
    opentelemetry_enabled: bool = True
    opentelemetry_tracer: str = "artemis"
    sentry_enabled: bool = True
    sentry_record_breadcrumbs: bool = True
    sentry_capture_exceptions: bool = True
    sentry_breadcrumb_category: str = "artemis"
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
        "metric_error",
        "metric_success",
        "metric_timing",
        "span",
        "stack",
        "start",
        "success_attributes",
    )

    def __init__(
        self,
        *,
        start: float,
        stack: ExitStack,
        span: Any | None,
        datadog_tags: tuple[str, ...],
        metric_success: str | None,
        metric_error: str | None,
        metric_timing: str | None,
        success_attributes: Mapping[str, Any] | None = None,
        error_attributes: Mapping[str, Any] | None = None,
        capture_exception: bool = True,
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

    def close(self, error: BaseException | None = None) -> None:
        if error is None:
            self.stack.__exit__(None, None, None)
        else:
            self.stack.__exit__(type(error), error, error.__traceback__)


class Observability:
    """Coordinate tracing, error tracking, and metrics providers."""

    def __init__(self, config: ObservabilityConfig | None = None) -> None:
        self.config = config or ObservabilityConfig()
        self._tracer = None
        self._client_span_kind = None
        self._server_span_kind = None
        self._status_cls = None
        self._status_code_cls = None
        self._status_ok = None
        self._status_error = None
        self._sentry_hub = None
        self._statsd = None
        self._base_datadog_tags = tuple(
            f"{key}:{value}" for key, value in self.config.datadog_tags
        )
        if self.config.enabled:
            self._prepare_opentelemetry()
            self._prepare_sentry()
            self._prepare_datadog()
        self._enabled = self.config.enabled and any(
            (self._tracer, self._sentry_hub, self._statsd)
        )

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

    def _status(self, code: Any, description: str | None = None) -> Any | None:
        if self._status_cls is None or code is None:
            return None
        if description is None:
            return self._status_cls(code)
        return self._status_cls(code, description=description)

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
    ) -> _ObservationContext | None:
        if not self._enabled:
            return None
        stack = ExitStack()
        span = None
        if self._tracer is not None:
            span = stack.enter_context(self._tracer.start_as_current_span(span_name, kind=kind))
            for key, value in attributes.items():
                span.set_attribute(key, value)
        if self._sentry_hub is not None:
            if (
                breadcrumb_message is not None
                and self.config.sentry_record_breadcrumbs
            ):
                self._sentry_hub.add_breadcrumb(
                    category=breadcrumb_category or self.config.sentry_breadcrumb_category,
                    level=breadcrumb_level or self.config.sentry_breadcrumb_level,
                    message=breadcrumb_message,
                    data=dict(breadcrumb_data or {}),
                )
            scope = stack.enter_context(self._sentry_hub.push_scope())
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
        return _ObservationContext(
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
        )

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
        if host:
            breadcrumb_data["webhook_host"] = host
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
            breadcrumb_message=message.text,
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

    def on_chatops_send_error(
        self, context: _ObservationContext | None, error: BaseException
    ) -> None:
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
        return self._start(
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
        )

    def on_request_success(
        self, context: _ObservationContext | None, response: "Response"
    ) -> None:
        if context is None:
            return
        status = getattr(response, "status", None)
        tags = list(context.datadog_tags)
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
        context.close()

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
        self._capture_exception(error)
        context.close(error)


__all__ = [
    "ChatOpsObservabilityConfig",
    "Observability",
    "ObservabilityConfig",
    "RequestObservabilityConfig",
]
