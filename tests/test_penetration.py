"""Regression-style penetration tests covering prior security findings."""

from __future__ import annotations

from types import MethodType
from typing import Any, Mapping

import pytest

from artemis.observability import Observability, ObservabilityConfig, _default_id_generator
from artemis.requests import Request
from artemis.tenancy import (
    TenantContext,
    TenantResolutionError,
    TenantResolver,
    TenantScope,
)

LONG_HOSTNAME = ".".join(["a" * 63] * 5) + ".demo.example.com"
OVERLONG_LABEL_HOST = ("a" * 64) + ".demo.example.com"


@pytest.mark.parametrize(
    "host",
    [
        "",  # empty host header
        " acme.demo.example.com",  # leading whitespace
        "acme.demo.example.com\r\nmalicious",  # header injection attempt
        "acme.demo.example.com/../../../etc/passwd",  # path traversal style payload
        ".demo.example.com",  # leading dot should be rejected
        "acme..demo.example.com",  # empty label in hostname
        "acme_demo.example.com",  # invalid character
        "acme.demo.example.com:abc",  # non-numeric port
        "acme.demo.example.com:0",  # invalid port number
        "acme.demo.example.com:70000",  # port out of range
        "acme.demo.example.com:",  # empty port should be rejected
        LONG_HOSTNAME,  # hostname exceeds RFC length limits
        OVERLONG_LABEL_HOST,  # label exceeds RFC length limits
    ],
)
def test_tenant_resolver_rejects_malicious_hosts(host: str) -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.resolve(host)


def test_tenant_resolver_allows_normalized_hosts() -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    context = resolver.resolve("Acme.DEMO.Example.COM")
    assert context.tenant == "acme"
    assert context.scope is TenantScope.TENANT
    with_port = resolver.resolve("acme.demo.example.com:8443")
    assert with_port.tenant == "acme"
    assert with_port.scope is TenantScope.TENANT
    max_port = resolver.resolve("acme.demo.example.com:65535")
    assert max_port.tenant == "acme"
    assert max_port.scope is TenantScope.TENANT


def test_tenant_resolver_allows_max_label_length() -> None:
    tenant = "a" * 63
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=(tenant,))
    context = resolver.resolve(f"{tenant}.demo.example.com")
    assert context.tenant == tenant
    assert context.scope is TenantScope.TENANT


def test_default_id_generator_relies_on_secure_entropy(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_token_bytes(size: int) -> bytes:
        calls.append(size)
        if len(calls) == 1:
            return b"\x00" * size  # force retry to ensure zero bytes are rejected
        payload = bytearray(size)
        payload[-1] = len(calls)
        return bytes(payload)

    monkeypatch.setattr("artemis.observability.secrets.token_bytes", fake_token_bytes)
    generator = _default_id_generator()
    token = generator(16)
    assert token.endswith(f"{len(calls):02x}")
    assert calls == [16, 16]
    with pytest.raises(ValueError):
        generator(0)


def test_observability_rejects_malicious_trace_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    observability = Observability(
        ObservabilityConfig(
            opentelemetry_enabled=False,
            datadog_enabled=False,
            sentry_enabled=False,
        )
    )
    captured: dict[str, Any] = {}
    original_start = observability._start

    def fake_start(
        self,
        span_name: str,
        *,
        trace_context: Mapping[str, str] | None = None,
        traceparent: str | None = None,
        tracestate: str | None = None,
        **kwargs: Any,
    ) -> Any:
        captured["trace_context"] = trace_context
        captured["traceparent"] = traceparent
        captured["tracestate"] = tracestate
        return original_start(
            span_name,
            trace_context=trace_context,
            traceparent=traceparent,
            tracestate=tracestate,
            **kwargs,
        )

    monkeypatch.setattr(observability, "_start", MethodType(fake_start, observability))

    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="GET",
        path="/",
        headers={
            "traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01\r\nset-cookie: attack",
            "tracestate": "vendor=1\r\nattacker=2",
        },
        tenant=tenant,
    )

    context = observability.on_request_start(request)
    assert captured["trace_context"] is None
    assert captured["traceparent"] is None
    assert captured["tracestate"] is None
    assert context is not None
    assert "set-cookie" not in context.traceparent
