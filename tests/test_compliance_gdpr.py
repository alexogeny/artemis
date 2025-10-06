"""GDPR Article 5 and Article 32 regression tests for privacy controls."""

from __future__ import annotations

import pytest

from mere.observability import (
    LoggingRedactionConfig,
    Observability,
    ObservabilityConfig,
    TenantRedactionConfig,
)
from mere.tenancy import TenantResolutionError, TenantResolver, TenantScope


def test_gdpr_request_logging_is_redacted() -> None:
    """Article 5(1)(c) data minimisation: redact identifiers from logs."""

    config = ObservabilityConfig(
        logging=LoggingRedactionConfig(request_path="redact", exception_message="hash"),
        tenant=TenantRedactionConfig(log_fields="redact"),
    )
    observability = Observability(config)

    payload = {"http.path": "/users/12345", "tenant": "acme", "error_message": "User email leaked"}
    observability._sanitize_log_payload(payload)

    assert payload["http.path"] == "[redacted]"
    assert payload["tenant"] == "[redacted]"
    assert payload["error_message"].startswith("[hash:")


def test_gdpr_rejects_ambiguous_tenant_hosts() -> None:
    """Article 32 requires strict isolation; nested tenant hosts are rejected."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    with pytest.raises(TenantResolutionError):
        resolver.resolve("nested.acme.demo.example.com")


def test_gdpr_rejects_invalid_port_specifications() -> None:
    """Article 32(1)(b) enforces rejection of malformed network endpoints."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.resolve("acme.demo.example.com:abc")


def test_gdpr_rejects_hosts_with_whitespace() -> None:
    """Article 32(1)(d) blocks host headers with surrounding whitespace."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.resolve(" acme.demo.example.com ")


def test_gdpr_public_host_maps_to_marketing_scope() -> None:
    """Article 25 privacy by design keeps marketing hosts in a public scope."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    context = resolver.resolve("demo.example.com")
    assert context.scope is TenantScope.PUBLIC
    assert context.tenant == "public"


def test_gdpr_admin_host_maps_to_privileged_scope() -> None:
    """Article 28(3)(h) ensures processor administration occurs on dedicated hosts."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    context = resolver.resolve("admin.demo.example.com")
    assert context.scope is TenantScope.ADMIN
    assert context.tenant == "admin"


def test_gdpr_resolver_supports_multiple_tenants_without_overlap() -> None:
    """Article 30 records of processing require deterministic tenant routing."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    acme = resolver.context_for("acme")
    beta = resolver.context_for("beta")

    assert acme.host == "acme.demo.example.com"
    assert beta.host == "beta.demo.example.com"
    assert acme.key() != beta.key()


def test_gdpr_hash_strategy_is_stable_for_log_payloads() -> None:
    """Article 5(1)(c) requires consistent hashing for audit comparisons."""

    config = ObservabilityConfig(
        logging=LoggingRedactionConfig(request_path="hash", exception_message="hash", hash_salt="pepper"),
        tenant=TenantRedactionConfig(log_fields="hash"),
    )
    observability = Observability(config)
    payload_a = {"http.path": "/users/42", "tenant": "acme"}
    payload_b = {"http.path": "/users/42", "tenant": "acme"}

    observability._sanitize_log_payload(payload_a)
    observability._sanitize_log_payload(payload_b)
    assert payload_a == payload_b


def test_gdpr_log_hashing_masks_tenant_metadata() -> None:
    """Article 32(2) limits tenant identifiers in operational logs."""

    config = ObservabilityConfig(tenant=TenantRedactionConfig(log_fields="hash"))
    observability = Observability(config)
    payload = {"tenant": "acme", "http.tenant": "beta", "site": "demo", "http.site": "demo.example.com"}

    observability._sanitize_log_payload(payload)
    for value in payload.values():
        assert isinstance(value, str) and value.startswith("[hash:")


def test_gdpr_datadog_tags_can_be_fully_redacted() -> None:
    """Article 5(1)(f) enforces confidentiality for exported monitoring tags."""

    config = ObservabilityConfig(tenant=TenantRedactionConfig(datadog_tags="redact"))
    observability = Observability(config)

    tags = observability._sanitize_datadog_tags(("tenant:acme", "http.site:demo.example.com"))
    assert tags[0] == "tenant:[redacted]"
    assert tags[1] == "http.site:[redacted]"


def test_gdpr_unknown_tenant_is_rejected() -> None:
    """Article 5(1)(d) demands accuracy checks for declared tenant identifiers."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.context_for("beta")


def test_gdpr_requires_configured_tenant_allowlist() -> None:
    """Article 24(1) accountability demands controllers maintain tenant allowlists."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=())
    with pytest.raises(TenantResolutionError):
        resolver.resolve("acme.demo.example.com")


def test_gdpr_blocks_control_characters_in_hosts() -> None:
    """Article 32(1)(a) defends against control character host header injection."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.resolve("acme.demo.example.com\x00")


def test_gdpr_sentry_tags_redacted_for_incident_reports() -> None:
    """Article 33(1) requires breach reporting tools to omit tenant identifiers."""

    config = ObservabilityConfig(tenant=TenantRedactionConfig(sentry_tags="redact"))
    observability = Observability(config)
    tags = observability._sanitize_sentry_tags({"tenant": "acme", "issue": "timeout"})
    assert tags is not None
    assert tags["tenant"] == "[redacted]"
    assert tags["issue"] == "timeout"


def test_gdpr_rejects_hosts_with_path_delimiters() -> None:
    """Article 32(1)(c) blocks host headers containing path delimiters."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.resolve("acme/demo.example.com")


def test_gdpr_rejects_overlong_dns_labels() -> None:
    """Article 32(2) enforces DNS label length checks for tenant hosts."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    overlong_label = "a" * 64
    with pytest.raises(TenantResolutionError):
        resolver.resolve(f"{overlong_label}.demo.example.com")


def test_gdpr_datadog_tags_can_be_hashed() -> None:
    """Article 28(3)(c) requires processors to pseudonymise monitoring exports."""

    config = ObservabilityConfig(tenant=TenantRedactionConfig(datadog_tags="hash"))
    observability = Observability(config)
    tags = observability._sanitize_datadog_tags(("tenant:acme", "chatops.site:demo"))
    assert tags[0].startswith("tenant:[hash:")
    assert tags[1].startswith("chatops.site:[hash:")


def test_gdpr_rejects_empty_host_headers() -> None:
    """Article 32(1)(b) requires requests to present a valid host identifier."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.resolve("")


def test_gdpr_resolver_normalizes_uppercase_hosts() -> None:
    """Article 5(1)(d) accuracy controls normalise tenant hostnames."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    context = resolver.resolve("ACME.DEMO.EXAMPLE.COM")
    assert context.tenant == "acme"
    assert context.scope is TenantScope.TENANT


def test_gdpr_rejects_hosts_exceeding_dns_length_limits() -> None:
    """Article 32(1)(c) blocks overlong hostnames that risk ambiguity."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    label = "a" * 63
    hostname = ".".join([label] * 4 + ["demo", "example", "com"])
    with pytest.raises(TenantResolutionError):
        resolver.resolve(hostname)
