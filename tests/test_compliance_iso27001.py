"""ISO/IEC 27001:2022 Annex A control coverage tests."""

from __future__ import annotations

import pytest

from mere.database import DatabaseCredentials, DatabaseError, SecretRef, SecretValue, TLSConfig
from mere.observability import (
    LoggingRedactionConfig,
    Observability,
    ObservabilityConfig,
    TenantRedactionConfig,
)
from tests.support import StaticSecretResolver


def test_iso27001_tls_config_resolves_secrets() -> None:
    """Annex A.8.24 and A.10.1 require protecting cryptographic material."""

    resolver = StaticSecretResolver(
        {
            ("vault", "ca-cert", None): "CA",  # trusted root
            ("vault", "client-cert", None): "CLIENT",  # client certificate
            ("vault", "client-key", None): "CLIENT_KEY",  # client key
            ("vault", "client-key-pass", None): "KEYPASS",  # encrypted key password
        }
    )
    tls = TLSConfig(
        mode="verify-full",
        ca_certificate=SecretValue(secret=SecretRef("vault", "ca-cert", None)),
        client_certificate=SecretValue(secret=SecretRef("vault", "client-cert", None)),
        client_key=SecretValue(secret=SecretRef("vault", "client-key", None)),
        client_key_password=SecretValue(secret=SecretRef("vault", "client-key-pass", None)),
        server_name="db.internal",
        certificate_pins=("sha256/abcdef",),
        minimum_version="TLSv1.2",
        maximum_version="TLSv1.3",
    )

    options = tls.resolve(resolver)
    assert options["sslmode"] == "verify-full"
    assert options["sslrootcert"] == "CA"
    assert options["sslcert"] == "CLIENT"
    assert options["sslkey"] == "CLIENT_KEY"
    assert options["sslpassword"] == "KEYPASS"
    assert options["ssl_server_name"] == "db.internal"
    assert options["ssl_cert_pins"] == ("sha256/abcdef",)
    assert options["ssl_min_protocol_version"] == "TLSv1.2"
    assert options["ssl_max_protocol_version"] == "TLSv1.3"


def test_iso27001_datadog_tag_sanitization() -> None:
    """Annex A.8.11/A.8.12 expect tenant metadata to be sanitised before export."""

    config = ObservabilityConfig(tenant=TenantRedactionConfig(datadog_tags="hash"))
    observability = Observability(config)

    tags = observability._sanitize_datadog_tags(
        (
            "tenant:acme",
            "chatops.site:demo",
            "http.site:demo.example",
            "service:mere",
        )
    )
    assert tags[0].startswith("tenant:[hash:")
    assert tags[1].startswith("chatops.site:[hash:")
    assert tags[2].startswith("http.site:[hash:")
    assert "service:mere" in tags


def test_iso27001_secret_resolution_requires_controls() -> None:
    """Annex A.5.30 mandates secret retrieval go through controlled resolvers."""

    credential = SecretValue(secret=SecretRef("vault", "db-user", None))
    with pytest.raises(DatabaseError) as excinfo:
        credential.resolve(None, field="credentials.username")
    assert "Secret resolver required" in str(excinfo.value)


def test_iso27001_database_credentials_merge_sources() -> None:
    """Annex A.9.2.1 requires least privilege credentials to be centralised."""

    resolver = StaticSecretResolver({("vault", "db-user", None): "service"})
    credentials = DatabaseCredentials(
        username=SecretValue(secret=SecretRef("vault", "db-user", None)),
        password=SecretValue(literal="inline-secret"),
    )

    resolved = credentials.resolve(resolver)
    assert resolved == {"user": "service", "password": "inline-secret"}


def test_iso27001_logging_hashes_sensitive_identifiers() -> None:
    """Annex A.12.4.1 expects sensitive HTTP attributes to be anonymised."""

    config = ObservabilityConfig(
        logging=LoggingRedactionConfig(
            request_path="hash",
            exception_message="hash",
            hash_salt="pepper",
        ),
    )
    observability = Observability(config)
    payload = {"http.path": "/patients/42", "error_message": "PHI leaked"}

    observability._sanitize_log_payload(payload)
    assert payload["http.path"].startswith("[hash:")
    assert payload["error_message"].startswith("[hash:")


def test_iso27001_datadog_respects_raw_strategy() -> None:
    """Annex A.8.10 allows raw tenant tags only when explicitly approved."""

    config = ObservabilityConfig(tenant=TenantRedactionConfig(datadog_tags="raw"))
    observability = Observability(config)

    tags = observability._sanitize_datadog_tags(("tenant:acme", "service:mere"))
    assert tags == ("tenant:acme", "service:mere")


def test_iso27001_tls_config_handles_optional_material() -> None:
    """Annex A.10.1.1 allows disabling TLS fields only when controls documented."""

    tls = TLSConfig(mode="")
    assert tls.resolve(None) == {}


def test_iso27001_tracestate_rejects_control_characters() -> None:
    """Annex A.8.16 validates telemetry headers for integrity before export."""

    assert Observability._sanitize_tracestate("tenant=acme\x00sig") is None
    assert Observability._sanitize_tracestate(None) is None


def test_iso27001_tracestate_trims_extraneous_whitespace() -> None:
    """Annex A.8.16 strips whitespace to preserve canonical tracing metadata."""

    assert Observability._sanitize_tracestate("  vendor=mere ") == "vendor=mere"


def test_iso27001_sentry_tags_follow_tenant_strategy() -> None:
    """Annex A.8.11 requires tenant identifiers in Sentry to be anonymised."""

    config = ObservabilityConfig(tenant=TenantRedactionConfig(sentry_tags="hash"))
    observability = Observability(config)
    tags = observability._sanitize_sentry_tags({"tenant": "acme", "release": "1.2.3"})
    assert tags is not None
    assert tags["tenant"].startswith("[hash:")
    assert tags["release"] == "1.2.3"


def test_iso27001_rejects_unknown_logging_strategy() -> None:
    """Annex A.8.28 mandates rejecting unvetted logging redaction strategies."""

    config = ObservabilityConfig(logging=LoggingRedactionConfig(request_path="unsafe"))
    with pytest.raises(ValueError):
        Observability(config)


def test_iso27001_environment_flags_require_explicit_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Annex A.5.32 requires observability tooling changes be explicitly authorised."""

    monkeypatch.setenv("MERE_OBSERVABILITY_OPENTELEMETRY_ENABLED", "yes")
    monkeypatch.setenv("MERE_OBSERVABILITY_SENTRY_ENABLED", "1")
    monkeypatch.setenv("MERE_OBSERVABILITY_DATADOG_ENABLED", "on")

    config = ObservabilityConfig(
        opentelemetry_enabled=False,
        sentry_enabled=False,
        datadog_enabled=False,
    )
    observability = Observability(config)

    assert observability._opentelemetry_enabled is True
    assert observability._sentry_enabled is True
    assert observability._datadog_enabled is True
