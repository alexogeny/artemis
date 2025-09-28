from __future__ import annotations

import pytest

from mere.tenancy import TenantResolutionError, TenantResolver, TenantScope


@pytest.mark.parametrize(
    "host,expected_scope,expected_tenant",
    [
        ("acme.demo.example.com", TenantScope.TENANT, "acme"),
        ("beta.demo.example.com", TenantScope.TENANT, "beta"),
        ("admin.demo.example.com", TenantScope.ADMIN, "admin"),
        ("demo.example.com", TenantScope.PUBLIC, "public"),
    ],
)
def test_tenant_resolution(host: str, expected_scope: TenantScope, expected_tenant: str) -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    context = resolver.resolve(host)
    assert context.scope is expected_scope
    assert context.tenant == expected_tenant
    assert context.host == host


def test_tenant_resolution_rejects_unknown() -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    with pytest.raises(TenantResolutionError):
        resolver.resolve("gamma.demo.example.com")


def test_context_for_admin_and_public() -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    admin_ctx = resolver.context_for("admin", scope=TenantScope.ADMIN)
    assert admin_ctx.is_admin
    assert admin_ctx.host == "admin.demo.example.com"
    public_ctx = resolver.context_for("public", scope=TenantScope.PUBLIC)
    assert public_ctx.scope is TenantScope.PUBLIC
    assert public_ctx.host == "demo.example.com"


def test_context_key_representation() -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    context = resolver.resolve("acme.demo.example.com")
    assert context.key() == "tenant:acme@demo.example.com"


def test_tenant_resolution_errors() -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.resolve("alpha.beta.demo.example.com")
    with pytest.raises(TenantResolutionError):
        resolver.resolve("example.org")


def test_tenant_resolution_requires_allowlist() -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=())
    context = resolver.resolve("demo.example.com")
    assert context.scope is TenantScope.PUBLIC
    with pytest.raises(TenantResolutionError):
        resolver.resolve("acme.demo.example.com")
    with pytest.raises(TenantResolutionError):
        resolver.context_for("acme")


def test_context_for_unknown_tenant_rejected() -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    with pytest.raises(TenantResolutionError):
        resolver.context_for("beta")
