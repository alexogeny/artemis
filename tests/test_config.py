from __future__ import annotations

from mere.config import AppConfig


def test_tenant_host_variants() -> None:
    config = AppConfig(site="demo", domain="example.com")
    assert config.tenant_host(config.marketing_tenant) == "demo.example.com"
    assert config.tenant_host(config.admin_subdomain) == "admin.demo.example.com"
    assert config.tenant_host("acme") == "acme.demo.example.com"
