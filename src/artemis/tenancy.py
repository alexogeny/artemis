"""Tenant resolution primitives."""

from __future__ import annotations

from enum import Enum
from typing import Iterable

from msgspec import Struct


class TenantScope(str, Enum):
    TENANT = "tenant"
    ADMIN = "admin"
    PUBLIC = "public"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class TenantContext(Struct, frozen=True):
    tenant: str
    site: str
    domain: str
    scope: TenantScope

    @property
    def is_admin(self) -> bool:
        return self.scope is TenantScope.ADMIN

    @property
    def host(self) -> str:
        if self.scope is TenantScope.PUBLIC:
            return f"{self.site}.{self.domain}"
        if self.scope is TenantScope.ADMIN:
            return f"admin.{self.site}.{self.domain}"
        return f"{self.tenant}.{self.site}.{self.domain}"

    def key(self) -> str:
        return f"{self.scope}:{self.tenant}@{self.site}.{self.domain}"


class TenantResolutionError(ValueError):
    """Raised when a hostname cannot be mapped to a tenant."""


class TenantResolver:
    """Resolve hostnames into :class:`TenantContext` values."""

    def __init__(
        self,
        *,
        site: str,
        domain: str,
        admin_subdomain: str = "admin",
        marketing_tenant: str = "public",
        allowed_tenants: Iterable[str] | None = None,
    ) -> None:
        self.site = site
        self.domain = domain
        self.admin_subdomain = admin_subdomain
        self.marketing_tenant = marketing_tenant
        self.allowed_tenants = set(allowed_tenants or ())

    def resolve(self, host: str) -> TenantContext:
        hostname = host.split(":", 1)[0].lower()
        expected_suffix = f"{self.site}.{self.domain}"
        if hostname == expected_suffix:
            return TenantContext(
                tenant=self.marketing_tenant,
                site=self.site,
                domain=self.domain,
                scope=TenantScope.PUBLIC,
            )
        if hostname == f"{self.admin_subdomain}.{expected_suffix}":
            return TenantContext(
                tenant=self.admin_subdomain,
                site=self.site,
                domain=self.domain,
                scope=TenantScope.ADMIN,
            )
        suffix = f".{expected_suffix}"
        if hostname.endswith(suffix):
            tenant = hostname[: -len(suffix)]
            if "." in tenant:
                raise TenantResolutionError(f"Ambiguous tenant hostname: {host}")
            if self.allowed_tenants and tenant not in self.allowed_tenants:
                raise TenantResolutionError(f"Unknown tenant '{tenant}' for host {host}")
            return TenantContext(tenant=tenant, site=self.site, domain=self.domain, scope=TenantScope.TENANT)
        raise TenantResolutionError(f"Host {host} is not served by {expected_suffix}")

    def context_for(self, tenant: str, scope: TenantScope | None = None) -> TenantContext:
        resolved_scope = scope or (TenantScope.ADMIN if tenant == self.admin_subdomain else TenantScope.TENANT)
        if resolved_scope is TenantScope.PUBLIC:
            tenant = self.marketing_tenant
        return TenantContext(tenant=tenant, site=self.site, domain=self.domain, scope=resolved_scope)
