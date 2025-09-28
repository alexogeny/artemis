"""Tenant resolution primitives."""

from __future__ import annotations

from enum import Enum
from typing import Iterable

from msgspec import Struct

_HOSTNAME_ALLOWED_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")
_MAX_HOSTNAME_LENGTH = 253
_MAX_LABEL_LENGTH = 63


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
        normalized = _normalize_host(host)
        hostname = normalized.split(":", 1)[0]
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
            if not self.allowed_tenants:
                raise TenantResolutionError("No tenant hosts are configured")
            if tenant not in self.allowed_tenants:
                raise TenantResolutionError(f"Unknown tenant '{tenant}' for host {host}")
            return TenantContext(tenant=tenant, site=self.site, domain=self.domain, scope=TenantScope.TENANT)
        raise TenantResolutionError(f"Host {host} is not served by {expected_suffix}")

    def context_for(self, tenant: str, scope: TenantScope | None = None) -> TenantContext:
        resolved_scope = scope or (TenantScope.ADMIN if tenant == self.admin_subdomain else TenantScope.TENANT)
        if resolved_scope is TenantScope.PUBLIC:
            tenant = self.marketing_tenant
        if resolved_scope is TenantScope.TENANT:
            if not self.allowed_tenants:
                raise TenantResolutionError("No tenant hosts are configured")
            if tenant not in self.allowed_tenants:
                raise TenantResolutionError(f"Unknown tenant '{tenant}'")
        return TenantContext(tenant=tenant, site=self.site, domain=self.domain, scope=resolved_scope)


def _normalize_host(raw: str) -> str:
    if not raw:
        raise TenantResolutionError("Host header is empty")
    candidate = raw
    if candidate != candidate.strip():
        raise TenantResolutionError("Host header contains surrounding whitespace")
    if any(ord(char) <= 31 or char == "\x7f" or char.isspace() for char in candidate):
        raise TenantResolutionError("Host header contains control characters")
    if "/" in candidate or "\\" in candidate:
        raise TenantResolutionError("Host header contains illegal characters")
    lower = candidate.lower()
    hostname, sep, port = lower.partition(":")
    if sep and not port:
        raise TenantResolutionError("Host header contains an invalid port")
    if not hostname or hostname.startswith(".") or hostname.endswith(".") or ".." in hostname:
        raise TenantResolutionError("Host header is not a valid DNS name")
    labels = hostname.split(".")
    if any(len(label) > _MAX_LABEL_LENGTH for label in labels):
        raise TenantResolutionError("Host header contains an overlong DNS label")
    if len(hostname) > _MAX_HOSTNAME_LENGTH:
        raise TenantResolutionError("Host header is too long")
    if any(char not in _HOSTNAME_ALLOWED_CHARS for char in hostname):
        raise TenantResolutionError("Host header contains invalid characters")
    if port:
        if not port.isdigit():
            raise TenantResolutionError("Host header contains an invalid port")
        port_value = int(port)
        if port_value <= 0 or port_value > 65535:
            raise TenantResolutionError("Host header contains an invalid port")
    return hostname + (sep + port if port else "")
