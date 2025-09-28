"""Application configuration objects."""

from __future__ import annotations

from msgspec import Struct

from .chatops import ChatOpsConfig
from .database import DatabaseConfig
from .execution import ExecutionConfig
from .observability import ObservabilityConfig


class AppConfig(Struct, frozen=True):
    """Typed configuration for an :class:`~artemis.application.ArtemisApp` instance."""

    site: str = "demo"
    domain: str = "example.com"
    admin_subdomain: str = "admin"
    marketing_tenant: str = "public"
    allowed_tenants: tuple[str, ...] = ()
    max_request_body_bytes: int | None = 1_048_576
    execution: ExecutionConfig = ExecutionConfig()
    database: DatabaseConfig | None = None
    chatops: ChatOpsConfig = ChatOpsConfig()
    observability: ObservabilityConfig = ObservabilityConfig()

    def tenant_host(self, tenant: str) -> str:
        """Return the hostname for a given tenant."""

        if tenant == self.marketing_tenant:
            return f"{self.site}.{self.domain}"
        if tenant == self.admin_subdomain:
            return f"{self.admin_subdomain}.{self.site}.{self.domain}"
        return f"{tenant}.{self.site}.{self.domain}"
