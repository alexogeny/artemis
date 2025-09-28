"""Testing helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping
from urllib.parse import urlencode

from .application import MereApp
from .responses import Response
from .serialization import json_encode

if TYPE_CHECKING:  # pragma: no cover - typing helper
    from .golden import RequestResponseRecorder


class TestClient:
    """Async test client that executes requests in-process."""

    __test__ = False

    def __init__(
        self,
        app: MereApp,
        *,
        default_tenant: str | None = None,
        recorder: "RequestResponseRecorder | None" = None,
    ) -> None:
        self.app = app
        self.default_tenant = default_tenant or app.config.marketing_tenant
        self.recorder = recorder

    async def __aenter__(self) -> "TestClient":
        await self.app.startup()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.app.shutdown()

    async def request(
        self,
        method: str,
        path: str,
        *,
        tenant: str | None = None,
        host: str | None = None,
        json: Any | None = None,
        query: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        label: str | None = None,
    ) -> Response:
        tenant_name = tenant or self.default_tenant
        resolved_host = host or self._host_for(tenant_name)
        payload = b""
        request_headers = dict(headers or {})
        if json is not None:
            payload = json_encode(json)
            request_headers.setdefault("content-type", "application/json")
        query_string = urlencode(query or {}, doseq=True)
        response = await self.app.dispatch(
            method,
            path,
            host=resolved_host,
            query_string=query_string,
            headers=request_headers,
            body=payload,
        )
        if self.recorder is not None:
            self.recorder.record(
                name=label or f"{method.upper()} {path}",
                method=method.upper(),
                path=path,
                host=resolved_host,
                tenant=tenant_name,
                headers=request_headers,
                query=dict(query or {}),
                json_body=json,
                response=response,
            )
        return response

    async def get(
        self,
        path: str,
        *,
        tenant: str | None = None,
        query: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        label: str | None = None,
    ) -> Response:
        return await self.request(
            "GET",
            path,
            tenant=tenant,
            query=query,
            headers=headers,
            label=label,
        )

    async def post(
        self,
        path: str,
        *,
        tenant: str | None = None,
        json: Any | None = None,
        headers: Mapping[str, str] | None = None,
        label: str | None = None,
    ) -> Response:
        return await self.request(
            "POST",
            path,
            tenant=tenant,
            json=json,
            headers=headers,
            label=label,
        )

    def _host_for(self, tenant: str) -> str:
        if tenant == self.app.config.marketing_tenant:
            return f"{self.app.config.site}.{self.app.config.domain}"
        if tenant == self.app.config.admin_subdomain:
            return f"{self.app.config.admin_subdomain}.{self.app.config.site}.{self.app.config.domain}"
        return f"{tenant}.{self.app.config.site}.{self.app.config.domain}"
