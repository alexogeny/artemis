from __future__ import annotations

import msgspec
import pytest

from artemis.audit import audit_context, current_actor
from artemis.rbac import CedarEntity
from artemis.requests import Request
from artemis.serialization import json_encode
from artemis.tenancy import TenantContext, TenantScope


class BodyModel(msgspec.Struct):
    name: str


class QueryModel(msgspec.Struct):
    limit: int
    active: bool


def build_request(**kwargs) -> Request:
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    return Request(method="GET", path="/", tenant=tenant, **kwargs)


@pytest.mark.asyncio
async def test_request_body_helpers() -> None:
    payload = json_encode({"name": "Widget"})
    request = build_request(headers={"Content-Type": "application/json"}, body=payload)
    assert request.header("content-type") == "application/json"
    assert request.header("missing", "default") == "default"
    assert request.text() == '{"name":"Widget"}'
    assert request.body() == payload
    decoded = await request.json()
    assert decoded == {"name": "Widget"}
    model = await request.json(BodyModel)
    assert isinstance(model, BodyModel)
    assert model.name == "Widget"


@pytest.mark.asyncio
async def test_request_query_parsing() -> None:
    request = build_request(query_string="limit=5&active=true")
    request.query_params["noop"] = []
    params = request.query(QueryModel)
    assert params.limit == 5
    assert params.active is True


@pytest.mark.asyncio
async def test_empty_json_body_returns_none() -> None:
    request = build_request()
    assert await request.json() is None


@pytest.mark.asyncio
async def test_request_with_principal_updates_audit_actor() -> None:
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(method="GET", path="/", tenant=tenant)
    async with audit_context(tenant=tenant, actor=None):
        assert current_actor() is None
        request.with_principal(CedarEntity(type="User", id="user-1", attributes={"role": "member"}))
        actor = current_actor()
        assert actor is not None
        assert actor.id == "user-1"
        assert actor.type == "User"
        request.with_principal(None)
        assert current_actor() is None
