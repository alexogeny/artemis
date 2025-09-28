from __future__ import annotations

import asyncio

import msgspec
import pytest

from artemis.audit import audit_context, current_actor
from artemis.exceptions import HTTPError
from artemis.rbac import CedarEntity
from artemis.requests import _MAX_QUERY_PARAMS, Request
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
    assert await request.text() == '{"name":"Widget"}'
    body = await request.body()
    assert body == payload
    assert body is await request.body()
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


def test_request_defers_query_parsing() -> None:
    request = build_request(query_string="limit=5")
    assert request._query_params is None
    params = request.query_params
    assert request._query_params is params
    assert params["limit"] == ["5"]


def test_request_query_type_hints_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    import artemis.requests as requests_module

    requests_module._model_type_hints.cache_clear()
    call_count = 0
    original_get_type_hints = requests_module.get_type_hints

    def counting(model):
        nonlocal call_count
        call_count += 1
        return original_get_type_hints(model)

    monkeypatch.setattr(requests_module, "get_type_hints", counting)

    request = build_request(query_string="limit=5&active=true")
    request.query(QueryModel)
    request.query(QueryModel)
    assert call_count == 1
    requests_module._model_type_hints.cache_clear()


def test_request_rejects_excessive_query_parameters() -> None:
    request = build_request(query_string="&".join(f"key{index}=value" for index in range(_MAX_QUERY_PARAMS + 1)))
    with pytest.raises(HTTPError) as captured:
        _ = request.query_params
    error = captured.value
    assert isinstance(error, HTTPError)
    assert error.status == 400
    assert error.detail == {"detail": "too_many_query_parameters"}


@pytest.mark.asyncio
async def test_empty_json_body_returns_none() -> None:
    request = build_request()
    assert await request.json() is None


@pytest.mark.asyncio
async def test_request_body_loader_handles_large_payload() -> None:
    chunk = b"x" * 65536
    chunks = [chunk] * 32
    loader_calls = 0

    async def loader() -> bytes:
        nonlocal loader_calls
        loader_calls += 1
        buffer = bytearray()
        for part in chunks:
            buffer.extend(part)
        return bytes(buffer)

    request = build_request(body_loader=loader)
    assert loader_calls == 0
    payload = await request.body()
    assert loader_calls == 1
    assert len(payload) == len(chunk) * len(chunks)
    assert payload is await request.body()
    assert await request.text() == payload.decode()


@pytest.mark.asyncio
async def test_request_json_loader_caches_large_payload() -> None:
    payload_obj = {"name": "x" * (1024 * 256)}
    payload = json_encode(payload_obj)
    chunk_size = 32768
    loader_calls = 0

    async def loader() -> bytes:
        nonlocal loader_calls
        loader_calls += 1
        buffer = bytearray()
        for index in range(0, len(payload), chunk_size):
            buffer.extend(payload[index : index + chunk_size])
        return bytes(buffer)

    request = build_request(headers={"Content-Type": "application/json"}, body_loader=loader)
    decoded = await request.json()
    assert loader_calls == 1
    assert decoded == payload_obj
    assert await request.json() is decoded
    raw = await request.body()
    assert raw == payload
    assert raw is await request.body()
    assert await request.text() == payload.decode()


@pytest.mark.asyncio
async def test_request_loader_serializes_concurrent_access() -> None:
    calls = 0

    async def loader() -> bytes:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return b"sync"

    request = build_request(body_loader=loader)
    first, second = await asyncio.gather(request.body(), request.body())
    assert first is second
    assert calls == 1


@pytest.mark.asyncio
async def test_request_loader_waiters_receive_cached_body() -> None:
    ready = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def loader() -> bytes:
        nonlocal calls
        calls += 1
        ready.set()
        await release.wait()
        return b"payload"

    request = build_request(body_loader=loader)

    first_task = asyncio.create_task(request.body())
    await ready.wait()

    waiter_task = asyncio.create_task(request.body())
    await asyncio.sleep(0)
    release.set()

    first, waiter = await asyncio.gather(first_task, waiter_task)
    assert first == waiter == b"payload"
    assert calls == 1


@pytest.mark.asyncio
async def test_request_waiter_skips_loader_after_cache_fill() -> None:
    calls = 0

    async def loader() -> bytes:
        nonlocal calls
        calls += 1
        return b"never-called"

    request = build_request(body_loader=loader)

    await request._body_lock.acquire()
    try:
        waiter = asyncio.create_task(request.body())
        for _ in range(100):
            await asyncio.sleep(0)
            waiters = request._body_lock._waiters  # pragma: no cover - exercised in tests only
            if waiters:
                break
        else:  # pragma: no cover
            pytest.fail("waiter did not block on request body lock")
        request._body = b"prefilled"
        request._body_loader = None
    finally:
        request._body_lock.release()

    body = await waiter
    assert body == b"prefilled"
    assert calls == 0


@pytest.mark.asyncio
async def test_request_loader_handles_none_and_bytearray() -> None:
    async def none_loader() -> bytes | None:
        return None

    request_empty = build_request(body_loader=none_loader)
    empty_body = await request_empty.body()
    assert empty_body == b""
    assert empty_body is await request_empty.body()

    async def array_loader() -> bytearray:
        return bytearray(b"abc")

    request_array = build_request(body_loader=array_loader)
    body = await request_array.body()
    assert body == b"abc"
    assert isinstance(body, bytes)
    assert body is await request_array.body()


def test_request_body_and_loader_are_mutually_exclusive() -> None:
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    async def loader() -> bytes:
        return b"payload"

    with pytest.raises(ValueError):
        Request(method="GET", path="/", tenant=tenant, body=b"payload", body_loader=loader)


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
