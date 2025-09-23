from __future__ import annotations

import pytest

from artemis.routing import RouteGuard, Router, get, post, route


@pytest.mark.asyncio
async def test_router_matches_path_parameters() -> None:
    router = Router()

    async def handler(item_id: int) -> int:
        return item_id

    route = router.add_route("/items/{item_id}", methods=["GET"], endpoint=handler, name="get_item")
    match = router.find("GET", "/items/123")
    assert match.route is route
    assert match.params["item_id"] == "123"


@pytest.mark.asyncio
async def test_router_include_decorated_handler() -> None:
    router = Router()

    @get("/ping", name="ping")
    async def ping() -> str:
        return "pong"

    router.include([ping])
    match = router.find("GET", "/ping")
    assert match.route.spec.endpoint is ping
    assert match.route.spec.name == "ping"


def test_route_decorator_accepts_guard_sequences() -> None:
    guard_a = RouteGuard(action="items:read", resource_type="item")
    guard_b = RouteGuard(action="items:write", resource_type="item")

    @route("/items", methods=("GET", "POST"), authorize=[guard_a, guard_b])
    async def handler() -> None:
        return None

    spec = getattr(handler, "__artemis_route__")
    assert spec.guards == (guard_a, guard_b)


def test_route_decorator_single_guard() -> None:
    guard = RouteGuard(action="items:read", resource_type="item")

    @route("/items", methods=("GET",), authorize=guard)
    async def handler() -> None:
        return None

    spec = getattr(handler, "__artemis_route__")
    assert spec.guards == (guard,)


@pytest.mark.asyncio
async def test_router_find_not_found() -> None:
    router = Router()
    with pytest.raises(LookupError):
        router.find("GET", "/missing")


@pytest.mark.asyncio
async def test_router_handles_missing_groups(monkeypatch) -> None:
    router = Router()

    async def handler(item_id: str) -> str:
        return item_id

    route = router.add_route("/items/{item_id}", methods=["GET"], endpoint=handler)

    class DummyMatch:
        def group(self, name: str) -> str | None:
            return None

    class DummyPattern:
        @staticmethod
        def match(path: str) -> DummyMatch:
            return DummyMatch()

    route.pattern = DummyPattern()  # type: ignore[assignment]
    match = router.find("GET", "/items/42")
    assert match.params == {}


def test_router_applies_global_guards() -> None:
    router = Router()
    guard = RouteGuard(action="read", resource_type="item")
    router.guard(guard)

    async def handler() -> None:
        return None

    route = router.add_route("/items", methods=["GET"], endpoint=handler)
    assert guard in route.guards


@pytest.mark.asyncio
async def test_post_decorator_metadata() -> None:
    @post("/submit")
    async def submit() -> str:
        return "ok"

    spec = getattr(submit, "__artemis_route__")
    assert spec.methods == ("POST",)


def test_router_supports_path_converter() -> None:
    router = Router()

    async def handler(filepath: str) -> str:
        return filepath

    router.add_route("/static/{filepath:path}", methods=["GET"], endpoint=handler)
    match = router.find("GET", "/static/css/app.css")
    assert match.params["filepath"] == "css/app.css"


def test_router_rejects_unknown_converter() -> None:
    router = Router()

    async def handler() -> None:
        return None

    with pytest.raises(ValueError):
        router.add_route("/items/{item:uuid}", methods=["GET"], endpoint=handler)
