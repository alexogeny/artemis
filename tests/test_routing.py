from __future__ import annotations

import pytest

from artemis.routing import Router, get, post


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


@pytest.mark.asyncio
async def test_post_decorator_metadata() -> None:
    @post("/submit")
    async def submit() -> str:
        return "ok"

    spec = getattr(submit, "__artemis_route__")
    assert spec.methods == ("POST",)
