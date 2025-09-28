from __future__ import annotations

from time import perf_counter
from typing import Any, Callable, cast

import pytest

import mere.routing as routing
from mere.routing import RouteGuard, RouteMatch, Router, get, post, route


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
async def test_router_scopes_routes_by_method() -> None:
    router = Router()

    async def handler() -> str:
        return "ok"

    router.add_route("/items", methods=["GET"], endpoint=handler)

    with pytest.raises(LookupError):
        router.find("POST", "/items")


@pytest.mark.asyncio
async def test_router_registers_multiple_methods() -> None:
    router = Router()

    async def handler() -> str:
        return "ok"

    route = router.add_route("/items", methods=["GET", "post"], endpoint=handler)

    assert route.spec.methods == ("GET", "POST")
    assert router.find("GET", "/items").route is route
    assert router.find("POST", "/items").route is route


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

    spec = getattr(handler, "__mere_route__")
    assert spec.guards == (guard_a, guard_b)


def test_route_decorator_single_guard() -> None:
    guard = RouteGuard(action="items:read", resource_type="item")

    @route("/items", methods=("GET",), authorize=guard)
    async def handler() -> None:
        return None

    spec = getattr(handler, "__mere_route__")
    assert spec.guards == (guard,)


@pytest.mark.asyncio
async def test_router_find_not_found() -> None:
    router = Router()

    async def handler() -> None:
        return None

    router.add_route("/items", methods=["GET"], endpoint=handler)
    with pytest.raises(LookupError):
        router.find("GET", "/missing")


@pytest.mark.asyncio
async def test_router_deduplicates_dynamic_candidates() -> None:
    router = Router()

    async def handler(item_id: str) -> str:
        return item_id

    router.add_route("/items/{item_id}", methods=["GET", "*"], endpoint=handler)

    match = router.find("GET", "/items/123")
    assert match.params["item_id"] == "123"


@pytest.mark.asyncio
async def test_router_dynamic_not_matching_pattern_raises() -> None:
    router = Router()

    async def handler(item_id: str) -> str:
        return item_id

    router.add_route("/items/{item_id}", methods=["GET"], endpoint=handler)

    with pytest.raises(LookupError):
        router.find("GET", "/items/123/details")


def test_prefix_helpers_cover_edge_cases() -> None:
    assert routing._dynamic_prefix_key("/static") == "/static"
    assert routing._dynamic_prefix_key("/{tenant}") is None
    assert routing._dynamic_prefix_key("/files/{path:path}") == "files"
    assert routing._dynamic_prefix_key("/foo{bar}") is None
    assert routing._request_prefix_key("/") is None
    assert routing._request_prefix_key("/docs/api") == "docs"


@pytest.mark.asyncio
async def test_router_supports_wildcard_method() -> None:
    router = Router()

    async def handler() -> str:
        return "ok"

    route = router.add_route("/any", methods=["*"], endpoint=handler)

    match = router.find("PATCH", "/any")
    assert match.route is route


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


def test_router_find_only_consults_routes_for_method() -> None:
    router = Router()

    async def handler() -> None:
        return None

    for idx in range(50):
        router.add_route(f"/posts/{idx}", methods=["POST"], endpoint=handler)

    for idx in range(50):
        router.add_route(f"/items/{idx}", methods=["GET"], endpoint=handler)

    class CountingPattern:
        def __init__(self, pattern: Any) -> None:
            self.pattern = pattern
            self.calls = 0

        def match(self, path: str) -> Any:
            self.calls += 1
            return self.pattern.match(path)

        def __getattr__(self, name: str) -> Any:
            return getattr(self.pattern, name)

    counting_patterns = []
    for registered_route in router._routes:
        wrapper = CountingPattern(registered_route.pattern)
        counting_patterns.append((registered_route, wrapper))
        registered_route.pattern = cast(Any, wrapper)

    match = router.find("GET", "/items/49")
    assert match.route.spec.path == "/items/49"

    post_calls = sum(
        wrapper.calls for registered_route, wrapper in counting_patterns if "POST" in registered_route.spec.methods
    )
    get_calls = sum(
        wrapper.calls for registered_route, wrapper in counting_patterns if "GET" in registered_route.spec.methods
    )
    get_routes = sum(1 for registered_route, _ in counting_patterns if "GET" in registered_route.spec.methods)

    assert post_calls == 0
    assert get_calls <= get_routes


@pytest.mark.asyncio
async def test_post_decorator_metadata() -> None:
    @post("/submit")
    async def submit() -> str:
        return "ok"

    spec = getattr(submit, "__mere_route__")
    assert spec.methods == ("POST",)


def test_router_dispatch_microbenchmark() -> None:
    router = Router()

    async def handler() -> None:
        return None

    for idx in range(2000):
        router.add_route(f"/background/{idx}", methods=["POST"], endpoint=handler)

    target_route = router.add_route("/bench/target", methods=["GET"], endpoint=handler)
    target_path = target_route.spec.path

    assert router.find("GET", target_path).route is target_route

    iterations = 3000

    def _measure(func: Callable[[], None]) -> float:
        start = perf_counter()
        func()
        return perf_counter() - start

    def run_router() -> None:
        for _ in range(iterations):
            router.find("GET", target_path)

    def _naive_find(method: str, path: str) -> RouteMatch:
        method_upper = method.upper()
        for registered_route in router._routes:
            if method_upper not in registered_route.spec.methods:
                continue
            captures = registered_route.pattern.match(path)
            if captures is None:
                continue
            params: dict[str, str] = {}
            for name in registered_route.param_names:
                group = captures.group(name)
                if group is not None:
                    params[name] = group
            return RouteMatch(route=registered_route, params=params)
        raise LookupError(f"No route matches {method_upper} {path}")

    def run_naive() -> None:
        for _ in range(iterations):
            _naive_find("GET", target_path)

    run_router()
    run_naive()

    optimized_time = _measure(run_router)
    baseline_time = _measure(run_naive)

    assert baseline_time > optimized_time
    assert baseline_time / optimized_time > 10


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
