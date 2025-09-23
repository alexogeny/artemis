from __future__ import annotations

import os

import pytest

from artemis.application import ArtemisApp
from artemis.config import AppConfig
from artemis.exceptions import HTTPError
from artemis.execution import TaskExecutor
from artemis.serialization import json_decode
from artemis.static import StaticFiles
from artemis.testing import TestClient


@pytest.mark.asyncio
async def test_mount_static_serves_files_for_all_tenants(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    bundle = assets / "app.js"
    bundle.write_text("console.log('ok');", encoding="utf-8")

    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    app.mount_static("/assets", directory=assets)

    async with TestClient(app) as client:
        for tenant in ("acme", "beta", "admin"):
            response = await client.get("/assets/app.js", tenant=tenant)
            assert response.status == 200
            assert response.body == b"console.log('ok');"
            headers = dict(response.headers)
            assert headers["content-type"] == "text/javascript; charset=utf-8"
            assert headers["cache-control"] == "public, max-age=3600"


@pytest.mark.asyncio
async def test_mount_static_serves_directory_index(tmp_path) -> None:
    assets = tmp_path / "assets"
    docs = assets / "docs"
    docs.mkdir(parents=True)
    (docs / "index.html").write_text("<h1>Docs</h1>", encoding="utf-8")

    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    app.mount_static("/assets", directory=assets)

    async with TestClient(app) as client:
        response = await client.get("/assets/docs", tenant="acme")
        assert response.status == 200
        headers = dict(response.headers)
        assert headers["content-type"] == "text/html; charset=utf-8"
        assert b"<h1>Docs</h1>" in response.body
        trailing = await client.get("/assets/docs/", tenant="beta")
        assert trailing.status == 200
        assert trailing.body == response.body


@pytest.mark.asyncio
async def test_mount_static_missing_and_traversal(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()

    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    app.mount_static("/assets", directory=assets, index_file=None)

    async with TestClient(app) as client:
        missing = await client.get("/assets/missing.txt", tenant="acme")
        assert missing.status == 404
        payload = json_decode(missing.body)
        assert payload["error"]["status"] == 404

        traversal = await client.get("/assets/../secrets.txt", tenant="beta")
        assert traversal.status == 404
        root_missing = await client.get("/assets", tenant="admin")
        assert root_missing.status == 404


@pytest.mark.asyncio
async def test_mount_static_head_request(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    script = assets / "bundle.js"
    script.write_text("console.log('head');", encoding="utf-8")
    expected_size = script.stat().st_size

    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    app.mount_static("/assets", directory=assets, cache_control="public, max-age=60")

    async with TestClient(app) as client:
        response = await client.request("HEAD", "/assets/bundle.js", tenant="acme")
        assert response.status == 200
        assert response.body == b""
        headers = dict(response.headers)
        assert headers["content-length"] == str(expected_size)
        assert headers["cache-control"] == "public, max-age=60"


def test_mount_static_requires_existing_directory(tmp_path) -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    with pytest.raises(ValueError):
        app.mount_static("/assets", directory=tmp_path / "missing")


def test_mount_static_rejects_absolute_index(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    with pytest.raises(ValueError):
        app.mount_static("/assets", directory=assets, index_file="/abs/index.html")


def test_mount_static_rejects_root_path(tmp_path) -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    with pytest.raises(ValueError):
        app.mount_static("/", directory=tmp_path)


def test_mount_static_rejects_empty_path(tmp_path) -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    with pytest.raises(ValueError):
        app.mount_static("   ", directory=tmp_path)


@pytest.mark.asyncio
async def test_staticfiles_direct_behaviors(tmp_path) -> None:
    if not hasattr(os, "symlink") or not hasattr(os, "mkfifo"):
        pytest.skip("platform lacks symlink or mkfifo support")

    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "index.html").write_text("home", encoding="utf-8")
    (assets / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (assets / "value.data").write_text("42", encoding="utf-8")
    (assets / "mystery.unknownext").write_text("?", encoding="utf-8")

    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    os.symlink(outside, assets / "link.txt")

    danger = assets / "danger"
    danger.mkdir()
    os.symlink(outside, danger / "index.html")

    empty_dir = assets / "empty"
    empty_dir.mkdir()

    folder = assets / "folder"
    folder.mkdir()
    (folder / "file.txt").write_text("folder", encoding="utf-8")

    pipe_path = assets / "pipe"
    os.mkfifo(pipe_path)

    executor = TaskExecutor()
    server = StaticFiles(
        directory=assets,
        executor=executor,
        cache_control=None,
        content_types={".data": "application/data"},
    )
    try:
        root = await server.serve("", method="GET")
        headers = dict(root.headers)
        assert "cache-control" not in headers
        assert headers["content-type"] == "text/html; charset=utf-8"

        with pytest.raises(HTTPError) as excinfo:
            await server.serve("index.html", method="POST")
        assert excinfo.value.status == 405

        with pytest.raises(HTTPError):
            await server.serve("link.txt", method="GET")

        with pytest.raises(HTTPError):
            await server.serve("danger", method="GET")

        with pytest.raises(HTTPError):
            await server.serve("empty", method="GET")

        override = await server.serve("value.data", method="GET")
        assert dict(override.headers)["content-type"] == "application/data"

        mystery = await server.serve("mystery.unknownext", method="GET")
        assert dict(mystery.headers)["content-type"] == "application/octet-stream"

        image = await server.serve("logo.png", method="GET")
        assert dict(image.headers)["content-type"] == "image/png"

        dir_server = StaticFiles(directory=assets, executor=executor, index_file="folder")
        with pytest.raises(HTTPError):
            await dir_server.serve("", method="GET")

        with pytest.raises(HTTPError):
            await server.serve("pipe", method="GET")

        follow_server = StaticFiles(
            directory=assets,
            executor=executor,
            cache_control=None,
            follow_symlinks=True,
        )
        followed = await follow_server.serve("link.txt", method="GET")
        assert followed.body == outside.read_bytes()
        followed_dir = await follow_server.serve("danger", method="GET")
        assert followed_dir.body == outside.read_bytes()
    finally:
        await executor.shutdown()


@pytest.mark.asyncio
async def test_mount_static_normalizes_path_and_names(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "app.js").write_text("console.log('named');", encoding="utf-8")

    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    app.mount_static("assets", directory=assets, name="static-assets")

    async with TestClient(app) as client:
        response = await client.get("/assets/app.js", tenant="acme")
        assert response.status == 200

    assert app.url_path_for("static-assets") == "/assets"
