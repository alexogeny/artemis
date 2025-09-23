from __future__ import annotations

import gzip
import os

import brotli
import pytest
import zstandard as zstd

from artemis.application import ArtemisApp
from artemis.config import AppConfig
from artemis.exceptions import HTTPError
from artemis.execution import ExecutionConfig, ExecutionMode, TaskExecutor
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
            assert headers["vary"] == "accept-encoding"
            assert "content-encoding" not in headers


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
        assert headers["vary"] == "accept-encoding"
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
        assert payload["error"]["reason"] == "Not Found"

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
        assert headers["vary"] == "accept-encoding"
        assert "content-encoding" not in headers


@pytest.mark.asyncio
async def test_mount_static_applies_compression(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    script = assets / "bundle.js"
    script.write_text("const data = '" + "x" * 512 + "';", encoding="utf-8")
    expected = script.read_bytes()

    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    app.mount_static("/assets", directory=assets)

    async with TestClient(app) as client:
        plain = await client.get("/assets/bundle.js", tenant="acme")
        assert plain.status == 200
        plain_headers = dict(plain.headers)
        assert "content-encoding" not in plain_headers
        assert plain_headers["vary"] == "accept-encoding"

        gzip_response = await client.get(
            "/assets/bundle.js",
            tenant="acme",
            headers={"accept-encoding": "gzip"},
        )
        gzip_headers = dict(gzip_response.headers)
        assert gzip_headers["content-encoding"] == "gzip"
        assert gzip_headers["vary"] == "accept-encoding"
        assert gzip.decompress(gzip_response.body) == expected

        head_response = await client.request(
            "HEAD",
            "/assets/bundle.js",
            tenant="acme",
            headers={"accept-encoding": "gzip"},
        )
        head_headers = dict(head_response.headers)
        assert head_response.body == b""
        assert head_headers["content-encoding"] == "gzip"
        assert head_headers["content-length"] == str(len(gzip_response.body))

        br_response = await client.get(
            "/assets/bundle.js",
            tenant="beta",
            headers={"accept-encoding": "br, gzip;q=0.2"},
        )
        br_headers = dict(br_response.headers)
        assert br_headers["content-encoding"] == "br"
        assert br_headers["vary"] == "accept-encoding"
        assert brotli.decompress(br_response.body) == expected

        zstd_response = await client.get(
            "/assets/bundle.js",
            tenant="admin",
            headers={"accept-encoding": "gzip;q=0.1, zstd;q=0.9"},
        )
        zstd_headers = dict(zstd_response.headers)
        assert zstd_headers["content-encoding"] == "zstd"
        assert zstd_headers["vary"] == "accept-encoding"
        decompressor = zstd.ZstdDecompressor()
        assert decompressor.decompress(zstd_response.body) == expected


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
        assert headers["vary"] == "accept-encoding"
        assert "content-encoding" not in headers

        with pytest.raises(HTTPError) as excinfo:
            await server.serve("index.html", method="POST")
        assert isinstance(excinfo.value, HTTPError)
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

        image = await server.serve("logo.png", method="GET", headers={"accept-encoding": "gzip, br"})
        image_headers = dict(image.headers)
        assert image_headers["content-type"] == "image/png"
        assert image_headers["vary"] == "accept-encoding"
        assert "content-encoding" not in image_headers

        with pytest.raises(HTTPError) as unacceptable:
            await server.serve("logo.png", method="GET", headers={"accept-encoding": "identity;q=0"})
        assert isinstance(unacceptable.value, HTTPError)
        assert unacceptable.value.status == 406

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


def test_static_available_compressors_handles_missing(monkeypatch) -> None:
    from artemis import static as static_module

    current = static_module._available_compressors()
    assert ("gzip", static_module._gzip_compress) in current

    monkeypatch.setattr(static_module, "_brotli_compress", None)
    monkeypatch.setattr(static_module, "_zstd_compress", None)
    only_gzip = static_module._available_compressors()
    assert only_gzip == (("gzip", static_module._gzip_compress),)


@pytest.mark.asyncio
async def test_static_encoding_negotiation_branches(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "index.html").write_text("home", encoding="utf-8")

    executor = TaskExecutor()
    server = StaticFiles(directory=assets, executor=executor)
    try:
        def _identity(data: bytes) -> bytes:
            return data

        server._compressors = (("br", _identity), ("gzip", _identity))
        server._compressor_map = {name: _identity for name, _ in server._compressors}

        available = {name for name, _ in server._compressors}
        assert server._negotiate_encoding("*;q=0.5", compressible=True) in available
        assert server._negotiate_encoding("gzip;q=0, *;q=0.6", compressible=True) == "br"
        assert server._negotiate_encoding("gzip;q=0, identity;q=0.5", compressible=True) is None
        with pytest.raises(HTTPError) as excinfo:
            server._negotiate_encoding("gzip;q=0, identity;q=0", compressible=True)
        assert isinstance(excinfo.value, HTTPError)
        assert excinfo.value.status == 406

        parsed = server._parse_accept_encoding("gzip,, ;")
        assert parsed["gzip"] == 1.0
        parsed = server._parse_accept_encoding("gzip;q=0.8;foo=bar, gzip;q=0.5, gzip")
        assert parsed["gzip"] == 1.0
        assert server._should_compress("application/problem+json")
    finally:
        await executor.shutdown()


@pytest.mark.asyncio
async def test_staticfiles_executor_non_thread_modes(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "index.html").write_text("home", encoding="utf-8")

    for mode in (ExecutionMode.PROCESS, ExecutionMode.REMOTE):
        executor = TaskExecutor(ExecutionConfig(default_mode=mode, max_workers=1))
        server = StaticFiles(directory=assets, executor=executor)
        try:
            response = await server.serve("", method="GET")
            assert response.status == 200
            assert response.body == b"home"
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
