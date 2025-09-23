"""Static file serving utilities.

Compression relies on the ubiquitous ``brotli`` and ``zstandard`` C extensions
because no mature Rust-backed Python bindings exist for these codecs today.
"""

from __future__ import annotations

import gzip
import importlib
import mimetypes
import os
import stat as stat_module
from dataclasses import dataclass
from email.utils import formatdate
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping, cast

from .exceptions import HTTPError
from .execution import TaskExecutor
from .http import Status
from .responses import Response

brotli: ModuleType | None
try:  # pragma: no cover - optional dependency guard
    brotli = importlib.import_module("brotli")
except ModuleNotFoundError:  # pragma: no cover - runtime fallback when optional deps missing
    brotli = None

zstd: ModuleType | None
try:  # pragma: no cover - optional dependency guard
    zstd = importlib.import_module("zstandard")
except ModuleNotFoundError:  # pragma: no cover - runtime fallback when optional deps missing
    zstd = None

CompressFunc = Callable[[bytes], bytes]


def _gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=6)


if brotli is not None:  # pragma: no branch - optional dependency

    def _brotli_compress(data: bytes) -> bytes:
        assert brotli is not None
        return cast(Any, brotli).compress(data, quality=5)

else:  # pragma: no cover - executed when dependency missing
    _brotli_compress = None


if zstd is not None:  # pragma: no branch - optional dependency
    _ZSTD_COMPRESSOR = zstd.ZstdCompressor(level=6)

    def _zstd_compress(data: bytes) -> bytes:
        assert zstd is not None
        return _ZSTD_COMPRESSOR.compress(data)

else:  # pragma: no cover - executed when dependency missing
    _zstd_compress = None


def _available_compressors() -> tuple[tuple[str, CompressFunc], ...]:
    compressors: list[tuple[str, CompressFunc]] = []
    if _brotli_compress is not None:
        compressors.append(("br", _brotli_compress))
    if _zstd_compress is not None:
        compressors.append(("zstd", _zstd_compress))
    compressors.append(("gzip", _gzip_compress))
    return tuple(compressors)


_COMPRESSORS = _available_compressors()


def _stat_path_info(path: str) -> tuple[int, float, int]:
    metadata = os.stat(path)
    return metadata.st_size, metadata.st_mtime, metadata.st_mode


def _read_path_bytes(path: str) -> bytes:
    return Path(path).read_bytes()


@dataclass(slots=True, frozen=True)
class _FileMetadata:
    st_size: int
    st_mtime: float
    st_mode: int

    @property
    def is_dir(self) -> bool:
        return stat_module.S_ISDIR(self.st_mode)

    @property
    def is_file(self) -> bool:
        return stat_module.S_ISREG(self.st_mode)


@dataclass(slots=True)
class _AssetCacheEntry:
    metadata: _FileMetadata
    raw: bytes | None
    encodings: dict[str, bytes]


class StaticFiles:
    """Serve files from a directory tree using :class:`TaskExecutor`."""

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        executor: TaskExecutor,
        index_file: str | None = "index.html",
        follow_symlinks: bool = False,
        cache_control: str | None = "public, max-age=3600",
        content_types: Mapping[str, str] | None = None,
    ) -> None:
        root = Path(os.fspath(directory))
        if not root.is_dir():
            raise ValueError(f"Static directory {root!s} does not exist or is not a directory")
        if index_file is not None and Path(index_file).is_absolute():
            raise ValueError("index_file must be a relative path")
        self._root = root.resolve()
        self._executor = executor
        self._index_file = index_file
        self._follow_symlinks = follow_symlinks
        self._cache_control = cache_control
        self._content_types = {suffix.lower(): value for suffix, value in (content_types or {}).items()}
        self._compressors = _COMPRESSORS
        self._compressor_map = {name: func for name, func in self._compressors}
        self._asset_cache: dict[str, _AssetCacheEntry] = {}

    async def serve(
        self,
        path: str,
        *,
        method: str,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        """Return a :class:`Response` for ``path`` using the provided HTTP ``method``."""

        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise HTTPError(Status.METHOD_NOT_ALLOWED, {"detail": "method_not_allowed"})
        target, metadata = await self._locate(path)
        normalized_headers = {k.lower(): v for k, v in (headers or {}).items()}
        content_type = self._content_type_for(target)
        compressible = self._should_compress(content_type)
        negotiated = self._negotiate_encoding(
            normalized_headers.get("accept-encoding"),
            compressible=compressible,
        )
        compressor = self._compressor_map.get(negotiated) if negotiated else None
        cache_entry = self._cached_asset(target, metadata)
        metadata = cache_entry.metadata
        body: bytes
        content_length: int
        content_encoding: tuple[str, str] | None = None
        if compressor is not None:
            compressed = await self._ensure_compressed(cache_entry, target, negotiated, compressor)
            body = compressed if method == "GET" else b""
            content_length = len(compressed)
            if negotiated is None:  # pragma: no cover - defensive check
                raise RuntimeError("Compression selected without negotiated encoding")
            content_encoding = ("content-encoding", negotiated)
        else:
            if method == "GET":
                raw_body = await self._ensure_raw(cache_entry, target)
                body = raw_body
            else:
                body = b""
            content_length = metadata.st_size
        header_pairs = [
            ("content-type", content_type),
            ("content-length", str(content_length)),
            ("last-modified", formatdate(metadata.st_mtime, usegmt=True)),
            ("vary", "accept-encoding"),
        ]
        if content_encoding is not None:
            header_pairs.append(content_encoding)
        if self._cache_control:
            header_pairs.append(("cache-control", self._cache_control))
        return Response(status=int(Status.OK), headers=tuple(header_pairs), body=body)

    def _cached_asset(self, path: Path, metadata: _FileMetadata) -> _AssetCacheEntry:
        key = os.fspath(path)
        entry = self._asset_cache.get(key)
        if entry is None or entry.metadata != metadata:
            entry = _AssetCacheEntry(metadata=metadata, raw=None, encodings={})
            self._asset_cache[key] = entry
        return entry

    async def _ensure_raw(self, entry: _AssetCacheEntry, path: Path) -> bytes:
        if entry.raw is None:
            entry.raw = await self._read_file(path)
        return entry.raw

    async def _ensure_compressed(
        self,
        entry: _AssetCacheEntry,
        path: Path,
        encoding: str,
        compressor: CompressFunc,
    ) -> bytes:
        cached = entry.encodings.get(encoding)
        if cached is not None:
            return cached
        raw = await self._ensure_raw(entry, path)
        compressed = await self._executor.run(compressor, raw)
        entry.encodings[encoding] = compressed
        return compressed

    def _negotiate_encoding(self, header: str | None, *, compressible: bool) -> str | None:
        if not header or not self._compressors or not compressible:
            # Validate the header even if we are not compressing to respect q-values.
            header_values = header if header is not None else ""
            if header_values:
                q_values = self._parse_accept_encoding(header_values)
                wildcard_q = q_values.get("*")
                identity_q = q_values.get("identity")
                if identity_q is not None and identity_q <= 0 and (wildcard_q is None or wildcard_q <= 0):
                    raise HTTPError(Status.NOT_ACCEPTABLE, {"detail": "encoding_not_acceptable"})
            return None

        q_values = self._parse_accept_encoding(header)
        wildcard_q = q_values.get("*")
        best_encoding: str | None = None
        best_q = 0.0
        for name, _ in self._compressors:
            quality = q_values.get(name)
            if quality is None:
                if wildcard_q is None:
                    continue
                quality = wildcard_q
            if quality <= 0:
                continue
            if quality > best_q:
                best_q = quality
                best_encoding = name
        if best_encoding is None:
            identity_q = q_values.get("identity")
            if identity_q is not None and identity_q <= 0 and (wildcard_q is None or wildcard_q <= 0):
                raise HTTPError(Status.NOT_ACCEPTABLE, {"detail": "encoding_not_acceptable"})
        return best_encoding

    def _parse_accept_encoding(self, header: str) -> dict[str, float]:
        q_values: dict[str, float] = {}
        for raw_part in header.split(","):
            token = raw_part.strip()
            if not token:
                continue
            parts = [segment.strip() for segment in token.split(";") if segment.strip()]
            if not parts:
                continue
            encoding = parts[0].lower()
            quality = 1.0
            for param in parts[1:]:
                name, _, value = param.partition("=")
                if name.strip() != "q":
                    continue
                try:
                    quality = float(value)
                except ValueError:  # pragma: no cover - invalid q-value
                    quality = 0.0
            existing = q_values.get(encoding)
            if existing is None or quality > existing:
                q_values[encoding] = quality
        return q_values

    def _should_compress(self, content_type: str) -> bool:
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type.startswith("text/"):
            return True
        if media_type.endswith("+json") or media_type.endswith("+xml"):
            return True
        return media_type in {
            "application/json",
            "application/javascript",
            "application/xml",
            "application/xhtml+xml",
            "application/rss+xml",
            "application/atom+xml",
            "application/x-javascript",
            "application/yaml",
            "application/x-yaml",
            "image/svg+xml",
        }

    async def _locate(self, path: str) -> tuple[Path, _FileMetadata]:
        relative = self._sanitize(path)
        target = (self._root / relative).resolve()
        if not self._follow_symlinks:
            try:
                target.relative_to(self._root)
            except ValueError as exc:
                raise HTTPError(Status.NOT_FOUND, {"detail": "not_found"}) from exc
        try:
            metadata = await self._stat(target)
        except FileNotFoundError as exc:
            raise HTTPError(Status.NOT_FOUND, {"detail": "not_found"}) from exc
        if metadata.is_dir:
            if self._index_file is None:
                raise HTTPError(Status.NOT_FOUND, {"detail": "not_found"})
            index_target = (target / self._index_file).resolve()
            if not self._follow_symlinks:
                try:
                    index_target.relative_to(self._root)
                except ValueError as exc:
                    raise HTTPError(Status.NOT_FOUND, {"detail": "not_found"}) from exc
            try:
                metadata = await self._stat(index_target)
            except FileNotFoundError as exc:
                raise HTTPError(Status.NOT_FOUND, {"detail": "not_found"}) from exc
            if metadata.is_dir:
                raise HTTPError(Status.NOT_FOUND, {"detail": "not_found"})
            target = index_target
        if not metadata.is_file:
            raise HTTPError(Status.NOT_FOUND, {"detail": "not_found"})
        return target, metadata

    def _sanitize(self, path: str) -> Path:
        raw = (path or "").lstrip("/")
        if not raw:
            return Path(".")
        candidate = Path(raw)
        if candidate.is_absolute() or any(part == ".." for part in candidate.parts):
            raise HTTPError(Status.NOT_FOUND, {"detail": "not_found"})
        return candidate

    def _content_type_for(self, path: Path) -> str:
        override = self._content_types.get(path.suffix.lower())
        if override:
            return override
        guessed, _ = mimetypes.guess_type(path.name)
        if guessed is None:
            return "application/octet-stream"
        if guessed.startswith("text/") and "charset=" not in guessed:
            return f"{guessed}; charset=utf-8"
        return guessed

    async def _stat(self, path: Path) -> _FileMetadata:
        size, mtime, mode = await self._executor.run(_stat_path_info, os.fspath(path))
        return _FileMetadata(st_size=size, st_mtime=mtime, st_mode=mode)

    async def _read_file(self, path: Path) -> bytes:
        return await self._executor.run(_read_path_bytes, os.fspath(path))


__all__ = ["StaticFiles"]
