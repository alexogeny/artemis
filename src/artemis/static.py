"""Static file serving utilities."""

from __future__ import annotations

import mimetypes
import os
import stat as stat_module
from email.utils import formatdate
from pathlib import Path
from typing import Mapping

from .exceptions import HTTPError
from .execution import TaskExecutor
from .responses import Response


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

    async def serve(self, path: str, *, method: str) -> Response:
        """Return a :class:`Response` for ``path`` using the provided HTTP ``method``."""

        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise HTTPError(405, {"detail": "method_not_allowed"})
        target, metadata = await self._locate(path)
        body = b""
        if method == "GET":
            body = await self._executor.run(target.read_bytes)
        headers = [
            ("content-type", self._content_type_for(target)),
            ("content-length", str(metadata.st_size)),
            ("last-modified", formatdate(metadata.st_mtime, usegmt=True)),
        ]
        if self._cache_control:
            headers.append(("cache-control", self._cache_control))
        return Response(status=200, headers=tuple(headers), body=body)

    async def _locate(self, path: str) -> tuple[Path, os.stat_result]:
        relative = self._sanitize(path)
        target = (self._root / relative).resolve()
        if not self._follow_symlinks:
            try:
                target.relative_to(self._root)
            except ValueError as exc:
                raise HTTPError(404, {"detail": "not_found"}) from exc
        try:
            metadata = await self._executor.run(target.stat)
        except FileNotFoundError as exc:
            raise HTTPError(404, {"detail": "not_found"}) from exc
        if stat_module.S_ISDIR(metadata.st_mode):
            if self._index_file is None:
                raise HTTPError(404, {"detail": "not_found"})
            index_target = (target / self._index_file).resolve()
            if not self._follow_symlinks:
                try:
                    index_target.relative_to(self._root)
                except ValueError as exc:
                    raise HTTPError(404, {"detail": "not_found"}) from exc
            try:
                metadata = await self._executor.run(index_target.stat)
            except FileNotFoundError as exc:
                raise HTTPError(404, {"detail": "not_found"}) from exc
            if stat_module.S_ISDIR(metadata.st_mode):
                raise HTTPError(404, {"detail": "not_found"})
            target = index_target
        if not stat_module.S_ISREG(metadata.st_mode):
            raise HTTPError(404, {"detail": "not_found"})
        return target, metadata

    def _sanitize(self, path: str) -> Path:
        raw = (path or "").lstrip("/")
        if not raw:
            return Path(".")
        candidate = Path(raw)
        if candidate.is_absolute() or any(part == ".." for part in candidate.parts):
            raise HTTPError(404, {"detail": "not_found"})
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


__all__ = ["StaticFiles"]
