"""Adapters for the Rust-backed ``id57`` helpers."""

from __future__ import annotations

import id57 as _id57

ALPHABET = _id57.ALPHABET
base57_encode = _id57.base57_encode
decode57 = _id57.decode57
generate_id57 = _id57.generate_id57

USING_RUST_BACKEND = getattr(generate_id57, "__module__", "").startswith("id57._core")
if not USING_RUST_BACKEND:  # pragma: no cover - runtime guard for unsupported platforms
    msg = "Mere requires the Rust-backed id57 extension; ensure the native wheel is available."
    raise RuntimeError(msg)

__all__ = [
    "ALPHABET",
    "USING_RUST_BACKEND",
    "base57_encode",
    "decode57",
    "generate_id57",
]
