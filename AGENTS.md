# AGENTS.md — **Artemis (Backend)**

Implement fast, safe, tenant-aware services and tools with a bias toward **Rust-backed Python** libraries, fully asynchronous functional code, and near-total test coverage.

---

## Tech Defaults (Rust-backed Python first)

* **Server/runtime:** `granian` (RSGI) as the app server.
* **Event loop:** `rloop`.
* **Regex:** `rure`.
* **Serialization:** `msgspec` (structs, JSON, msgpack).
* **Process/thread orchestration:** prefer Rust primitives exposed to Python; otherwise `multiprocessing`/`concurrent.futures` with msgspec IPC.
* **Tooling:**

  * Package/build: **uv** ([docs.astral.sh/uv](https://docs.astral.sh/uv/))
  * Lint/format: **ruff** ([docs.astral.sh/ruff](https://docs.astral.sh/ruff/))
  * Type checking: **ty** ([docs.astral.sh/ty](https://docs.astral.sh/ty/))
* Choose a non-Rust lib **only** when a Rust-backed option is impossible or impractical. Document the exception.

---

## Code Style & Structure

* **Asynchronous + functional by default.** No blocking calls in hot paths. Use `async` all the way down.
* **Modular & farmable.** Every unit should be runnable:

  1. in-thread, 2) in a separate process, **or** 3) on a remote worker.
* **Stateless services** where possible; pass state explicitly. No hidden globals or implicit singletons.
* **Pure functions** for core logic; side effects at boundaries only.
* **Readable, documented code.** 120-char line limit; clear names; concise docstrings with examples.
* **Declarative APIs.** Public surfaces accept typed config objects/structs or decorators—no imperative setup required.

---

## Concurrency & Offloading Rules

* Design each component with a **safe execution mode matrix**: `thread | process | remote`.
* **No shared mutable state** across workers. Communicate via msgspec-encoded messages.
* **Idempotency first.** All actions must be retryable. Include idempotency keys where relevant.
* Streaming I/O is preferred to large in-memory buffers.
* Timeouts and circuit breakers are mandatory on all I/O boundaries.

---

## Multitenancy

* **Addressing:** Tenants live at `<name>.<site>.<domain>`.

  * Central admin at `admin.<site>.<domain>`.
  * Root of `<site>.<domain>` is marketing/public.
* **Routing:** Resolve tenant from hostname. Reject ambiguous hosts.
* **Isolation:** No cross-tenant data access. Always require an explicit `TenantContext` in service boundaries.
* **Testing:** Every feature must have tests for at least **two distinct tenants** plus **admin** scope.

---

## Testing Policy (aim for \~100% coverage)

* **All code paths async-tested** (use `pytest-asyncio` or equivalent).
* **Coverage target:** 100% (or as close as practical). PRs **fail** if under threshold.
* Include:

  * Unit tests (pure logic, property-based where useful).
  * Concurrency tests (thread, process, remote modes).
  * Tenancy routing/isolation tests.
  * Serialization round-trip tests (msgspec).
  * Contract tests for public APIs (inputs/outputs, error models).
  * Performance smoke tests for critical paths.
* Every new public surface **must** ship with tests.
* **As part of every PR**, ensure that you've run these four things:
✅ uv run ruff format
✅ uv run ruff check
✅ uv run ty check
✅ uv run pytest

---

## CI Requirements (every PR)

1. `uv lock` is current; deps are pinned.
2. **ruff**: lint + format; zero warnings in changed files.
3. **ty**: type-check passes (no ignored errors in new/changed code).
4. Full async test suite with coverage threshold enforced.
5. Granian app boots in CI smoke test (RSGI entrypoint validated).

---

## API Design Checklist (Declarative)

* Typed config objects (msgspec structs) for inputs; no untyped dicts at boundaries.
* Defaults are safe and **non-surprising**; tuning is explicit and documented.
* All operations expose an **async** function + optional **declarative decorator**/factory.
* Inputs/outputs are **stable contracts**; version them if you must break changes.
* Errors are structured (typed) and serializable.

---

## Definition of Done

* Meets tech defaults or documented exceptions.
* Async, modular, farmable (thread/process/remote) with tests for each mode where meaningful.
* Tenant-aware with isolation tested.
* Readable code, 120-char lines, ruff-clean, ty-clean.
* Tests on PR with \~100% coverage and CI green.
* Public API is declarative, typed, and documented with examples.
* **As part of every PR**, ensure that you've run these four things:
✅ uv run ruff format
✅ uv run ruff check
✅ uv run ty check
✅ uv run pytest

*Keep it simple. Favor safety, clarity, and throughput.*
