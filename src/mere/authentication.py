"""Authentication primitives for Mere."""

from __future__ import annotations

import asyncio
import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable, Iterable, Mapping, MutableMapping
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from time import monotonic
from typing import Any, Generic, Protocol, TypeVar
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key
from msgspec import Struct, structs

import lxml.etree as LET

try:  # pragma: no cover - optional dependency
    from argonautica import Hasher as ArgonauticaHasher  # type: ignore[import-not-found]
    from argonautica import Verifier as ArgonauticaVerifier  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency or build failure
    ArgonauticaHasher = None
    ArgonauticaVerifier = None
from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret as argon2_hash_secret

from .database import SecretResolver
from .exceptions import HTTPError
from .http import Status
from .id57 import generate_id57
from .models import (
    AdminUser,
    AppSecret,
    FederatedProvider,
    MfaCode,
    MfaPurpose,
    Passkey,
    SessionLevel,
    SessionToken,
    TenantFederatedUser,
    TenantOidcProvider,
    TenantSamlProvider,
    TenantSecret,
    TenantUser,
)
from .tenancy import TenantContext, TenantScope

__all__ = [
    "AuthenticationError",
    "AuthenticationFlowEngine",
    "AuthenticationFlowPasskey",
    "AuthenticationFlowResponse",
    "AuthenticationFlowSession",
    "AuthenticationFlowUser",
    "AuthenticationLoginRecord",
    "AuthenticationRateLimiter",
    "AuthenticationService",
    "FederatedIdentityDirectory",
    "IssuedSessionToken",
    "LoginStep",
    "MfaManager",
    "OidcAuthenticator",
    "OidcValidationDefaults",
    "PasskeyManager",
    "PasswordHasher",
    "SamlAuthenticator",
    "compose_admin_secret",
    "compose_tenant_secret",
]


class AuthenticationError(RuntimeError):
    """Raised when authentication fails."""


def compose_admin_secret(app_secret: AppSecret, user: AdminUser, *, resolver: SecretResolver) -> str:
    secret_value = app_secret.resolve_secret(resolver)
    return "::".join(["admin", secret_value, user.password_secret])


def compose_tenant_secret(
    app_secret: AppSecret,
    tenant_secret: TenantSecret,
    user: TenantUser,
    *,
    resolver: SecretResolver,
) -> str:
    secret_value = app_secret.resolve_secret(resolver)
    tenant_value = tenant_secret.resolve_secret(resolver)
    return "::".join(["tenant", secret_value, tenant_value, user.password_secret])


@dataclass(slots=True)
class _RateLimitState:
    failures: int = 0
    last_failure: dt.datetime | None = None
    locked_until: dt.datetime | None = None
    last_seen: dt.datetime | None = None


class AuthenticationRateLimiter:
    """Track authentication failures and enforce lockouts/backoff."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        window: dt.timedelta = dt.timedelta(minutes=15),
        lockout_period: dt.timedelta = dt.timedelta(minutes=15),
        base_cooldown: dt.timedelta = dt.timedelta(seconds=1),
        max_cooldown: dt.timedelta = dt.timedelta(seconds=30),
        max_entries: int = 1024,
    ) -> None:
        self.max_attempts = max_attempts
        self.window = window
        self.lockout_period = lockout_period
        self.base_cooldown = base_cooldown
        self.max_cooldown = max_cooldown
        self.max_entries = max(1, max_entries)
        self._states: dict[str, _RateLimitState] = {}
        self._lock = asyncio.Lock()

    async def enforce(self, keys: Iterable[str], now: dt.datetime) -> None:
        """Ensure ``keys`` are allowed to attempt authentication."""

        async with self._lock:
            self._prune(now)
            for key in keys:
                state = self._states.get(key)
                if state is None:
                    continue
                state.last_seen = now
                if self._refresh_state(key, state, now):
                    continue
                if state.locked_until is not None and state.locked_until > now:
                    raise AuthenticationError("account_locked")
                if state.failures > 0 and state.last_failure is not None:  # pragma: no branch - dependent state
                    cooldown = self._cooldown(state.failures)
                    next_allowed = state.last_failure + cooldown
                    if next_allowed > now:
                        raise AuthenticationError("rate_limited")

    async def record_failure(self, keys: Iterable[str], now: dt.datetime) -> None:
        """Record a failed authentication attempt."""

        async with self._lock:
            for key in keys:
                state = self._states.setdefault(key, _RateLimitState())
                state.last_seen = now
                if self._refresh_state(key, state, now):
                    state = self._states.setdefault(key, _RateLimitState())
                    state.last_seen = now
                state.failures += 1
                state.last_failure = now
                if state.failures >= self.max_attempts:
                    state.locked_until = now + self.lockout_period
                    state.failures = 0
                    state.last_failure = None
            self._prune(now)

    async def record_success(self, keys: Iterable[str]) -> None:
        """Reset throttling state after a successful authentication."""

        async with self._lock:
            for key in keys:
                self._states.pop(key, None)

    def _refresh_state(self, key: str, state: _RateLimitState, now: dt.datetime) -> bool:
        if state.locked_until is not None and state.locked_until <= now:
            state.locked_until = None
        if state.last_failure is not None and now - state.last_failure >= self.window:
            state.failures = 0
            state.last_failure = None
        if state.locked_until is None and state.last_failure is None and state.failures <= 0:
            self._states.pop(key, None)
            return True
        return False

    def _cooldown(self, failures: int) -> dt.timedelta:
        scaled = self.base_cooldown * (2 ** max(failures - 1, 0))
        return scaled if scaled <= self.max_cooldown else self.max_cooldown

    def _prune(self, now: dt.datetime) -> None:
        stale_cutoff = now - self.window
        removable = [
            key
            for key, state in self._states.items()
            if (state.locked_until is None and state.last_failure is None and state.failures <= 0)
            or (state.locked_until is None and state.last_seen is not None and state.last_seen <= stale_cutoff)
        ]
        for key in removable:
            self._states.pop(key, None)
        overflow = len(self._states) - self.max_entries
        if overflow <= 0:
            return
        ordered = sorted(
            self._states.items(),
            key=lambda item: item[1].last_seen or dt.datetime.min,
        )
        for key, _ in ordered[:overflow]:
            self._states.pop(key, None)


class IssuedSessionToken(Struct, frozen=True):
    """Composite result containing persisted and client session data."""

    token: str
    record: SessionToken

    @property
    def id(self) -> str:
        return self.record.id

    @property
    def user_id(self) -> str:
        return self.record.user_id

    @property
    def level(self) -> SessionLevel:
        return self.record.level

    @property
    def expires_at(self) -> dt.datetime:
        return self.record.expires_at

    @property
    def revoked_at(self) -> dt.datetime | None:
        return self.record.revoked_at


_SESSION_TOKEN_PBKDF2_ITERATIONS = 120_000


class PasswordHasher:
    """Async wrapper around Argonautica hashing and verification."""

    def __init__(
        self,
        *,
        time_cost: int = 4,
        memory_cost: int = 65_536,
        parallelism: int = 2,
        backend: str | None = None,
    ) -> None:
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.backend = backend or ("argonautica" if ArgonauticaHasher is not None else "argon2")

    async def hash(self, password: str, *, secret_key: str, salt: str) -> str:
        if self.backend == "argonautica" and ArgonauticaHasher is not None:  # pragma: no cover - optional backend
            hasher = ArgonauticaHasher(
                time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism
            )
            return await asyncio.to_thread(hasher.hash, password=password, secret_key=secret_key, salt=salt)
        return await asyncio.to_thread(
            _argon2_hash,
            password,
            secret_key,
            salt,
            self.time_cost,
            self.memory_cost,
            self.parallelism,
        )

    async def verify(self, password: str, *, secret_key: str, salt: str, expected: str) -> bool:
        if self.backend == "argonautica" and ArgonauticaVerifier is not None:  # pragma: no cover - optional backend
            verifier = ArgonauticaVerifier(
                time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism
            )
            return await asyncio.to_thread(
                verifier.verify, hash=expected, password=password, secret_key=secret_key, salt=salt
            )
        candidate = await asyncio.to_thread(
            _argon2_hash,
            password,
            secret_key,
            salt,
            self.time_cost,
            self.memory_cost,
            self.parallelism,
        )
        return hmac.compare_digest(candidate, expected)


class AuthenticationService:
    """High-level authentication helpers for Mere applications."""

    def __init__(
        self,
        password_hasher: PasswordHasher,
        *,
        secret_resolver: SecretResolver,
        rate_limiter: AuthenticationRateLimiter | None = None,
    ) -> None:
        self.password_hasher = password_hasher
        self._secret_resolver = secret_resolver
        self._rate_limiter = rate_limiter or AuthenticationRateLimiter()

    async def hash_admin_password(self, *, app_secret: AppSecret, user_secret: str, password: str) -> tuple[str, str]:
        salt = secrets.token_hex(16)
        secret_value = app_secret.resolve_secret(self._secret_resolver)
        secret_key = "::".join(["admin", secret_value, user_secret])
        hashed = await self.password_hasher.hash(password, secret_key=secret_key, salt=salt)
        return hashed, salt

    async def hash_tenant_password(
        self,
        *,
        app_secret: AppSecret,
        tenant_secret: TenantSecret,
        user_secret: str,
        password: str,
    ) -> tuple[str, str]:
        salt = secrets.token_hex(16)
        app_value = app_secret.resolve_secret(self._secret_resolver)
        tenant_value = tenant_secret.resolve_secret(self._secret_resolver)
        secret_key = "::".join(["tenant", app_value, tenant_value, user_secret])
        hashed = await self.password_hasher.hash(password, secret_key=secret_key, salt=salt)
        return hashed, salt

    async def verify_admin_password(self, *, user: AdminUser, app_secret: AppSecret, password: str) -> bool:
        secret = compose_admin_secret(app_secret, user, resolver=self._secret_resolver)
        return await self.password_hasher.verify(
            password, secret_key=secret, salt=user.password_salt, expected=user.hashed_password
        )

    async def verify_tenant_password(
        self,
        *,
        user: TenantUser,
        app_secret: AppSecret,
        tenant_secret: TenantSecret,
        password: str,
    ) -> bool:
        secret = compose_tenant_secret(app_secret, tenant_secret, user, resolver=self._secret_resolver)
        return await self.password_hasher.verify(
            password, secret_key=secret, salt=user.password_salt, expected=user.hashed_password
        )

    async def authenticate_tenant_password(
        self,
        *,
        user: TenantUser,
        app_secret: AppSecret,
        tenant_secret: TenantSecret,
        password: str,
        mfa_codes: Iterable[MfaCode] | None = None,
        submitted_code: str | None = None,
        now: dt.datetime | None = None,
        client_fingerprint: str | None = None,
    ) -> IssuedSessionToken:
        timestamp = now or dt.datetime.now(dt.UTC)
        keys = self._rate_limit_keys(user=user, tenant_secret=tenant_secret, client=client_fingerprint)
        await self._rate_limiter.enforce(keys, timestamp)

        if not await self.verify_tenant_password(
            user=user, app_secret=app_secret, tenant_secret=tenant_secret, password=password
        ):
            await self._rate_limiter.record_failure(keys, timestamp)
            raise AuthenticationError("invalid credentials")

        level = SessionLevel.PASSWORD_ONLY
        if user.mfa_enforced:
            if submitted_code is None:
                raise AuthenticationError("mfa_required")
            manager = MfaManager()
            manager.verify(
                codes=mfa_codes or [],
                user_id=user.id,
                submitted=submitted_code,
                purpose=MfaPurpose.SIGN_IN,
                now=timestamp,
            )
            level = SessionLevel.MFA

        await self._rate_limiter.record_success(keys)
        return self._issue_session_token(user_id=user.id, level=level, issued_at=timestamp)

    def authenticate_with_passkey(
        self,
        *,
        passkey: Passkey,
        challenge: str,
        signature: str,
        allow_user: TenantUser | AdminUser | None = None,
    ) -> IssuedSessionToken:
        manager = PasskeyManager()
        if not manager.verify(passkey=passkey, challenge=challenge, signature=signature):
            raise AuthenticationError("invalid_passkey")
        if allow_user is not None and getattr(allow_user, "id", None) != passkey.user_id:
            raise AuthenticationError("passkey_user_mismatch")
        return self._issue_session_token(user_id=passkey.user_id, level=SessionLevel.PASSKEY)

    def _rate_limit_keys(self, *, user: TenantUser, tenant_secret: TenantSecret, client: str | None) -> list[str]:
        keys = [f"user:{user.id}", f"tenant:{tenant_secret.id}"]
        if client:
            keys.append(f"client:{client}")
        return keys

    def _issue_session_token(
        self,
        *,
        user_id: str,
        level: SessionLevel,
        issued_at: dt.datetime | None = None,
    ) -> IssuedSessionToken:
        now = issued_at or dt.datetime.now(dt.UTC)
        token = generate_id57()
        salt = secrets.token_hex(16)
        token_hash = _derive_session_token_hash(token, salt)
        record = SessionToken(
            id=generate_id57(),
            user_id=user_id,
            token_hash=token_hash,
            token_salt=salt,
            created_at=now,
            updated_at=now,
            expires_at=now + dt.timedelta(hours=1),
            level=level,
        )
        return IssuedSessionToken(token=token, record=record)


class MfaManager:
    """Generate and validate one-time MFA codes."""

    def __init__(self, *, code_length: int = 6) -> None:
        self.code_length = code_length

    def issue(
        self,
        *,
        user_id: str,
        purpose: MfaPurpose,
        ttl: dt.timedelta = dt.timedelta(minutes=10),
        now: dt.datetime | None = None,
        channel: str = "totp",
    ) -> MfaCode:
        issued_at = now or dt.datetime.now(dt.UTC)
        code = "".join(str(secrets.randbelow(10)) for _ in range(self.code_length))
        return MfaCode(
            id=generate_id57(),
            user_id=user_id,
            code=code,
            purpose=purpose,
            created_at=issued_at,
            expires_at=issued_at + ttl,
            channel=channel,
        )

    def verify(
        self,
        *,
        codes: Iterable[MfaCode],
        user_id: str,
        submitted: str,
        purpose: MfaPurpose,
        now: dt.datetime | None = None,
    ) -> MfaCode:
        timestamp = now or dt.datetime.now(dt.UTC)
        for code in codes:
            if code.user_id != user_id or code.purpose is not purpose:
                continue
            if code.code != submitted:
                continue
            if code.consumed_at is not None or code.expires_at <= timestamp:
                break
            return structs.replace(code, consumed_at=timestamp)
        raise AuthenticationError("invalid_mfa_code")


class PasskeyManager:
    """Register and verify passkeys using HMAC based attestation."""

    def __init__(self) -> None:
        self._digest = sha256

    def register(
        self,
        *,
        user_id: str,
        credential_id: str,
        secret: bytes,
        user_handle: str,
        label: str | None = None,
        transports: Iterable[str] | None = None,
        now: dt.datetime | None = None,
    ) -> Passkey:
        created_at = now or dt.datetime.now(dt.UTC)
        encoded_secret = base64.urlsafe_b64encode(secret).decode().rstrip("=")
        return Passkey(
            id=generate_id57(),
            user_id=user_id,
            credential_id=credential_id,
            public_key=encoded_secret,
            user_handle=user_handle,
            created_at=created_at,
            transports=list(transports or []),
            label=label,
        )

    def challenge(self) -> str:
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")

    def sign(self, *, passkey: Passkey, challenge: str) -> str:
        secret = _decode_secret(passkey.public_key)
        digest = hmac.new(secret, challenge.encode(), self._digest).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def verify(self, *, passkey: Passkey, challenge: str, signature: str) -> bool:
        expected = self.sign(passkey=passkey, challenge=challenge)
        return hmac.compare_digest(signature, expected)


class AuthenticationFlowPasskey(Protocol):
    """Minimal passkey contract for authentication flows."""

    credential_id: str
    secret: str


class AuthenticationFlowUser(Protocol):
    """Minimal user contract for staged authentication flows."""

    id: str
    email: str
    password: str | None
    passkeys: Iterable[AuthenticationFlowPasskey]
    mfa_code: str | None
    sso: object | None


LoginUserT = TypeVar("LoginUserT", bound=AuthenticationFlowUser)
SessionT = TypeVar("SessionT")


@dataclass(slots=True)
class AuthenticationLoginRecord(Generic[LoginUserT]):
    """Mapping tying a login user to a tenant scope."""

    scope: TenantScope
    tenant: str
    user: LoginUserT


class LoginStep(str, Enum):
    """Next action required by the authentication flow."""

    SSO = "sso"
    PASSKEY = "passkey"
    PASSWORD = "password"
    MFA = "mfa"
    SUCCESS = "success"


class AuthenticationFlowSession(Struct, frozen=True):
    """Session metadata issued after a successful authentication flow."""

    token: str
    user_id: str
    scope: TenantScope
    level: SessionLevel
    expires_in: int


class AuthenticationFlowResponse(Struct, frozen=True):
    """Structured response describing the state of an authentication flow."""

    flow_token: str
    next: LoginStep
    fallback: LoginStep | None = None
    challenge: str | None = None
    credential_ids: tuple[str, ...] = ()
    provider: object | None = None
    session: object | None = None


@dataclass(slots=True)
class _LoginFlow(Generic[LoginUserT]):
    """Mutable in-memory login flow state."""

    id: str
    tenant: str
    scope: TenantScope
    user: LoginUserT
    step: LoginStep
    fallback: LoginStep | None
    challenge: str | None = None
    level: SessionLevel | None = None
    expires_at: float = 0.0
    attempts: int = 0


class AuthenticationFlowEngine(Generic[LoginUserT, SessionT]):
    """Reusable orchestration for staged authentication flows."""

    def __init__(
        self,
        *,
        flow_ttl_seconds: int = 600,
        session_ttl_seconds: int = 3600,
        max_attempts: int = 5,
        passkey_manager: PasskeyManager | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.flow_ttl_seconds = flow_ttl_seconds
        self.session_ttl_seconds = session_ttl_seconds
        self.max_attempts = max_attempts
        self._passkey_manager = passkey_manager or PasskeyManager()
        self._flows: MutableMapping[str, _LoginFlow[LoginUserT]] = {}
        self._users: dict[tuple[TenantScope, str, str], LoginUserT] = {}
        self._passkeys: dict[str, tuple[str, str]] = {}
        self._lock = asyncio.Lock()
        self._clock = clock or monotonic

    async def start(self, tenant: TenantContext, *, email: str) -> AuthenticationFlowResponse:
        """Begin a login flow for ``email`` within ``tenant``."""

        if tenant.scope is TenantScope.PUBLIC:
            raise HTTPError(Status.NOT_FOUND, {"detail": "login_not_available"})
        user = self._lookup_user(tenant.scope, tenant.tenant, email)
        async with self._lock:
            now = self._clock()
            self._prune_expired(now)
            flow_id = generate_id57()
            first_step, fallback = self._next_step(user)
            challenge = None
            if first_step is LoginStep.PASSKEY:
                challenge = self._passkey_manager.challenge()
            flow = _LoginFlow(
                id=flow_id,
                tenant=tenant.tenant,
                scope=tenant.scope,
                user=user,
                step=first_step,
                fallback=fallback,
                challenge=challenge,
                expires_at=now + self.flow_ttl_seconds,
            )
            self._flows[flow_id] = flow
            return self._render_flow(flow)

    async def passkey(self, tenant: TenantContext, attempt: Any) -> AuthenticationFlowResponse:
        """Verify a passkey assertion for ``attempt``."""

        async with self._lock:
            now = self._clock()
            flow = self._expect_flow(attempt.flow_token, tenant, now=now)
            if flow.step is LoginStep.SSO:
                if flow.fallback is not LoginStep.PASSKEY:
                    raise HTTPError(Status.BAD_REQUEST, {"detail": "passkey_not_available"})
                flow.step = LoginStep.PASSKEY
                flow.fallback = self._fallback_after(LoginStep.PASSKEY, flow.user)
                flow.challenge = self._passkey_manager.challenge()
                flow.expires_at = now + self.flow_ttl_seconds
                return self._render_flow(flow)
            if flow.step is not LoginStep.PASSKEY:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "passkey_not_expected"})
            record = self._passkeys.get(attempt.credential_id)
            if record is None or record[0] != getattr(flow.user, "id"):
                self._register_failure(flow)
                raise HTTPError(Status.UNAUTHORIZED, {"detail": "unknown_passkey"})
            challenge = flow.challenge
            if not challenge:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "missing_challenge"})
            passkey = self._passkey_manager.register(
                user_id=getattr(flow.user, "id"),
                credential_id=attempt.credential_id,
                secret=record[1].encode("utf-8"),
                user_handle=f"{getattr(flow.user, 'id')}:{flow.tenant}",
            )
            if not self._passkey_manager.verify(passkey=passkey, challenge=challenge, signature=attempt.signature):
                self._register_failure(flow)
                raise HTTPError(Status.UNAUTHORIZED, {"detail": "invalid_passkey"})
            self._reset_attempts(flow)
            return self._complete_primary(flow, SessionLevel.PASSKEY)

    async def password(self, tenant: TenantContext, attempt: Any) -> AuthenticationFlowResponse:
        """Verify a password submission."""

        async with self._lock:
            now = self._clock()
            flow = self._expect_flow(attempt.flow_token, tenant, now=now)
            if flow.step not in {LoginStep.PASSWORD, LoginStep.SSO, LoginStep.PASSKEY}:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "password_not_expected"})
            if flow.step is LoginStep.PASSKEY:
                if flow.fallback is not LoginStep.PASSWORD:
                    raise HTTPError(Status.BAD_REQUEST, {"detail": "password_not_available"})
                flow.step = LoginStep.PASSWORD
                flow.challenge = None
                flow.expires_at = now + self.flow_ttl_seconds
            user_password = getattr(flow.user, "password", None)
            if user_password is None or user_password != attempt.password:
                self._register_failure(flow)
                raise HTTPError(Status.UNAUTHORIZED, {"detail": "invalid_password"})
            self._reset_attempts(flow)
            return self._complete_primary(flow, SessionLevel.PASSWORD_ONLY)

    async def mfa(self, tenant: TenantContext, attempt: Any) -> AuthenticationFlowResponse:
        """Verify the MFA code for ``attempt``."""

        async with self._lock:
            now = self._clock()
            flow = self._expect_flow(attempt.flow_token, tenant, now=now)
            if flow.step is not LoginStep.MFA:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "mfa_not_expected"})
            if flow.level is None:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "primary_not_verified"})
            user_code = getattr(flow.user, "mfa_code", None)
            if user_code is None or user_code != attempt.code:
                self._register_failure(flow)
                raise HTTPError(Status.UNAUTHORIZED, {"detail": "invalid_mfa"})
            self._reset_attempts(flow)
            return self._finish(flow, SessionLevel.MFA)

    def reset(self, records: Iterable[AuthenticationLoginRecord[LoginUserT]]) -> None:
        """Replace indexed users and clear flow state."""

        self._flows.clear()
        self._users.clear()
        self._passkeys.clear()
        for record in records:
            key = (record.scope, record.tenant, record.user.email.lower())
            self._users[key] = record.user
            for passkey in getattr(record.user, "passkeys", ()):
                credential_id = getattr(passkey, "credential_id", None)
                secret = getattr(passkey, "secret", None)
                if credential_id and secret is not None:  # pragma: no branch
                    self._passkeys[credential_id] = (getattr(record.user, "id"), secret)

    def _complete_primary(self, flow: _LoginFlow[LoginUserT], level: SessionLevel) -> AuthenticationFlowResponse:
        if getattr(flow.user, "mfa_code", None):
            flow.step = LoginStep.MFA
            flow.level = level
            flow.expires_at = self._clock() + self.flow_ttl_seconds
            return self._render_flow(flow)
        return self._finish(flow, level)

    def _finish(self, flow: _LoginFlow[LoginUserT], level: SessionLevel) -> AuthenticationFlowResponse:
        session = self._issue_session(flow, level)
        self._flows.pop(flow.id, None)
        flow.step = LoginStep.SUCCESS
        return AuthenticationFlowResponse(
            flow_token=flow.id,
            next=LoginStep.SUCCESS,
            session=session,
        )

    def _render_flow(self, flow: _LoginFlow[LoginUserT]) -> AuthenticationFlowResponse:
        if flow.step is LoginStep.SUCCESS:
            raise HTTPError(Status.BAD_REQUEST, {"detail": "flow_completed"})
        payload: dict[str, object] = {}
        if flow.step is LoginStep.PASSKEY:
            payload["challenge"] = flow.challenge
            payload["credential_ids"] = tuple(
                getattr(passkey, "credential_id") for passkey in getattr(flow.user, "passkeys", ())
            )
        provider = getattr(flow.user, "sso", None) if flow.step is LoginStep.SSO else None
        return AuthenticationFlowResponse(
            flow_token=flow.id,
            next=flow.step,
            fallback=flow.fallback,
            challenge=payload.get("challenge"),
            credential_ids=payload.get("credential_ids", ()),
            provider=provider,
        )

    def _expect_flow(self, token: str, tenant: TenantContext, *, now: float) -> _LoginFlow[LoginUserT]:
        flow = self._flows.get(token)
        if flow is None or flow.scope is not tenant.scope or flow.tenant != tenant.tenant:
            raise HTTPError(Status.NOT_FOUND, {"detail": "unknown_flow"})
        if flow.expires_at <= now:
            self._flows.pop(flow.id, None)
            raise HTTPError(Status.GONE, {"detail": "flow_expired"})
        return flow

    def _lookup_user(self, scope: TenantScope, tenant: str, email: str) -> LoginUserT:
        key = (scope, tenant, email.lower())
        user = self._users.get(key)
        if user is None:
            raise HTTPError(Status.NOT_FOUND, {"detail": "unknown_user"})
        return user

    def _next_step(self, user: LoginUserT) -> tuple[LoginStep, LoginStep | None]:
        if getattr(user, "sso", None) is not None:
            return LoginStep.SSO, self._fallback_after(LoginStep.SSO, user)
        if getattr(user, "passkeys", None):
            return LoginStep.PASSKEY, self._fallback_after(LoginStep.PASSKEY, user)
        if getattr(user, "password", None) is not None:
            return LoginStep.PASSWORD, None
        raise HTTPError(Status.BAD_REQUEST, {"detail": "no_authenticators"})

    def _fallback_after(self, step: LoginStep, user: LoginUserT) -> LoginStep | None:
        has_passkeys = bool(getattr(user, "passkeys", ()))
        has_password = getattr(user, "password", None) is not None
        if step is LoginStep.SSO and has_passkeys:
            return LoginStep.PASSKEY
        if step in {LoginStep.SSO, LoginStep.PASSKEY} and has_password:
            return LoginStep.PASSWORD
        return None

    def _prune_expired(self, now: float) -> None:
        expired = [token for token, flow in self._flows.items() if flow.expires_at <= now]
        for token in expired:
            self._flows.pop(token, None)

    def _register_failure(self, flow: _LoginFlow[LoginUserT]) -> None:
        flow.attempts += 1
        if flow.attempts >= self.max_attempts:
            self._flows.pop(flow.id, None)
            raise HTTPError(Status.TOO_MANY_REQUESTS, {"detail": "flow_locked"})

    @staticmethod
    def _reset_attempts(flow: _LoginFlow[LoginUserT]) -> None:
        flow.attempts = 0

    def _issue_session(self, flow: _LoginFlow[LoginUserT], level: SessionLevel) -> SessionT:
        raise NotImplementedError  # pragma: no cover


class OidcValidationDefaults(Struct, frozen=True):
    """Default validation bounds for OpenID Connect tokens."""

    clock_skew_seconds: int = 120
    default_token_ttl_seconds: int | None = 300
    max_token_age_seconds: int | None = 3600
    require_iat: bool = True


class OidcAuthenticator:
    """Validate OIDC tokens using the provider's JWKS configuration."""

    def __init__(
        self,
        provider: TenantOidcProvider,
        *,
        defaults: OidcValidationDefaults | None = None,
        jwks_fetcher: Callable[[str], Mapping[str, Any]] | None = None,
        secret_resolver: SecretResolver | None = None,
    ) -> None:
        self.provider = provider
        self.defaults = defaults or OidcValidationDefaults()
        self._jwks_fetcher = jwks_fetcher or _default_jwks_fetcher
        self._jwks_cache: list[Mapping[str, Any]] | None = None
        self._secret_resolver = secret_resolver

    def validate(
        self,
        token: str,
        *,
        expected_nonce: str | None = None,
        now: dt.datetime | None = None,
    ) -> Mapping[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthenticationError("invalid_token")
        header_segment, payload_segment, signature_segment = parts
        signing_input = f"{header_segment}.{payload_segment}".encode()
        header = self._decode_segment(header_segment)
        alg = header.get("alg")
        if not isinstance(alg, str):
            raise AuthenticationError("unsupported_algorithm")
        kid_value = header.get("kid")
        if kid_value is not None and not isinstance(kid_value, str):
            raise AuthenticationError("invalid_token")
        key = self._resolve_jwk(alg, kid_value)
        self._verify_signature(alg, key, signing_input, signature_segment)
        claims = self._decode_segment(payload_segment)
        self._validate_claims(claims, expected_nonce=expected_nonce, now=now)
        return claims

    def _decode_segment(self, segment: str) -> Mapping[str, Any]:
        try:
            data = _b64url_decode(segment)
        except (binascii.Error, ValueError) as exc:
            raise AuthenticationError("invalid_token") from exc
        try:
            decoded = json.loads(data)
        except json.JSONDecodeError as exc:
            raise AuthenticationError("invalid_token") from exc
        if not isinstance(decoded, Mapping):
            raise AuthenticationError("invalid_token")
        return decoded

    def _load_jwks(self) -> list[Mapping[str, Any]]:
        if self._jwks_cache is None:
            document = self._jwks_fetcher(self.provider.jwks_uri)
            if not isinstance(document, Mapping):
                raise AuthenticationError("invalid_jwks")
            keys = document.get("keys")
            if keys is None:
                keys = []
            if not isinstance(keys, list):
                raise AuthenticationError("invalid_jwks")
            for key in keys:
                if not isinstance(key, Mapping):
                    raise AuthenticationError("invalid_jwks")
            self._jwks_cache = list(keys)
        return self._jwks_cache

    def _resolve_jwk(self, alg: str, kid: str | None) -> Mapping[str, Any]:
        expected_kty: str | None
        if alg in _HMAC_ALGORITHMS:
            expected_kty = "oct"
        elif alg in _RSA_HASH_ALGORITHMS:
            expected_kty = "RSA"
        else:
            expected_kty = None

        def select_key(keys: list[Mapping[str, Any]]) -> Mapping[str, Any] | None:
            matches: list[Mapping[str, Any]] = []
            for key in keys:
                if expected_kty is not None and key.get("kty") != expected_kty:
                    continue
                if kid is not None and key.get("kid") != kid:
                    continue
                matches.append(key)
            if kid is None:
                if len(matches) == 1:
                    return matches[0]
                if len(matches) > 1:
                    raise AuthenticationError("ambiguous_jwk")
                return None
            return matches[0] if matches else None

        keys = self._load_jwks()
        key = select_key(keys)
        if key is None:
            self._jwks_cache = None
            keys = self._load_jwks()
            key = select_key(keys)
        if key is None:
            has_expected_kty = expected_kty is not None and any(
                candidate.get("kty") == expected_kty for candidate in keys
            )
            if expected_kty == "oct" and not has_expected_kty:
                fallback = self._client_secret_hmac_key(alg)
                if fallback is not None:
                    return fallback
            raise AuthenticationError("unknown_jwk")
        key_alg = key.get("alg")
        if key_alg is not None and key_alg != alg:
            raise AuthenticationError("unsupported_algorithm")
        use = key.get("use")
        if use is not None and use != "sig":
            raise AuthenticationError("unsupported_jwk")
        return key

    def _client_secret_hmac_key(self, alg: str) -> Mapping[str, Any] | None:
        if alg not in _HMAC_ALGORITHMS:
            return None
        secret_ref = self.provider.client_secret
        if secret_ref is None:
            return None
        if self._secret_resolver is None:
            raise AuthenticationError("client_secret_unavailable")
        try:
            secret_value = self.provider.resolve_client_secret(self._secret_resolver)
        except Exception as exc:
            raise AuthenticationError("client_secret_unavailable") from exc
        if not secret_value.strip():
            raise AuthenticationError("client_secret_unavailable")
        return {
            "kty": "oct",
            "k": _b64url_encode(secret_value.encode()),
            "alg": alg,
            "use": "sig",
        }

    def _verify_signature(
        self,
        alg: str,
        key: Mapping[str, Any],
        signing_input: bytes,
        signature_segment: str,
    ) -> None:
        try:
            signature = _b64url_decode(signature_segment)
        except (binascii.Error, ValueError) as exc:
            raise AuthenticationError("invalid_token_signature") from exc
        kty = key.get("kty")
        if kty == "oct":
            secret_b64 = key.get("k")
            if not isinstance(secret_b64, str):
                raise AuthenticationError("invalid_jwks")
            try:
                secret = _b64url_decode(secret_b64)
            except (binascii.Error, ValueError) as exc:
                raise AuthenticationError("invalid_jwks") from exc
            digest_factory = _HMAC_ALGORITHMS.get(alg)
            if digest_factory is None:
                raise AuthenticationError("unsupported_algorithm")
            expected = hmac.new(secret, signing_input, digest_factory).digest()
            if not hmac.compare_digest(signature, expected):
                raise AuthenticationError("invalid_token_signature")
            return
        if kty == "RSA":
            if not _verify_rsa_signature(alg, key, signing_input, signature):
                raise AuthenticationError("invalid_token_signature")
            return
        raise AuthenticationError("unsupported_jwk")

    def _validate_claims(
        self,
        claims: Mapping[str, Any],
        *,
        expected_nonce: str | None,
        now: dt.datetime | None,
    ) -> None:
        issuer = claims.get("iss")
        if issuer != self.provider.issuer:
            raise AuthenticationError("invalid_issuer")
        audience_claim = claims.get("aud")
        if self.provider.allowed_audiences:
            audiences = _normalize_audience(audience_claim)
            if not audiences.intersection(self.provider.allowed_audiences):
                raise AuthenticationError("invalid_audience")
        now_instant = _ensure_utc(now)
        skew = dt.timedelta(seconds=max(self.defaults.clock_skew_seconds, 0))
        issued_at = _parse_epoch_claim(claims.get("iat"), "iat")
        if issued_at is None:
            if self.defaults.require_iat:
                raise AuthenticationError("missing_iat")
        else:
            if issued_at - skew > now_instant:
                raise AuthenticationError("token_issued_in_future")
            max_age_seconds = self.defaults.max_token_age_seconds
            if max_age_seconds is not None:
                max_age_delta = dt.timedelta(seconds=max(max_age_seconds, 0))
                if issued_at + max_age_delta + skew < now_instant:
                    raise AuthenticationError("token_replay_detected")
        expiration = _parse_epoch_claim(claims.get("exp"), "exp")
        if expiration is None:
            ttl_seconds = self.defaults.default_token_ttl_seconds
            if ttl_seconds is not None:
                if issued_at is None:
                    raise AuthenticationError("missing_exp")
                expiration = issued_at + dt.timedelta(seconds=max(ttl_seconds, 0))
        if expiration is not None and now_instant - skew >= expiration:
            raise AuthenticationError("token_expired")
        not_before = _parse_epoch_claim(claims.get("nbf"), "nbf")
        if not_before is not None and now_instant + skew < not_before:
            raise AuthenticationError("token_not_yet_valid")
        if expected_nonce is not None and claims.get("nonce") != expected_nonce:
            raise AuthenticationError("invalid_nonce")
        groups_claim = claims.get("groups", [])
        if isinstance(groups_claim, str):
            groups = {groups_claim}
        elif isinstance(groups_claim, list):
            groups = {value for value in groups_claim if isinstance(value, str)}
        else:
            groups = set()
        if self.provider.allowed_groups and not groups.intersection(self.provider.allowed_groups):
            raise AuthenticationError("unauthorized_group")


_HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

_RSA_HASH_ALGORITHMS = {
    "RS256": hashlib.sha256,
    "RS384": hashlib.sha384,
    "RS512": hashlib.sha512,
}

_RSA_DIGEST_INFOS = {
    "RS256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "RS384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "RS512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _verify_rsa_signature(
    alg: str,
    key: Mapping[str, Any],
    signing_input: bytes,
    signature: bytes,
) -> bool:
    hash_factory = _RSA_HASH_ALGORITHMS.get(alg)
    digest_prefix = _RSA_DIGEST_INFOS.get(alg)
    if hash_factory is None or digest_prefix is None:
        raise AuthenticationError("unsupported_algorithm")
    modulus_b64 = key.get("n")
    exponent_b64 = key.get("e")
    if not isinstance(modulus_b64, str) or not isinstance(exponent_b64, str):
        raise AuthenticationError("invalid_jwks")
    try:
        modulus_bytes = _b64url_decode(modulus_b64)
        exponent_bytes = _b64url_decode(exponent_b64)
    except (binascii.Error, ValueError) as exc:
        raise AuthenticationError("invalid_jwks") from exc
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    if modulus <= 0 or exponent <= 0:
        raise AuthenticationError("invalid_jwks")
    key_size = (modulus.bit_length() + 7) // 8
    digest = hash_factory(signing_input).digest()
    padding_len = key_size - len(digest_prefix) - len(digest) - 3
    if padding_len < 0:
        raise AuthenticationError("invalid_jwks")
    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus:
        return False
    decrypted = pow(signature_int, exponent, modulus).to_bytes(key_size, "big")
    expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_prefix + digest
    return hmac.compare_digest(decrypted, expected)


def _normalize_audience(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple)):
        entries = {item for item in value if isinstance(item, str)}
        if not entries and value:
            raise AuthenticationError("invalid_audience")
        return entries
    raise AuthenticationError("invalid_audience")


def _parse_epoch_claim(value: Any, claim: str) -> dt.datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        timestamp = int(value)
    elif isinstance(value, str):
        if not value:
            raise AuthenticationError(f"invalid_{claim}")
        try:
            timestamp = int(value)
        except ValueError as exc:
            raise AuthenticationError(f"invalid_{claim}") from exc
    else:
        raise AuthenticationError(f"invalid_{claim}")
    try:
        return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise AuthenticationError(f"invalid_{claim}") from exc


def _ensure_utc(moment: dt.datetime | None) -> dt.datetime:
    if moment is None:
        return dt.datetime.now(dt.timezone.utc)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc)


def _default_jwks_fetcher(uri: str) -> Mapping[str, Any]:
    from urllib.request import urlopen

    try:
        with urlopen(uri, timeout=5) as response:  # type: ignore[call-arg]
            status = getattr(response, "status", 200)
            if status != 200:
                raise AuthenticationError("jwks_fetch_failed")
            payload = response.read()
    except OSError as exc:  # pragma: no cover - network failure
        raise AuthenticationError("jwks_fetch_failed") from exc
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise AuthenticationError("invalid_jwks") from exc
    if not isinstance(document, Mapping):
        raise AuthenticationError("invalid_jwks")
    return document


class SamlAuthenticator:
    """Validate simplified SAML assertions using shared-secret signatures."""

    def __init__(self, provider: TenantSamlProvider) -> None:
        self.provider = provider
        try:
            self._public_key = _load_public_key_from_certificate(provider.certificate)
        except ValueError as exc:  # pragma: no cover - defensive guard
            raise AuthenticationError("invalid_certificate") from exc

    def validate(self, assertion: str, *, now: dt.datetime | None = None) -> Mapping[str, Any]:
        try:
            tree = ET.fromstring(assertion)
        except ET.ParseError as exc:  # pragma: no cover - defensive branch
            raise AuthenticationError("invalid_assertion") from exc
        ns = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
        subject = tree.findtext(".//saml2:Subject/saml2:NameID", namespaces=ns)
        if not subject:
            raise AuthenticationError("missing_subject")
        signature_value = tree.findtext(".//{*}SignatureValue")
        if not signature_value or not signature_value.strip():
            raise AuthenticationError("missing_signature")
        self._verify_signature(assertion)
        now = now or dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=dt.timezone.utc)
        skew = dt.timedelta(seconds=max(self.provider.clock_skew_seconds, 0))

        def parse_instant(value: str) -> dt.datetime:
            try:
                instant = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:  # pragma: no cover - defensive branch
                raise AuthenticationError("invalid_timestamp") from exc
            if instant.tzinfo is None:
                instant = instant.replace(tzinfo=dt.timezone.utc)
            return instant

        conditions = tree.find(".//saml2:Conditions", namespaces=ns)
        if conditions is not None:
            not_before_attr = conditions.get("NotBefore")
            if not_before_attr:
                not_before = parse_instant(not_before_attr)
                if now + skew < not_before:
                    raise AuthenticationError("assertion_not_yet_valid")
            not_on_or_after_attr = conditions.get("NotOnOrAfter")
            if not_on_or_after_attr:
                not_on_or_after = parse_instant(not_on_or_after_attr)
                if now - skew >= not_on_or_after:
                    raise AuthenticationError("assertion_expired")

        for data in tree.findall(".//saml2:SubjectConfirmation/saml2:SubjectConfirmationData", namespaces=ns):
            data_not_before = data.get("NotBefore")
            if data_not_before:
                not_before = parse_instant(data_not_before)
                if now + skew < not_before:
                    raise AuthenticationError("subject_confirmation_not_yet_valid")
            data_not_on_or_after = data.get("NotOnOrAfter")
            if data_not_on_or_after:
                not_on_or_after = parse_instant(data_not_on_or_after)
                if now - skew >= not_on_or_after:
                    raise AuthenticationError("subject_confirmation_expired")

        audiences = [
            node.text
            for node in tree.findall(".//saml2:AudienceRestriction/saml2:Audience", namespaces=ns)
            if node.text
        ]
        if self.provider.allowed_audiences and not set(audiences).intersection(self.provider.allowed_audiences):
            raise AuthenticationError("invalid_audience")
        attributes: MutableMapping[str, str] = {}
        for attribute in tree.findall(".//saml2:Attribute", namespaces=ns):
            name = attribute.get("Name")
            value = attribute.findtext(".//saml2:AttributeValue", namespaces=ns)
            if name and value:
                mapped = self.provider.attribute_mapping.get(name, name)
                attributes[mapped] = value
        return {"subject": subject, "attributes": attributes}

    def _verify_signature(self, assertion: str) -> None:
        try:
            document = LET.fromstring(assertion.encode())
        except (TypeError, ValueError, LET.XMLSyntaxError) as exc:
            raise AuthenticationError("invalid_assertion") from exc
        signature = document.find(".//{*}Signature")
        if signature is None:
            raise AuthenticationError("missing_signature")
        signed_info = signature.find("{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
        if signed_info is None:
            signed_info = signature.find("SignedInfo")
        if signed_info is None:
            raise AuthenticationError("invalid_signature")
        signature_value_text = signature.findtext("{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
        if not signature_value_text:
            signature_value_text = signature.findtext("SignatureValue")
        if not signature_value_text:
            raise AuthenticationError("invalid_signature")
        try:
            signature_bytes = _decode_signature(signature_value_text)
        except ValueError as exc:
            raise AuthenticationError("invalid_signature") from exc
        payload = _canonicalize_signed_info(signed_info)
        _verify_reference_digests(document, signed_info)
        algorithm = _resolve_signature_algorithm(signed_info)
        _verify_signature_payload(self._public_key, algorithm, signature_bytes, payload)


class FederatedIdentityDirectory:
    """In-memory lookup for federated identities."""

    def __init__(self, identities: Iterable[TenantFederatedUser] | None = None) -> None:
        self._index: dict[tuple[FederatedProvider, str, str], TenantFederatedUser] = {}
        for identity in identities or []:
            self.add(identity)

    def add(self, identity: TenantFederatedUser) -> None:
        key = (identity.provider_type, identity.provider_id, identity.subject)
        self._index[key] = identity

    def lookup(self, *, provider_type: FederatedProvider, provider_id: str, subject: str) -> TenantFederatedUser | None:
        return self._index.get((provider_type, provider_id, subject))


def _decode_secret(secret: str) -> bytes:
    padding = "=" * ((4 - len(secret) % 4) % 4)
    return base64.urlsafe_b64decode(secret + padding)


def _decode_signature(value: str) -> bytes:
    normalized = "".join(value.split())
    padding = "=" * ((4 - len(normalized) % 4) % 4)
    return base64.b64decode(normalized + padding, validate=True)


_XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
_XML_EXC_C14N_NS = "http://www.w3.org/2001/10/xml-exc-c14n#"
_XML_ENVELOPED_SIGNATURE_URI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"


class _SupportsDigest(Protocol):
    def digest(self) -> bytes:
        """Return the digest of the hashed payload."""


_DIGEST_ALGORITHMS: dict[str, Callable[[bytes], _SupportsDigest]] = {
    "http://www.w3.org/2001/04/xmlenc#sha256": hashlib.sha256,
    "http://www.w3.org/2001/04/xmlenc#sha512": hashlib.sha512,
    "http://www.w3.org/2000/09/xmldsig#sha1": hashlib.sha1,
}


@dataclass(frozen=True)
class _CanonicalizationConfig:
    exclusive: bool
    with_comments: bool


_CANONICALIZATION_ALGORITHMS: dict[str, _CanonicalizationConfig] = {
    "http://www.w3.org/2001/10/xml-exc-c14n#": _CanonicalizationConfig(exclusive=True, with_comments=False),
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": _CanonicalizationConfig(exclusive=True, with_comments=True),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": _CanonicalizationConfig(exclusive=False, with_comments=False),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": _CanonicalizationConfig(
        exclusive=False,
        with_comments=True,
    ),
    "http://www.w3.org/2006/12/xml-c14n11": _CanonicalizationConfig(exclusive=False, with_comments=False),
    "http://www.w3.org/2006/12/xml-c14n11#WithComments": _CanonicalizationConfig(exclusive=False, with_comments=True),
}


_SIGNATURE_VERIFIERS: dict[str, tuple[type[object], Callable[[object, bytes, bytes], None]]] = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": (
        rsa.RSAPublicKey,
        lambda key, signature, payload: key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256()),
    ),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": (
        ec.EllipticCurvePublicKey,
        lambda key, signature, payload: key.verify(signature, payload, ec.ECDSA(hashes.SHA256())),
    ),
    "http://www.w3.org/2001/04/xmldsig-more#ed25519": (
        ed25519.Ed25519PublicKey,
        lambda key, signature, payload: key.verify(signature, payload),
    ),
    "http://www.w3.org/2001/04/xmldsig-more#ed448": (
        ed448.Ed448PublicKey,
        lambda key, signature, payload: key.verify(signature, payload),
    ),
}


def _canonicalize_signed_info(signed_info: LET._Element) -> bytes:
    method = signed_info.find(f"{{{_XMLDSIG_NS}}}CanonicalizationMethod")
    if method is None:
        method = signed_info.find("CanonicalizationMethod")
    if method is None:
        raise AuthenticationError("invalid_signature")
    algorithm = method.get("Algorithm")
    if not algorithm:
        raise AuthenticationError("invalid_signature")
    prefixes = _inclusive_namespace_prefixes(method)
    return _canonicalize_element(signed_info, algorithm, prefixes)


def _verify_reference_digests(document: LET._Element, signed_info: LET._Element) -> None:
    references = list(signed_info.findall(f"{{{_XMLDSIG_NS}}}Reference")) or list(signed_info.findall("Reference"))
    if not references:
        raise AuthenticationError("invalid_signature")
    for reference in references:
        uri = reference.get("URI") or ""
        target = _resolve_reference(document, uri)
        transformed = _apply_reference_transforms(target, reference)
        digest_method = reference.find(f"{{{_XMLDSIG_NS}}}DigestMethod")
        if digest_method is None:
            digest_method = reference.find("DigestMethod")
        digest_value = reference.findtext(f"{{{_XMLDSIG_NS}}}DigestValue") or reference.findtext("DigestValue")
        if digest_method is None or not digest_value:
            raise AuthenticationError("invalid_signature")
        algorithm = digest_method.get("Algorithm")
        if not algorithm:
            raise AuthenticationError("invalid_signature")
        expected = _compute_digest(transformed, algorithm)
        if not hmac.compare_digest(expected, "".join(digest_value.split())):
            raise AuthenticationError("invalid_signature")


def _resolve_signature_algorithm(signed_info: LET._Element) -> str:
    signature_method = signed_info.find(f"{{{_XMLDSIG_NS}}}SignatureMethod")
    if signature_method is None:
        signature_method = signed_info.find("SignatureMethod")
    if signature_method is None:
        raise AuthenticationError("invalid_signature")
    algorithm = signature_method.get("Algorithm")
    if not algorithm:
        raise AuthenticationError("invalid_signature")
    return algorithm


def _verify_signature_payload(public_key: object, algorithm: str, signature: bytes, payload: bytes) -> None:
    verifier_entry = _SIGNATURE_VERIFIERS.get(algorithm)
    if verifier_entry is None:
        raise AuthenticationError("invalid_signature")
    expected_type, verifier = verifier_entry
    if not isinstance(public_key, expected_type):
        raise AuthenticationError("invalid_signature")
    try:
        verifier(public_key, signature, payload)
    except InvalidSignature as exc:
        raise AuthenticationError("invalid_signature") from exc


def _apply_reference_transforms(target: LET._Element, reference: LET._Element) -> bytes:
    transforms_parent = reference.find(f"{{{_XMLDSIG_NS}}}Transforms")
    if transforms_parent is None:
        transforms_parent = reference.find("Transforms")
    data: bytes | LET._Element = _clone_element(target)
    if transforms_parent is not None:
        transforms = list(transforms_parent.findall(f"{{{_XMLDSIG_NS}}}Transform")) or list(
            transforms_parent.findall("Transform")
        )
        for transform in transforms:
            algorithm = transform.get("Algorithm") or ""
            if algorithm == _XML_ENVELOPED_SIGNATURE_URI:
                if isinstance(data, bytes):
                    data = LET.fromstring(data)
                _strip_signatures(data)
            elif algorithm in _CANONICALIZATION_ALGORITHMS:
                config = _CANONICALIZATION_ALGORITHMS[algorithm]
                element = LET.fromstring(data) if isinstance(data, bytes) else data
                prefixes = _inclusive_namespace_prefixes(transform)
                data = LET.tostring(
                    element,
                    method="c14n",
                    exclusive=config.exclusive,
                    with_comments=config.with_comments,
                    inclusive_ns_prefixes=list(prefixes) if prefixes else None,
                )
            else:  # pragma: no cover - unsupported transform guard
                raise AuthenticationError("invalid_signature")
    if isinstance(data, LET._Element):
        data = LET.tostring(data, method="c14n", exclusive=False, with_comments=False)
    return data


def _canonicalize_element(
    element: LET._Element,
    algorithm: str,
    prefixes: tuple[str, ...] = (),
) -> bytes:
    config = _CANONICALIZATION_ALGORITHMS.get(algorithm)
    if config is None:
        raise AuthenticationError("invalid_signature")
    return LET.tostring(
        element,
        method="c14n",
        exclusive=config.exclusive,
        with_comments=config.with_comments,
        inclusive_ns_prefixes=list(prefixes) if prefixes else None,
    )


def _inclusive_namespace_prefixes(element: LET._Element) -> tuple[str, ...]:
    node = element.find(f"{{{_XML_EXC_C14N_NS}}}InclusiveNamespaces")
    if node is None:
        node = element.find("InclusiveNamespaces")
    if node is None:
        return ()
    prefix_text = node.get("PrefixList") or ""
    prefix_list = prefix_text.split()
    return tuple(prefix_list)


def _resolve_reference(document: LET._Element, uri: str) -> LET._Element:
    if not uri:
        return _clone_element(document)
    if uri.startswith("#"):
        reference_id = uri[1:]
        matches = document.xpath(
            "//*[@ID=$id or @Id=$id or @id=$id]",
            id=reference_id,
        )
        if not matches:
            raise AuthenticationError("invalid_signature")
        target = matches[0]
        return _clone_element(target)
    raise AuthenticationError("invalid_signature")


def _clone_element(element: LET._Element) -> LET._Element:
    return LET.fromstring(LET.tostring(element))


def _strip_signatures(element: LET._Element) -> None:
    for signature in list(element.xpath(".//*[local-name()='Signature']")):
        parent = signature.getparent()
        if parent is not None:
            parent.remove(signature)


def _compute_digest(data: bytes, algorithm: str) -> str:
    factory = _DIGEST_ALGORITHMS.get(algorithm)
    if factory is None:
        raise AuthenticationError("invalid_signature")
    digest = factory(data).digest()
    return base64.b64encode(digest).decode()


def _load_public_key_from_certificate(certificate: str):
    material = certificate.strip()
    if not material:
        raise ValueError("empty certificate")
    errors: list[Exception] = []
    try:
        return x509.load_pem_x509_certificate(material.encode()).public_key()
    except ValueError as exc:
        errors.append(exc)
    try:
        der_cert = base64.b64decode(material, validate=True)
        return x509.load_der_x509_certificate(der_cert).public_key()
    except (ValueError, binascii.Error) as exc:
        errors.append(exc)
    for loader in (load_pem_public_key, load_der_public_key):
        try:
            return loader(material.encode())
        except ValueError as exc:
            errors.append(exc)
    try:
        der_key = base64.b64decode(material, validate=True)
        return load_der_public_key(der_key)
    except (ValueError, binascii.Error) as exc:
        errors.append(exc)
    if errors:
        raise ValueError("unsupported_certificate_format") from errors[-1]
    raise ValueError("unsupported_certificate_format")  # pragma: no cover - defensive fallback


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _derive_session_token_hash(token: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", token.encode(), salt, _SESSION_TOKEN_PBKDF2_ITERATIONS)
    return derived.hex()


def _derive_salt(secret_key: str, salt: str) -> bytes:
    return sha256(f"{secret_key}:{salt}".encode()).digest()


def _argon2_hash(
    password: str,
    secret_key: str,
    salt: str,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
) -> str:
    derived = _derive_salt(secret_key, salt)
    hashed = argon2_hash_secret(
        password.encode(),
        derived,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    )
    if isinstance(hashed, bytes):
        return hashed.decode()
    return hashed
