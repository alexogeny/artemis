"""Authentication primitives for Artemis."""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hmac
import json
import secrets
from hashlib import sha256
from typing import Any, Iterable, Mapping, MutableMapping
from xml.etree import ElementTree as ET

from msgspec import structs

try:  # pragma: no cover - optional dependency
    from argonautica import Hasher as ArgonauticaHasher  # type: ignore[import-not-found]
    from argonautica import Verifier as ArgonauticaVerifier  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency or build failure
    ArgonauticaHasher = None
    ArgonauticaVerifier = None
from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret as argon2_hash_secret

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

__all__ = [
    "AuthenticationError",
    "AuthenticationService",
    "FederatedIdentityDirectory",
    "MfaManager",
    "OidcAuthenticator",
    "PasskeyManager",
    "PasswordHasher",
    "SamlAuthenticator",
    "compose_admin_secret",
    "compose_tenant_secret",
]


class AuthenticationError(RuntimeError):
    """Raised when authentication fails."""


def compose_admin_secret(app_secret: AppSecret, user: AdminUser) -> str:
    return "::".join(["admin", app_secret.secret_value, user.password_secret])


def compose_tenant_secret(app_secret: AppSecret, tenant_secret: TenantSecret, user: TenantUser) -> str:
    return "::".join(["tenant", app_secret.secret_value, tenant_secret.secret, user.password_secret])


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
    """High-level authentication helpers for Artemis applications."""

    def __init__(self, password_hasher: PasswordHasher) -> None:
        self.password_hasher = password_hasher

    async def hash_admin_password(self, *, app_secret: AppSecret, user_secret: str, password: str) -> tuple[str, str]:
        salt = secrets.token_hex(16)
        secret_key = "::".join(["admin", app_secret.secret_value, user_secret])
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
        secret_key = "::".join(["tenant", app_secret.secret_value, tenant_secret.secret, user_secret])
        hashed = await self.password_hasher.hash(password, secret_key=secret_key, salt=salt)
        return hashed, salt

    async def verify_admin_password(self, *, user: AdminUser, app_secret: AppSecret, password: str) -> bool:
        secret = compose_admin_secret(app_secret, user)
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
        secret = compose_tenant_secret(app_secret, tenant_secret, user)
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
    ) -> SessionToken:
        if not await self.verify_tenant_password(
            user=user, app_secret=app_secret, tenant_secret=tenant_secret, password=password
        ):
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
                now=now,
            )
            level = SessionLevel.MFA

        return self._issue_session_token(user_id=user.id, level=level)

    def authenticate_with_passkey(
        self,
        *,
        passkey: Passkey,
        challenge: str,
        signature: str,
        allow_user: TenantUser | AdminUser | None = None,
    ) -> SessionToken:
        manager = PasskeyManager()
        if not manager.verify(passkey=passkey, challenge=challenge, signature=signature):
            raise AuthenticationError("invalid_passkey")
        if allow_user is not None and getattr(allow_user, "id", None) != passkey.user_id:
            raise AuthenticationError("passkey_user_mismatch")
        return self._issue_session_token(user_id=passkey.user_id, level=SessionLevel.PASSKEY)

    def _issue_session_token(self, *, user_id: str, level: SessionLevel) -> SessionToken:
        now = dt.datetime.now(dt.UTC)
        return SessionToken(
            id=generate_id57(),
            user_id=user_id,
            token=generate_id57(),
            created_at=now,
            expires_at=now + dt.timedelta(hours=1),
            level=level,
        )


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


class OidcAuthenticator:
    """Validate HMAC signed OIDC tokens."""

    def __init__(self, provider: TenantOidcProvider) -> None:
        self.provider = provider

    def validate(self, token: str, *, expected_nonce: str | None = None) -> Mapping[str, Any]:
        header, payload, signature = token.split(".")
        signing_input = f"{header}.{payload}".encode()
        expected_signature = _b64url_encode(
            hmac.new(self.provider.client_secret.encode(), signing_input, sha256).digest()
        )
        if not hmac.compare_digest(signature, expected_signature):
            raise AuthenticationError("invalid_token_signature")
        claims = json.loads(_b64url_decode(payload))
        if claims.get("iss") != self.provider.issuer:
            raise AuthenticationError("invalid_issuer")
        audience = claims.get("aud")
        if self.provider.allowed_audiences and audience not in self.provider.allowed_audiences:
            raise AuthenticationError("invalid_audience")
        if expected_nonce is not None and claims.get("nonce") != expected_nonce:
            raise AuthenticationError("invalid_nonce")
        groups = claims.get("groups", [])
        if self.provider.allowed_groups and not set(groups).intersection(self.provider.allowed_groups):
            raise AuthenticationError("unauthorized_group")
        return claims


class SamlAuthenticator:
    """Validate simplified SAML assertions using shared-secret signatures."""

    def __init__(self, provider: TenantSamlProvider) -> None:
        self.provider = provider

    def validate(self, assertion: str) -> Mapping[str, Any]:
        try:
            tree = ET.fromstring(assertion)
        except ET.ParseError as exc:  # pragma: no cover - defensive branch
            raise AuthenticationError("invalid_assertion") from exc
        ns = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
        subject = tree.findtext(".//saml2:Subject/saml2:NameID", namespaces=ns)
        if not subject:
            raise AuthenticationError("missing_subject")
        signature = tree.findtext(".//saml2:SignatureValue", namespaces=ns) or tree.findtext(".//SignatureValue")
        if not signature:
            raise AuthenticationError("missing_signature")
        expected = _b64url_encode(hmac.new(self.provider.certificate.encode(), subject.encode(), sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise AuthenticationError("invalid_signature")
        attributes: MutableMapping[str, str] = {}
        for attribute in tree.findall(".//saml2:Attribute", namespaces=ns):
            name = attribute.get("Name")
            value = attribute.findtext(".//saml2:AttributeValue", namespaces=ns)
            if name and value:
                mapped = self.provider.attribute_mapping.get(name, name)
                attributes[mapped] = value
        return {"subject": subject, "attributes": attributes}


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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


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
