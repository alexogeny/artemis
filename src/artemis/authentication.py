"""Authentication primitives for Artemis."""

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
from hashlib import sha256
from typing import Any
from xml.etree import ElementTree as ET

from msgspec import Struct, structs

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
    "OidcValidationDefaults",
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
    ) -> None:
        self.provider = provider
        self.defaults = defaults or OidcValidationDefaults()
        self._jwks_fetcher = jwks_fetcher or _default_jwks_fetcher
        self._jwks_cache: list[Mapping[str, Any]] | None = None

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
        secret = self.provider.client_secret
        if not secret:
            return None
        return {
            "kty": "oct",
            "k": _b64url_encode(secret.encode()),
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

    def validate(self, assertion: str, *, now: dt.datetime | None = None) -> Mapping[str, Any]:
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

        for data in tree.findall(
            ".//saml2:SubjectConfirmation/saml2:SubjectConfirmationData", namespaces=ns
        ):
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
