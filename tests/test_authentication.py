import base64
import datetime as dt
import hashlib
import hmac
import json
import xml.etree.ElementTree as ET
from typing import Callable, Iterable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import NameOID
from msgspec import structs

import lxml.etree as LET
import mere.authentication as authentication_module
from mere.authentication import (
    AuthenticationError,
    AuthenticationRateLimiter,
    AuthenticationService,
    FederatedIdentityDirectory,
    MfaManager,
    OidcAuthenticator,
    OidcValidationDefaults,
    PasskeyManager,
    PasswordHasher,
    SamlAuthenticator,
    compose_admin_secret,
    compose_tenant_secret,
)
from mere.database import SecretRef
from mere.id57 import generate_id57
from mere.models import (
    AdminUser,
    AppSecret,
    Customer,
    FederatedProvider,
    MfaPurpose,
    SessionLevel,
    TenantFederatedUser,
    TenantOidcProvider,
    TenantSamlProvider,
    TenantSecret,
    TenantUser,
)
from tests.support import StaticSecretResolver

_SigningKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _saml_instant(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _epoch(value: dt.datetime) -> int:
    return int(value.astimezone(dt.timezone.utc).timestamp())


def _make_app_secret(now: dt.datetime, *, salt: str = "salt") -> tuple[AppSecret, SecretRef]:
    ref = SecretRef(provider="vault", name=f"app::{generate_id57()}")
    secret = AppSecret(
        id=generate_id57(),
        secret=ref,
        salt=salt,
        created_at=now,
        updated_at=now,
    )
    return secret, ref


def _make_tenant_secret(now: dt.datetime, *, purpose: str = "password") -> tuple[TenantSecret, SecretRef]:
    ref = SecretRef(provider="vault", name=f"tenant::{generate_id57()}")
    secret = TenantSecret(
        id=generate_id57(),
        secret=ref,
        purpose=purpose,
        created_at=now,
        updated_at=now,
    )
    return secret, ref


def _resolver_for(pairs: Iterable[tuple[SecretRef, str]]) -> StaticSecretResolver:
    mapping = {(ref.provider, ref.name, ref.version): value for ref, value in pairs}
    return StaticSecretResolver(mapping)


def _generate_saml_signing_material(now: dt.datetime) -> tuple[ed25519.Ed25519PrivateKey, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test IdP")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(private_key, algorithm=None)
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return private_key, certificate_pem


def _generate_rsa_signing_material(now: dt.datetime) -> tuple[rsa.RSAPrivateKey, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSA IdP")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate.public_bytes(serialization.Encoding.PEM).decode()


def _generate_ecdsa_signing_material(now: dt.datetime) -> tuple[ec.EllipticCurvePrivateKey, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC IdP")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate.public_bytes(serialization.Encoding.PEM).decode()


def _make_saml_provider(
    now: dt.datetime,
    *,
    certificate: str,
    **overrides: object,
) -> TenantSamlProvider:
    return TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate=certificate,
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        **overrides,
    )


_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
_ENVELOPED_SIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
_DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
_ED25519 = "http://www.w3.org/2001/04/xmldsig-more#ed25519"
_ED448 = "http://www.w3.org/2001/04/xmldsig-more#ed448"


def _render_signed_assertion(
    signing_key: object,
    *,
    body: str,
    certificate: str | None = None,
    assertion_id: str | None = None,
    issue_instant: str | None = None,
    **context: object,
) -> str:
    assertion_id = assertion_id or f"_{generate_id57()}"
    instant = issue_instant or _saml_instant(dt.datetime.now(dt.timezone.utc))
    assertion = _wrap_assertion(assertion_id=assertion_id, issue_instant=instant, body=body.format(**context))
    return _sign_assertion(assertion, signing_key, certificate=certificate, reference_uri=assertion_id)


def _wrap_assertion(*, assertion_id: str, issue_instant: str, body: str) -> LET._Element:
    template = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion' Version='2.0' "
        f"ID='{assertion_id}' IssueInstant='{issue_instant}'>"
        f"{body}"
        "</Assertion>"
    )
    return LET.fromstring(template)


def _sign_assertion(
    assertion: LET._Element,
    key: object,
    *,
    certificate: str | None,
    reference_uri: str,
) -> str:
    digest_target = LET.fromstring(LET.tostring(assertion))
    _strip_signature_nodes(digest_target)
    digest_bytes = LET.tostring(digest_target, method="c14n", exclusive=True, with_comments=False)
    digest_value = base64.b64encode(hashlib.sha256(digest_bytes).digest()).decode()

    signature = LET.Element(f"{{{_DS_NS}}}Signature", nsmap={"ds": _DS_NS})
    signed_info = LET.SubElement(signature, f"{{{_DS_NS}}}SignedInfo")
    LET.SubElement(signed_info, f"{{{_DS_NS}}}CanonicalizationMethod", Algorithm=_EXC_C14N)
    signature_method = LET.SubElement(signed_info, f"{{{_DS_NS}}}SignatureMethod")
    signature_method.set("Algorithm", _signature_algorithm_uri_for_key(key))
    reference = LET.SubElement(signed_info, f"{{{_DS_NS}}}Reference")
    reference.set("URI", f"#{reference_uri}")
    transforms = LET.SubElement(reference, f"{{{_DS_NS}}}Transforms")
    LET.SubElement(transforms, f"{{{_DS_NS}}}Transform", Algorithm=_ENVELOPED_SIG)
    LET.SubElement(transforms, f"{{{_DS_NS}}}Transform", Algorithm=_EXC_C14N)
    LET.SubElement(reference, f"{{{_DS_NS}}}DigestMethod", Algorithm=_DIGEST_SHA256)
    digest_value_el = LET.SubElement(reference, f"{{{_DS_NS}}}DigestValue")
    digest_value_el.text = digest_value

    signed_info_bytes = LET.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
    signature_bytes = _sign_payload(key, signed_info_bytes)
    signature_value = LET.SubElement(signature, f"{{{_DS_NS}}}SignatureValue")
    signature_value.text = base64.b64encode(signature_bytes).decode()

    if certificate:
        key_info = LET.SubElement(signature, f"{{{_DS_NS}}}KeyInfo")
        x509_data = LET.SubElement(key_info, f"{{{_DS_NS}}}X509Data")
        cert_el = LET.SubElement(x509_data, f"{{{_DS_NS}}}X509Certificate")
        cert_el.text = _normalize_pem_certificate(certificate)

    assertion.insert(0, signature)
    return LET.tostring(assertion, encoding="unicode")


def _mutate_assertion_xml(assertion: str, mutator: Callable[[LET._Element], None]) -> str:
    document = LET.fromstring(assertion.encode())
    mutator(document)
    return LET.tostring(document, encoding="unicode")


def _sign_payload(key: _SigningKey, payload: bytes) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(payload, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return key.sign(payload)
    raise AssertionError(f"Unsupported signing key type: {type(key)!r}")


def _signature_algorithm_uri_for_key(key: _SigningKey) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return _RSA_SHA256
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return _ECDSA_SHA256
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return _ED25519
    if isinstance(key, ed448.Ed448PrivateKey):
        return _ED448
    raise AssertionError(f"Unsupported signing key type: {type(key)!r}")


def _strip_signature_nodes(element: LET._Element) -> None:
    for node in element.xpath(".//*[local-name()='Signature']"):
        parent = node.getparent()
        if parent is not None:
            parent.remove(node)


def _normalize_pem_certificate(material: str) -> str:
    lines = [line.strip() for line in material.splitlines() if "BEGIN" not in line and "END" not in line]
    return "".join(lines)


def test_customer_secret_resolves_with_secret_ref() -> None:
    secret_ref = SecretRef(provider="vault", name=f"customer::{generate_id57()}")
    customer = Customer(
        tenant="acme",
        schema_name="tenant_acme",
        billing_id="billing",
        status="active",
        tenant_secret=secret_ref,
    )
    resolver = _resolver_for([(secret_ref, "tenant-secret")])
    assert customer.resolve_tenant_secret(resolver) == "tenant-secret"


def test_tenant_oidc_provider_requires_client_secret_ref() -> None:
    provider = TenantOidcProvider(
        issuer="https://issuer.example.com",
        client_id="client",
        jwks_uri="https://issuer.example.com/jwks",
        authorization_endpoint="https://issuer.example.com/auth",
        token_endpoint="https://issuer.example.com/token",
        userinfo_endpoint="https://issuer.example.com/userinfo",
    )
    resolver = _resolver_for([])
    with pytest.raises(LookupError):
        provider.resolve_client_secret(resolver)


def _build_oidc_authenticator(
    *,
    now: dt.datetime,
    defaults: OidcValidationDefaults | None = None,
) -> tuple[OidcAuthenticator, TenantOidcProvider, bytes, StaticSecretResolver]:
    secret_value = "oidc-secret"
    secret_ref = SecretRef(provider="vault", name=f"oidc::{generate_id57()}")
    provider = TenantOidcProvider(
        id=generate_id57(),
        issuer="https://issuer.example.com",
        client_id="client",
        client_secret=secret_ref,
        jwks_uri="https://issuer.example.com/jwks",
        authorization_endpoint="https://issuer.example.com/auth",
        token_endpoint="https://issuer.example.com/token",
        userinfo_endpoint="https://issuer.example.com/userinfo",
        created_at=now,
        updated_at=now,
        allowed_audiences=["client"],
        allowed_groups=["admins"],
    )
    resolver = _resolver_for([(secret_ref, secret_value)])
    secret = secret_value.encode()
    jwks = {
        "keys": [
            {
                "kty": "oct",
                "kid": "primary",
                "k": _b64url(secret),
                "alg": "HS256",
                "use": "sig",
            }
        ]
    }
    authenticator = OidcAuthenticator(
        provider,
        defaults=defaults
        or OidcValidationDefaults(
            clock_skew_seconds=0,
            default_token_ttl_seconds=600,
            max_token_age_seconds=600,
        ),
        jwks_fetcher=lambda _: jwks,
        secret_resolver=resolver,
    )
    return authenticator, provider, secret, resolver


def _issue_oidc_token(
    claims: dict[str, object],
    secret: bytes,
    *,
    kid: str | None = "primary",
    alg: str = "HS256",
    signature_bytes: bytes | None = None,
) -> str:
    header_fields: dict[str, object] = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header_fields["kid"] = kid
    header = _b64url(json.dumps(header_fields).encode())
    payload = _b64url(json.dumps(claims).encode())
    if signature_bytes is None:
        signature_bytes = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    signature = _b64url(signature_bytes)
    return f"{header}.{payload}.{signature}"


@pytest.mark.asyncio
async def test_password_hashing_and_mfa_authentication() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    app_secret, app_ref = _make_app_secret(now)
    tenant_secret, tenant_ref = _make_tenant_secret(now)
    resolver = _resolver_for([(app_ref, "app"), (tenant_ref, "tenant")])
    service = AuthenticationService(hasher, secret_resolver=resolver)
    user_secret = "user-secret"
    hashed, salt = await service.hash_tenant_password(
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        user_secret=user_secret,
        password="correct horse battery",
    )
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        username="user",
        hashed_password=hashed,
        password_salt=salt,
        password_secret=user_secret,
        created_at=now,
        updated_at=now,
        mfa_enforced=True,
    )
    manager = MfaManager()
    issued = manager.issue(user_id=user.id, purpose=MfaPurpose.SIGN_IN, now=now)
    session = await service.authenticate_tenant_password(
        user=user,
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        password="correct horse battery",
        mfa_codes=[issued.record],
        submitted_code=issued.code,
        now=now,
    )
    assert session.level is SessionLevel.MFA
    with pytest.raises(AuthenticationError):
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="correct horse battery",
            mfa_codes=[issued.record],
            submitted_code="000000",
            now=now,
        )


def test_secret_composition_differs_between_scopes() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    app_secret, app_ref = _make_app_secret(now)
    admin = AdminUser(
        id=generate_id57(),
        email="admin@example.com",
        hashed_password="hash",
        created_at=now,
        updated_at=now,
        password_secret="admin",
    )
    tenant_secret, tenant_ref = _make_tenant_secret(now)
    resolver = _resolver_for([(app_ref, "app"), (tenant_ref, "tenant")])
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        hashed_password="hash",
        created_at=now,
        updated_at=now,
        password_secret="user",
    )
    admin_secret = compose_admin_secret(app_secret, admin, resolver=resolver)
    tenant_secret_value = compose_tenant_secret(app_secret, tenant_secret, user, resolver=resolver)
    assert admin_secret != tenant_secret_value


def test_passkey_manager_round_trip() -> None:
    manager = PasskeyManager()
    passkey = manager.register(
        user_id=generate_id57(),
        credential_id="cred",
        secret=b"super-secret",
        user_handle="handle",
        label="Laptop",
    )
    challenge = manager.challenge()
    signature = manager.sign(passkey=passkey, challenge=challenge)
    assert manager.verify(passkey=passkey, challenge=challenge, signature=signature)
    assert not manager.verify(passkey=passkey, challenge=challenge, signature="bad")


def test_oidc_authenticator_validates_token() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, provider, secret, _resolver = _build_oidc_authenticator(now=now)
    issued_at = now - dt.timedelta(seconds=30)
    expires_at = now + dt.timedelta(minutes=5)
    claims = {
        "iss": provider.issuer,
        "aud": [provider.client_id, "unused"],
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(issued_at),
        "nbf": _epoch(issued_at),
        "exp": _epoch(expires_at),
    }
    token = _issue_oidc_token(claims, secret)
    validated = authenticator.validate(token, expected_nonce="nonce", now=now)
    assert validated["aud"] == [provider.client_id, "unused"]
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, expected_nonce="other", now=now)
    assert str(exc.value) == "invalid_nonce"


def test_oidc_authenticator_hmac_fallback_uses_client_secret() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    base_authenticator, provider, secret, resolver = _build_oidc_authenticator(now=now)
    authenticator = OidcAuthenticator(
        provider,
        defaults=base_authenticator.defaults,
        jwks_fetcher=lambda _: {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "rsa",
                    "n": _b64url(b"\x01" + b"\x00" * 63),
                    "e": _b64url((65537).to_bytes(3, "big")),
                }
            ]
        },
        secret_resolver=resolver,
    )
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    token = _issue_oidc_token(claims, secret, kid=None)
    resolved = authenticator.validate(token, now=now)
    assert resolved["iss"] == provider.issuer


def test_oidc_authenticator_hmac_fallback_requires_client_secret() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    base_authenticator, provider, secret, resolver = _build_oidc_authenticator(now=now)
    provider_without_secret = TenantOidcProvider(
        id=provider.id,
        issuer=provider.issuer,
        client_id=provider.client_id,
        client_secret=None,
        jwks_uri=provider.jwks_uri,
        authorization_endpoint=provider.authorization_endpoint,
        token_endpoint=provider.token_endpoint,
        userinfo_endpoint=provider.userinfo_endpoint,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
        allowed_audiences=list(provider.allowed_audiences),
        allowed_groups=list(provider.allowed_groups),
        enabled=provider.enabled,
    )
    authenticator = OidcAuthenticator(
        provider_without_secret,
        defaults=base_authenticator.defaults,
        jwks_fetcher=lambda _: {},
        secret_resolver=resolver,
    )
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    token = _issue_oidc_token(claims, secret, kid=None)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unknown_jwk"


def test_oidc_authenticator_requires_secret_resolver_for_client_secret() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    base_authenticator, provider, secret, _ = _build_oidc_authenticator(now=now)
    authenticator = OidcAuthenticator(
        provider,
        defaults=base_authenticator.defaults,
        jwks_fetcher=lambda _: {},
    )
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    token = _issue_oidc_token(claims, secret, kid=None)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "client_secret_unavailable"


def test_oidc_authenticator_rejects_blank_client_secret() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    base_authenticator, provider, secret, _ = _build_oidc_authenticator(now=now)
    blank_ref = SecretRef(provider="vault", name=f"oidc::{generate_id57()}")
    provider_with_blank = TenantOidcProvider(
        id=provider.id,
        issuer=provider.issuer,
        client_id=provider.client_id,
        client_secret=blank_ref,
        jwks_uri=provider.jwks_uri,
        authorization_endpoint=provider.authorization_endpoint,
        token_endpoint=provider.token_endpoint,
        userinfo_endpoint=provider.userinfo_endpoint,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
        allowed_audiences=list(provider.allowed_audiences),
        allowed_groups=list(provider.allowed_groups),
        enabled=provider.enabled,
    )
    resolver = _resolver_for([(blank_ref, "   ")])
    authenticator = OidcAuthenticator(
        provider_with_blank,
        defaults=base_authenticator.defaults,
        jwks_fetcher=lambda _: {},
        secret_resolver=resolver,
    )
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    token = _issue_oidc_token(claims, secret, kid=None)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "client_secret_unavailable"


def test_oidc_authenticator_reports_secret_resolution_failure() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    base_authenticator, provider, secret, _ = _build_oidc_authenticator(now=now)

    class FailingResolver:
        def resolve(self, secret: SecretRef) -> str:
            raise RuntimeError("boom")

    authenticator = OidcAuthenticator(
        provider,
        defaults=base_authenticator.defaults,
        jwks_fetcher=lambda _: {},
        secret_resolver=FailingResolver(),
    )
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    token = _issue_oidc_token(claims, secret, kid=None)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "client_secret_unavailable"


def test_oidc_authenticator_client_secret_key_rejects_non_hmac() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, _, _, _ = _build_oidc_authenticator(now=now)
    assert authenticator._client_secret_hmac_key("RS256") is None


def test_saml_authenticator_validates_and_maps_attributes() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(
        now,
        certificate=certificate,
        attribute_mapping={"email": "mail"},
    )
    subject = "user@example.com"
    assertion = _render_signed_assertion(
        signing_key,
        body=(
            "<Subject><NameID>{subject}</NameID></Subject>"
            "<Attribute Name='email'><AttributeValue>user@example.com</AttributeValue></Attribute>"
            "<Attribute><AttributeValue>ignored</AttributeValue></Attribute>"
        ),
        subject=subject,
    )
    authenticator = SamlAuthenticator(provider)
    result = authenticator.validate(assertion)
    assert result["subject"] == subject
    assert result["attributes"]["mail"] == subject
    assert "ignored" not in result["attributes"].values()
    signature_value = ET.fromstring(assertion).findtext(".//{*}SignatureValue") or ""
    tampered = assertion.replace(signature_value, "invalid")
    with pytest.raises(AuthenticationError):
        authenticator.validate(tampered)


def test_federated_identity_directory() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    identity = TenantFederatedUser(
        id=generate_id57(),
        provider_id="google",
        provider_type=FederatedProvider.OIDC,
        subject="user@example.com",
        user_id=generate_id57(),
        created_at=now,
        updated_at=now,
    )
    directory = FederatedIdentityDirectory([identity])
    assert (
        directory.lookup(provider_type=FederatedProvider.OIDC, provider_id="google", subject="user@example.com")
        is identity
    )
    assert (
        directory.lookup(provider_type=FederatedProvider.SAML, provider_id="google", subject="user@example.com") is None
    )


@pytest.mark.asyncio
async def test_hash_and_verify_admin_password() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    app_secret, app_ref = _make_app_secret(now)
    resolver = _resolver_for([(app_ref, "secret")])
    service = AuthenticationService(hasher, secret_resolver=resolver)
    hashed, salt = await service.hash_admin_password(app_secret=app_secret, user_secret="user", password="s3cret")
    admin = AdminUser(
        id=generate_id57(),
        email="admin@example.com",
        hashed_password=hashed,
        password_salt=salt,
        password_secret="user",
        created_at=now,
        updated_at=now,
    )
    assert await service.verify_admin_password(user=admin, app_secret=app_secret, password="s3cret")
    assert not await service.verify_admin_password(user=admin, app_secret=app_secret, password="wrong")


@pytest.mark.asyncio
async def test_authenticate_tenant_password_invalid_credentials() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    app_secret, app_ref = _make_app_secret(now)
    tenant_secret, tenant_ref = _make_tenant_secret(now)
    resolver = _resolver_for([(app_ref, "app"), (tenant_ref, "tenant")])
    service = AuthenticationService(hasher, secret_resolver=resolver)
    hashed, salt = await service.hash_tenant_password(
        app_secret=app_secret, tenant_secret=tenant_secret, user_secret="user", password="p@ss"
    )
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        hashed_password=hashed,
        password_salt=salt,
        password_secret="user",
        created_at=now,
        updated_at=now,
    )
    with pytest.raises(AuthenticationError):
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="wrong",
        )


@pytest.mark.asyncio
async def test_authenticate_tenant_password_requires_mfa_code() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    app_secret, app_ref = _make_app_secret(now)
    tenant_secret, tenant_ref = _make_tenant_secret(now)
    resolver = _resolver_for([(app_ref, "app"), (tenant_ref, "tenant")])
    service = AuthenticationService(hasher, secret_resolver=resolver)
    hashed, salt = await service.hash_tenant_password(
        app_secret=app_secret, tenant_secret=tenant_secret, user_secret="user", password="p@ss"
    )
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        hashed_password=hashed,
        password_salt=salt,
        password_secret="user",
        created_at=now,
        updated_at=now,
        mfa_enforced=True,
    )
    with pytest.raises(AuthenticationError) as exc:
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="p@ss",
            mfa_codes=[],
        )
    assert str(exc.value) == "mfa_required"


@pytest.mark.asyncio
async def test_authenticate_tenant_password_without_mfa_sets_password_level() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    app_secret, app_ref = _make_app_secret(now)
    tenant_secret, tenant_ref = _make_tenant_secret(now)
    resolver = _resolver_for([(app_ref, "app"), (tenant_ref, "tenant")])
    service = AuthenticationService(hasher, secret_resolver=resolver)
    hashed, salt = await service.hash_tenant_password(
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        user_secret="user",
        password="p@ss",
    )
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        username="user",
        hashed_password=hashed,
        password_salt=salt,
        password_secret="user",
        created_at=now,
        updated_at=now,
    )
    session = await service.authenticate_tenant_password(
        user=user,
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        password="p@ss",
    )
    assert session.level is SessionLevel.PASSWORD_ONLY


@pytest.mark.asyncio
async def test_authenticate_tenant_password_uses_matching_mfa_code() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    app_secret, app_ref = _make_app_secret(now)
    tenant_secret, tenant_ref = _make_tenant_secret(now)
    resolver = _resolver_for([(app_ref, "app"), (tenant_ref, "tenant")])
    service = AuthenticationService(hasher, secret_resolver=resolver)
    hashed, salt = await service.hash_tenant_password(
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        user_secret="user",
        password="p@ss",
    )
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        username="user",
        hashed_password=hashed,
        password_salt=salt,
        password_secret="user",
        created_at=now,
        updated_at=now,
        mfa_enforced=True,
    )
    manager = MfaManager()
    issued = manager.issue(user_id=user.id, purpose=MfaPurpose.SIGN_IN, now=now)
    valid = issued.record
    mismatched_user = structs.replace(valid, user_id="other")
    mismatched_purpose = structs.replace(valid, purpose=MfaPurpose.RECOVERY)
    session = await service.authenticate_tenant_password(
        user=user,
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        password="p@ss",
        mfa_codes=[mismatched_user, mismatched_purpose, valid],
        submitted_code=issued.code,
        now=now,
    )
    assert session.level is SessionLevel.MFA


@pytest.mark.asyncio
async def test_authentication_rate_limiter_enforces_cooldown() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    app_secret, app_ref = _make_app_secret(now)
    tenant_secret, tenant_ref = _make_tenant_secret(now)
    resolver = _resolver_for([(app_ref, "app"), (tenant_ref, "tenant")])
    rate_limiter = AuthenticationRateLimiter(
        max_attempts=3,
        base_cooldown=dt.timedelta(seconds=5),
        max_cooldown=dt.timedelta(seconds=5),
        lockout_period=dt.timedelta(minutes=5),
        window=dt.timedelta(seconds=5),
    )
    service = AuthenticationService(
        hasher,
        secret_resolver=resolver,
        rate_limiter=rate_limiter,
    )
    hashed, salt = await service.hash_tenant_password(
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        user_secret="user",
        password="p@ss",
    )
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        hashed_password=hashed,
        password_salt=salt,
        password_secret="user",
        created_at=now,
        updated_at=now,
    )
    with pytest.raises(AuthenticationError):
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="wrong",
            now=now,
            client_fingerprint="127.0.0.1",
        )
    with pytest.raises(AuthenticationError) as exc:
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="wrong",
            now=now + dt.timedelta(seconds=1),
            client_fingerprint="127.0.0.1",
        )
    assert str(exc.value) == "rate_limited"
    with pytest.raises(AuthenticationError):
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="wrong",
            now=now + dt.timedelta(seconds=6),
            client_fingerprint="127.0.0.1",
        )


@pytest.mark.asyncio
async def test_authentication_rate_limiter_locks_after_failures() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    app_secret, app_ref = _make_app_secret(now)
    tenant_secret, tenant_ref = _make_tenant_secret(now)
    resolver = _resolver_for([(app_ref, "app"), (tenant_ref, "tenant")])
    rate_limiter = AuthenticationRateLimiter(
        max_attempts=2,
        base_cooldown=dt.timedelta(seconds=1),
        max_cooldown=dt.timedelta(seconds=1),
        lockout_period=dt.timedelta(minutes=2),
        window=dt.timedelta(seconds=30),
    )
    service = AuthenticationService(
        hasher,
        secret_resolver=resolver,
        rate_limiter=rate_limiter,
    )
    hashed, salt = await service.hash_tenant_password(
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        user_secret="user",
        password="p@ss",
    )
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        hashed_password=hashed,
        password_salt=salt,
        password_secret="user",
        created_at=now,
        updated_at=now,
    )
    with pytest.raises(AuthenticationError):
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="wrong",
            now=now,
            client_fingerprint="127.0.0.1",
        )
    with pytest.raises(AuthenticationError):
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="wrong",
            now=now + dt.timedelta(seconds=2),
            client_fingerprint="127.0.0.1",
        )
    with pytest.raises(AuthenticationError) as exc:
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="wrong",
            now=now + dt.timedelta(seconds=4),
            client_fingerprint="127.0.0.1",
        )
    assert str(exc.value) == "account_locked"
    future = now + dt.timedelta(minutes=3)
    session = await service.authenticate_tenant_password(
        user=user,
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        password="p@ss",
        now=future,
        client_fingerprint="127.0.0.1",
    )
    assert session.level is SessionLevel.PASSWORD_ONLY
    assert session.id == session.record.id
    assert session.expires_at == session.record.expires_at
    assert session.revoked_at is None


@pytest.mark.asyncio
async def test_authentication_rate_limiter_prunes_inactive_states() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    rate_limiter = AuthenticationRateLimiter(window=dt.timedelta(seconds=1))
    await rate_limiter.record_failure(["user"], now)
    assert "user" in rate_limiter._states
    await rate_limiter.enforce(["user"], now + dt.timedelta(seconds=2))
    assert "user" not in rate_limiter._states


@pytest.mark.asyncio
async def test_authentication_rate_limiter_bounds_entry_count() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    rate_limiter = AuthenticationRateLimiter(max_entries=5, window=dt.timedelta(seconds=60))
    for index in range(10):
        await rate_limiter.record_failure([f"user-{index}"], now + dt.timedelta(seconds=index))
    assert len(rate_limiter._states) <= 5


@pytest.mark.asyncio
async def test_authentication_rate_limiter_rate_limited_branch() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    rate_limiter = AuthenticationRateLimiter(
        window=dt.timedelta(seconds=10),
        base_cooldown=dt.timedelta(seconds=5),
        max_cooldown=dt.timedelta(seconds=5),
    )
    await rate_limiter.record_failure(["user"], now)
    with pytest.raises(AuthenticationError) as exc:
        await rate_limiter.enforce(["user"], now + dt.timedelta(seconds=2))
    assert str(exc.value) == "rate_limited"
    await rate_limiter.enforce(["user"], now + dt.timedelta(seconds=6))
    rate_limiter._states["idle"] = authentication_module._RateLimitState()
    await rate_limiter.enforce(["idle"], now + dt.timedelta(seconds=6))


@pytest.mark.asyncio
async def test_authentication_rate_limiter_resets_after_window() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    rate_limiter = AuthenticationRateLimiter(window=dt.timedelta(seconds=2))
    await rate_limiter.record_failure(["user"], now)
    state = rate_limiter._states["user"]
    assert rate_limiter._refresh_state("user", state, now + dt.timedelta(seconds=3))


def test_passkey_authentication_failures() -> None:
    resolver = StaticSecretResolver({})
    service = AuthenticationService(
        PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1),
        secret_resolver=resolver,
    )
    manager = PasskeyManager()
    passkey = manager.register(user_id=generate_id57(), credential_id="cred", secret=b"secret", user_handle="handle")
    challenge = manager.challenge()
    with pytest.raises(AuthenticationError):
        service.authenticate_with_passkey(passkey=passkey, challenge=challenge, signature="bad")
    signature = manager.sign(passkey=passkey, challenge=challenge)
    other_user = TenantUser(
        id=generate_id57(),
        email="other@example.com",
        hashed_password="hash",
        created_at=dt.datetime.now(dt.timezone.utc),
        updated_at=dt.datetime.now(dt.timezone.utc),
    )
    with pytest.raises(AuthenticationError):
        service.authenticate_with_passkey(
            passkey=passkey,
            challenge=challenge,
            signature=signature,
            allow_user=other_user,
        )


def test_passkey_authentication_success() -> None:
    resolver = StaticSecretResolver({})
    service = AuthenticationService(
        PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1),
        secret_resolver=resolver,
    )
    manager = PasskeyManager()
    now = dt.datetime.now(dt.timezone.utc)
    passkey = manager.register(
        user_id=generate_id57(),
        credential_id="cred",
        secret=b"secret",
        user_handle="handle",
        now=now,
    )
    challenge = manager.challenge()
    signature = manager.sign(passkey=passkey, challenge=challenge)
    user = TenantUser(
        id=passkey.user_id,
        email="user@example.com",
        hashed_password="hash",
        created_at=now,
        updated_at=now,
    )
    session = service.authenticate_with_passkey(
        passkey=passkey,
        challenge=challenge,
        signature=signature,
        allow_user=user,
    )
    assert session.user_id == passkey.user_id
    assert session.level is SessionLevel.PASSKEY


def test_mfa_manager_issue_hashes_codes() -> None:
    manager = MfaManager()
    now = dt.datetime.now(dt.timezone.utc)
    issued = manager.issue(user_id="user", purpose=MfaPurpose.SIGN_IN, now=now)
    record = issued.record
    assert record.code_hash is not None
    assert record.code_salt is not None
    assert record.code_hash != issued.code
    assert record.code_salt != issued.code
    verified = manager.verify(
        codes=[record],
        user_id="user",
        submitted=issued.code,
        purpose=MfaPurpose.SIGN_IN,
        now=now,
    )
    assert verified.consumed_at == now


def test_mfa_manager_invalid_code_paths() -> None:
    manager = MfaManager()
    now = dt.datetime.now(dt.timezone.utc)
    issued = manager.issue(user_id="user", purpose=MfaPurpose.SIGN_IN, now=now)
    wrong_code = "000000" if issued.code != "000000" else "111111"
    with pytest.raises(AuthenticationError):
        manager.verify(
            codes=[issued.record],
            user_id="user",
            submitted=wrong_code,
            purpose=MfaPurpose.SIGN_IN,
            now=now,
        )
    expired = structs.replace(
        issued.record,
        expires_at=now - dt.timedelta(seconds=1),
        created_at=now - dt.timedelta(minutes=1),
        updated_at=now - dt.timedelta(minutes=1),
    )
    with pytest.raises(AuthenticationError):
        manager.verify(
            codes=[expired],
            user_id="user",
            submitted=issued.code,
            purpose=MfaPurpose.SIGN_IN,
            now=now,
        )


def test_mfa_manager_rejects_consumed_codes() -> None:
    manager = MfaManager()
    now = dt.datetime.now(dt.timezone.utc)
    issued = manager.issue(user_id="user", purpose=MfaPurpose.SIGN_IN, now=now)
    consumed = structs.replace(
        issued.record,
        consumed_at=now,
        updated_at=now,
    )
    with pytest.raises(AuthenticationError):
        manager.verify(
            codes=[consumed],
            user_id="user",
            submitted=issued.code,
            purpose=MfaPurpose.SIGN_IN,
            now=now,
        )


def test_mfa_manager_ignores_legacy_codes_without_hash_material() -> None:
    manager = MfaManager()
    now = dt.datetime.now(dt.timezone.utc)
    issued = manager.issue(user_id="user", purpose=MfaPurpose.SIGN_IN, now=now)
    legacy = structs.replace(issued.record, code_hash=None, code_salt=None)
    with pytest.raises(AuthenticationError):
        manager.verify(
            codes=[legacy],
            user_id="user",
            submitted=issued.code,
            purpose=MfaPurpose.SIGN_IN,
            now=now,
        )


def test_mfa_manager_ignores_codes_with_invalid_hash_material() -> None:
    manager = MfaManager()
    now = dt.datetime.now(dt.timezone.utc)
    issued = manager.issue(user_id="user", purpose=MfaPurpose.SIGN_IN, now=now)
    invalid = structs.replace(issued.record, code_hash="zz", code_salt="zz")
    with pytest.raises(AuthenticationError):
        manager.verify(
            codes=[invalid],
            user_id="user",
            submitted=issued.code,
            purpose=MfaPurpose.SIGN_IN,
            now=now,
        )


def test_oidc_authenticator_error_paths() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, provider, secret, _ = _build_oidc_authenticator(now=now)
    base_claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    invalid_signature = _issue_oidc_token(base_claims, b"other-secret")
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(invalid_signature, now=now)
    assert str(exc.value) == "invalid_token_signature"
    wrong_issuer_token = _issue_oidc_token({**base_claims, "iss": "https://other"}, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(wrong_issuer_token, now=now)
    assert str(exc.value) == "invalid_issuer"
    wrong_audience_token = _issue_oidc_token({**base_claims, "aud": "other"}, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(wrong_audience_token, now=now)
    assert str(exc.value) == "invalid_audience"
    unauthorized_groups_token = _issue_oidc_token({**base_claims, "groups": ["users"]}, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(unauthorized_groups_token, now=now)
    assert str(exc.value) == "unauthorized_group"


def test_oidc_authenticator_rejects_expired_token() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, provider, secret, _ = _build_oidc_authenticator(now=now)
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(minutes=1)),
        "nbf": _epoch(now - dt.timedelta(minutes=1)),
        "exp": _epoch(now - dt.timedelta(seconds=1)),
    }
    token = _issue_oidc_token(claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "token_expired"


def test_oidc_authenticator_rejects_not_yet_valid_token() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, provider, secret, _ = _build_oidc_authenticator(now=now)
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now + dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    token = _issue_oidc_token(claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "token_not_yet_valid"


def test_oidc_authenticator_rejects_replayed_token() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    defaults = OidcValidationDefaults(
        clock_skew_seconds=0,
        default_token_ttl_seconds=600,
        max_token_age_seconds=60,
    )
    authenticator, provider, secret, _ = _build_oidc_authenticator(now=now, defaults=defaults)
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=120)),
        "nbf": _epoch(now - dt.timedelta(seconds=120)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    token = _issue_oidc_token(claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "token_replay_detected"


def test_oidc_authenticator_rejects_invalid_token_structures() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, provider, secret, _ = _build_oidc_authenticator(now=now)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate("invalid", now=now)
    assert str(exc.value) == "invalid_token"

    payload = _b64url(json.dumps({"iss": provider.issuer}).encode())
    signature = _b64url(b"sig")
    token = f"-!.{payload}.{signature}"
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_token"

    header = _b64url(json.dumps({"alg": "HS256"}).encode())
    payload = _b64url(b"not-json")
    signature_invalid_json = _b64url(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    token = f"{header}.{payload}.{signature_invalid_json}"
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_token"

    payload = _b64url(json.dumps(["not", "mapping"]).encode())
    signature_invalid_mapping = _b64url(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    token = f"{header}.{payload}.{signature_invalid_mapping}"
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_token"


def test_oidc_authenticator_handles_header_anomalies() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, provider, _secret, _ = _build_oidc_authenticator(now=now)
    payload = _b64url(json.dumps({"iss": provider.issuer}).encode())

    header = _b64url(json.dumps({"alg": 123}).encode())
    token = f"{header}.{payload}.sig"
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unsupported_algorithm"

    header = _b64url(json.dumps({"alg": "HS256", "kid": 123}).encode())
    token = f"{header}.{payload}.sig"
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_token"


def test_oidc_authenticator_jwks_fetch_errors() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    _, provider, secret, resolver = _build_oidc_authenticator(now=now)
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    token = _issue_oidc_token(claims, secret)

    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: [],
        secret_resolver=resolver,
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"

    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: {"keys": []},
        secret_resolver=resolver,
    )
    resolved = authenticator.validate(token, now=now)
    assert resolved["iss"] == provider.issuer

    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: {},
        secret_resolver=resolver,
    )
    resolved = authenticator.validate(token, now=now)
    assert resolved["iss"] == provider.issuer

    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: {"keys": ["value"]},
        secret_resolver=resolver,
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"

    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: {"keys": "invalid"},
        secret_resolver=resolver,
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"


def test_oidc_authenticator_key_resolution_errors() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    _, provider, secret, resolver = _build_oidc_authenticator(now=now)
    base_claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }

    jwks_ambiguous = {
        "keys": [
            {"kty": "oct", "kid": "a", "k": _b64url(b"one")},
            {"kty": "oct", "kid": "b", "k": _b64url(b"two")},
        ]
    }
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_ambiguous,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret, kid=None)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "ambiguous_jwk"

    jwks_single = {"keys": [{"kty": "oct", "kid": "primary", "k": _b64url(b"secret")}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_single,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret, kid="missing")
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unknown_jwk"

    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_single,
        secret_resolver=resolver,
    )
    authenticator._jwks_cache = []
    token = _issue_oidc_token(base_claims, b"secret", kid=None)
    resolved = authenticator.validate(token, now=now)
    assert resolved["iss"] == provider.issuer

    jwks_mismatch = {
        "keys": [
            {
                "kty": "oct",
                "kid": "primary",
                "k": _b64url(b"secret"),
                "alg": "RS256",
            }
        ]
    }
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_mismatch,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unsupported_algorithm"

    jwks_enc = {
        "keys": [
            {
                "kty": "oct",
                "kid": "primary",
                "k": _b64url(b"secret"),
                "use": "enc",
            }
        ]
    }
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_enc,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unsupported_jwk"


def test_oidc_authenticator_signature_edge_cases() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    _, provider, secret, resolver = _build_oidc_authenticator(now=now)
    base_claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }

    jwks_oct = {"keys": [{"kty": "oct", "kid": "primary", "k": _b64url(secret)}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_oct,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret, alg="HS999")
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unsupported_algorithm"

    token_parts = _issue_oidc_token(base_claims, secret).split(".")
    token_parts[2] = "-!"
    token = ".".join(token_parts)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_token_signature"

    jwks_no_secret = {"keys": [{"kty": "oct", "kid": "primary", "k": 123}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_no_secret,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"

    jwks_bad_secret = {"keys": [{"kty": "oct", "kid": "primary", "k": "-!"}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_bad_secret,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"

    jwks_ec = {"keys": [{"kty": "EC", "kid": "primary"}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_ec,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret)
    resolved = authenticator.validate(token, now=now)
    assert resolved["iss"] == provider.issuer

    jwks_ec_sig = {"keys": [{"kty": "EC", "kid": "primary", "alg": "ES256", "use": "sig"}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_ec_sig,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret, alg="ES256")
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unsupported_jwk"


def test_oidc_authenticator_rsa_signature_paths() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    _, provider, secret, resolver = _build_oidc_authenticator(now=now)
    base_claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }

    modulus = b"\x01" + b"\x00" * 63
    exponent = (65537).to_bytes(3, "big")
    jwks_rsa = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "rsa",
                "n": _b64url(modulus),
                "e": _b64url(exponent),
            }
        ]
    }
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_rsa,
        secret_resolver=resolver,
    )
    signature = b"\x00" * len(modulus)
    token = _issue_oidc_token(base_claims, secret, kid="rsa", alg="RS256", signature_bytes=signature)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_token_signature"

    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_rsa,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret, kid="rsa", alg="RS1024", signature_bytes=signature)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unsupported_algorithm"

    jwks_bad_fields = {"keys": [{"kty": "RSA", "kid": "rsa", "n": None, "e": _b64url(exponent)}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_bad_fields,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret, kid="rsa", alg="RS256", signature_bytes=signature)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"

    jwks_bad_base64 = {"keys": [{"kty": "RSA", "kid": "rsa", "n": "-!", "e": _b64url(exponent)}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_bad_base64,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret, kid="rsa", alg="RS256", signature_bytes=signature)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"

    jwks_zero_modulus = {"keys": [{"kty": "RSA", "kid": "rsa", "n": _b64url(b"\x00"), "e": _b64url(exponent)}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_zero_modulus,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(base_claims, secret, kid="rsa", alg="RS256", signature_bytes=signature)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"

    small_modulus = b"\x01" * 16
    jwks_small = {"keys": [{"kty": "RSA", "kid": "rsa", "n": _b64url(small_modulus), "e": _b64url(exponent)}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_small,
        secret_resolver=resolver,
    )
    token = _issue_oidc_token(
        base_claims,
        secret,
        kid="rsa",
        alg="RS256",
        signature_bytes=signature[: len(small_modulus)],
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_jwks"

    jwks_large = {"keys": [{"kty": "RSA", "kid": "rsa", "n": _b64url(modulus), "e": _b64url(exponent)}]}
    authenticator = OidcAuthenticator(
        provider,
        jwks_fetcher=lambda _: jwks_large,
        secret_resolver=resolver,
    )
    signature_high = b"\xff" * len(modulus)
    token = _issue_oidc_token(base_claims, secret, kid="rsa", alg="RS256", signature_bytes=signature_high)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_token_signature"


def test_oidc_authenticator_rsa_valid_signature_branch() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    base_authenticator, provider, _, resolver = _build_oidc_authenticator(now=now)
    modulus = b"\x01" + b"\x00" * 63
    exponent = (1).to_bytes(1, "big")
    rsa_key = {"kty": "RSA", "kid": "rsa", "n": _b64url(modulus), "e": _b64url(exponent)}
    jwks = {"keys": [rsa_key]}
    authenticator = OidcAuthenticator(
        provider,
        defaults=base_authenticator.defaults,
        jwks_fetcher=lambda _: jwks,
        secret_resolver=resolver,
    )
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=10)),
        "nbf": _epoch(now - dt.timedelta(seconds=10)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    header_segment = _b64url(json.dumps({"alg": "RS256", "kid": "rsa", "typ": "JWT"}).encode())
    payload_segment = _b64url(json.dumps(claims).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode()
    digest_prefix = authentication_module._RSA_DIGEST_INFOS["RS256"]
    digest = hashlib.sha256(signing_input).digest()
    padding_len = len(modulus) - len(digest_prefix) - len(digest) - 3
    signature_bytes = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_prefix + digest
    signature_segment = _b64url(signature_bytes)
    token = f"{header_segment}.{payload_segment}.{signature_segment}"
    resolved = authenticator.validate(token, now=now)
    assert resolved["iss"] == provider.issuer


def test_oidc_authenticator_rsa_invalid_signature_branch() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    base_authenticator, provider, secret, resolver = _build_oidc_authenticator(now=now)
    modulus = b"\x01" + b"\x00" * 63
    exponent = (65537).to_bytes(3, "big")
    rsa_key = {"kty": "RSA", "kid": "rsa", "n": _b64url(modulus), "e": _b64url(exponent)}
    jwks = {"keys": [rsa_key]}
    authenticator = OidcAuthenticator(
        provider,
        defaults=base_authenticator.defaults,
        jwks_fetcher=lambda _: jwks,
        secret_resolver=resolver,
    )
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }
    signature = b"\xff" * len(modulus)
    token = _issue_oidc_token(claims, secret, kid="rsa", alg="RS256", signature_bytes=signature)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_token_signature"


def test_oidc_authenticator_validate_claims_with_ttl() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, provider, secret, resolver = _build_oidc_authenticator(now=now)
    authenticator.defaults = OidcValidationDefaults(
        clock_skew_seconds=0,
        default_token_ttl_seconds=30,
        max_token_age_seconds=None,
        require_iat=False,
    )
    valid_claims = {
        "iss": provider.issuer,
        "aud": [provider.client_id, "other"],
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=10)),
        "nbf": _epoch(now - dt.timedelta(seconds=10)),
    }
    authenticator._validate_claims(valid_claims, expected_nonce=None, now=now)

    jwks = {
        "keys": [
            {
                "kty": "oct",
                "kid": "primary",
                "k": _b64url(secret),
                "alg": "HS256",
                "use": "sig",
            }
        ]
    }
    provider_without_audience = TenantOidcProvider(
        issuer=provider.issuer,
        client_id=provider.client_id,
        client_secret=provider.client_secret,
        jwks_uri=provider.jwks_uri,
        authorization_endpoint=provider.authorization_endpoint,
        token_endpoint=provider.token_endpoint,
        userinfo_endpoint=provider.userinfo_endpoint,
        allowed_audiences=[],
        allowed_groups=provider.allowed_groups,
    )
    authenticator_without_audience = OidcAuthenticator(
        provider_without_audience,
        defaults=authenticator.defaults,
        jwks_fetcher=lambda _: jwks,
        secret_resolver=resolver,
    )
    authenticator_without_audience._validate_claims(valid_claims, expected_nonce=None, now=now)

    expired_claims = dict(valid_claims)
    expired_claims["iat"] = _epoch(now - dt.timedelta(seconds=90))
    expired_claims["nbf"] = expired_claims["iat"]
    with pytest.raises(AuthenticationError) as exc:
        authenticator._validate_claims(expired_claims, expected_nonce=None, now=now)
    assert str(exc.value) == "token_expired"

    missing_iat_claims = dict(valid_claims)
    missing_iat_claims.pop("iat")
    with pytest.raises(AuthenticationError) as exc:
        authenticator._validate_claims(missing_iat_claims, expected_nonce=None, now=now)
    assert str(exc.value) == "missing_exp"

    authenticator.defaults = OidcValidationDefaults(
        clock_skew_seconds=0,
        default_token_ttl_seconds=None,
        max_token_age_seconds=None,
        require_iat=False,
    )
    authenticator._validate_claims(valid_claims, expected_nonce=None, now=now)


def test_oidc_authenticator_claim_validation_edge_cases() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    authenticator, provider, secret, resolver = _build_oidc_authenticator(now=now)
    base_claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(minutes=5)),
    }

    missing_iat = base_claims.copy()
    missing_iat.pop("iat")
    missing_iat.pop("nbf")
    token = _issue_oidc_token(missing_iat, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token)
    assert str(exc.value) == "missing_iat"

    future_claims = base_claims.copy()
    future_claims["iat"] = _epoch(now + dt.timedelta(seconds=60))
    future_claims["nbf"] = future_claims["iat"]
    token = _issue_oidc_token(future_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "token_issued_in_future"

    invalid_audience_claims = base_claims.copy()
    invalid_audience_claims["aud"] = [123]
    token = _issue_oidc_token(invalid_audience_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_audience"

    invalid_audience_type = base_claims.copy()
    invalid_audience_type["aud"] = 123
    token = _issue_oidc_token(invalid_audience_type, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_audience"

    invalid_exp_claims = base_claims.copy()
    invalid_exp_claims["exp"] = "not-a-number"
    token = _issue_oidc_token(invalid_exp_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_exp"

    invalid_iat_claims = base_claims.copy()
    invalid_iat_claims["iat"] = []
    token = _issue_oidc_token(invalid_iat_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_iat"

    empty_iat_claims = base_claims.copy()
    empty_iat_claims["iat"] = ""
    token = _issue_oidc_token(empty_iat_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_iat"

    huge_iat_claims = base_claims.copy()
    huge_iat_claims["iat"] = 10**20
    token = _issue_oidc_token(huge_iat_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "invalid_iat"

    odd_groups_claims = base_claims.copy()
    odd_groups_claims["groups"] = 42
    token = _issue_oidc_token(odd_groups_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(token, now=now)
    assert str(exc.value) == "unauthorized_group"

    string_groups_claims = base_claims.copy()
    string_groups_claims["groups"] = "admins"
    resolved_claims = authenticator.validate(_issue_oidc_token(string_groups_claims, secret), now=now)
    assert resolved_claims["iss"] == provider.issuer

    defaults = OidcValidationDefaults(
        clock_skew_seconds=0,
        default_token_ttl_seconds=60,
        max_token_age_seconds=600,
        require_iat=False,
    )
    authenticator_no_iat = OidcAuthenticator(
        provider,
        defaults=defaults,
        jwks_fetcher=lambda _: {"keys": [{"kty": "oct", "kid": "primary", "k": _b64url(secret)}]},
        secret_resolver=resolver,
    )
    missing_exp_claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
    }
    token = _issue_oidc_token(missing_exp_claims, secret)
    with pytest.raises(AuthenticationError) as exc:
        authenticator_no_iat.validate(token, now=now)
    assert str(exc.value) == "missing_exp"

    ttl_defaults = OidcValidationDefaults(
        clock_skew_seconds=0,
        default_token_ttl_seconds=60,
        max_token_age_seconds=None,
    )
    authenticator_ttl, provider_ttl, secret_ttl, _ = _build_oidc_authenticator(now=now, defaults=ttl_defaults)
    ttl_claims = {
        "iss": provider_ttl.issuer,
        "aud": provider_ttl.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=10)),
        "nbf": _epoch(now - dt.timedelta(seconds=10)),
    }
    ttl_token = _issue_oidc_token(ttl_claims, secret_ttl)
    ttl_result = authenticator_ttl.validate(ttl_token, now=now)
    assert ttl_result["iss"] == provider_ttl.issuer


def test_oidc_authenticator_handles_naive_now() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    defaults = OidcValidationDefaults(
        clock_skew_seconds=0,
        default_token_ttl_seconds=None,
        max_token_age_seconds=None,
    )
    authenticator, provider, secret, _ = _build_oidc_authenticator(now=now, defaults=defaults)
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "nonce": "nonce",
        "groups": ["admins"],
        "iat": _epoch(now - dt.timedelta(seconds=30)),
        "nbf": _epoch(now - dt.timedelta(seconds=30)),
        "exp": _epoch(now + dt.timedelta(days=3650)),
    }
    token = _issue_oidc_token(claims, secret)
    assert authenticator.validate(token)
    naive_now = dt.datetime(2024, 1, 1)
    assert authenticator.validate(token, now=naive_now)


def test_default_jwks_fetcher(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyResponse:
        def __init__(self, payload: bytes, status: int = 200, url: str = "https://example.com/jwks") -> None:
            self._payload = payload
            self.status = status
            self._url = url

        def read(self) -> bytes:
            return self._payload

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self._url

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda uri, timeout=5, context=None: DummyResponse(json.dumps({"keys": []}).encode()),
    )
    document = authentication_module._default_jwks_fetcher("https://example.com/jwks")
    assert document["keys"] == []

    with pytest.raises(AuthenticationError) as exc:
        authentication_module._default_jwks_fetcher("http://example.com/jwks")
    assert str(exc.value) == "jwks_insecure_uri"

    monkeypatch.setenv("MERE_OIDC_JWKS_ALLOWED_HOSTS", "example.com")
    with pytest.raises(AuthenticationError) as exc:
        authentication_module._default_jwks_fetcher("https://malicious.example.net/jwks")
    assert str(exc.value) == "jwks_disallowed_host"

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda uri, timeout=5, context=None: DummyResponse(
            json.dumps({"keys": []}).encode(), url="https://malicious.example.net/jwks"
        ),
    )
    with pytest.raises(AuthenticationError) as exc:
        authentication_module._default_jwks_fetcher("https://example.com/jwks")
    assert str(exc.value) == "jwks_disallowed_host"

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda uri, timeout=5, context=None: DummyResponse(
            json.dumps({"keys": []}).encode(), url="http://example.com/jwks"
        ),
    )
    with pytest.raises(AuthenticationError) as exc:
        authentication_module._default_jwks_fetcher("https://example.com/jwks")
    assert str(exc.value) == "jwks_insecure_redirect"

    monkeypatch.delenv("MERE_OIDC_JWKS_ALLOWED_HOSTS")

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda uri, timeout=5, context=None: DummyResponse(
            json.dumps({"keys": []}).encode(), status=500
        ),
    )
    with pytest.raises(AuthenticationError) as exc:
        authentication_module._default_jwks_fetcher("https://example.com/jwks")
    assert str(exc.value) == "jwks_fetch_failed"

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda uri, timeout=5, context=None: DummyResponse(b"not json"),
    )
    with pytest.raises(AuthenticationError) as exc:
        authentication_module._default_jwks_fetcher("https://example.com/jwks")
    assert str(exc.value) == "invalid_jwks"

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda uri, timeout=5, context=None: DummyResponse(json.dumps([1, 2, 3]).encode()),
    )
    with pytest.raises(AuthenticationError) as exc:
        authentication_module._default_jwks_fetcher("https://example.com/jwks")
    assert str(exc.value) == "invalid_jwks"

    def raise_os_error(uri: str, timeout: int = 5, context: object | None = None) -> None:
        raise OSError("boom")

    monkeypatch.setattr("urllib.request.urlopen", raise_os_error)
    with pytest.raises(AuthenticationError) as exc:
        authentication_module._default_jwks_fetcher("https://example.com/jwks")
    assert str(exc.value) == "jwks_fetch_failed"


def test_saml_authenticator_error_paths() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate)
    authenticator = SamlAuthenticator(provider)
    with pytest.raises(AuthenticationError):
        authenticator.validate("<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'></Assertion>")
    subject = "user@example.com"
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject=subject,
    )
    signature_value = ET.fromstring(assertion).findtext(".//{*}SignatureValue") or ""
    tampered = assertion.replace(signature_value, "bad")
    with pytest.raises(AuthenticationError):
        authenticator.validate(tampered)


def test_saml_authenticator_rejects_invalid_certificate() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = _make_saml_provider(now, certificate="")
    with pytest.raises(AuthenticationError) as exc:
        SamlAuthenticator(provider)
    assert str(exc.value) == "invalid_certificate"


def test_saml_authenticator_rejects_invalid_signature_encoding() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate)
    authenticator = SamlAuthenticator(provider)
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )
    signature_value = ET.fromstring(assertion).findtext(".//{*}SignatureValue") or ""
    invalid = assertion.replace(signature_value, "-!")
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_invalid_assertion_document() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    _, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature("not-xml")
    assert str(exc.value) == "invalid_assertion"


def test_saml_authenticator_requires_signature_element_in_payload() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def remove_signature_element(root: LET._Element) -> None:
        signature_node = root.xpath(".//*[local-name()='Signature']")[0]
        parent = signature_node.getparent()
        assert parent is not None
        parent.remove(signature_node)

    invalid = _mutate_assertion_xml(assertion, remove_signature_element)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "missing_signature"


def test_saml_authenticator_rejects_missing_signed_info() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def remove_signed_info(root: LET._Element) -> None:
        signature = root.xpath(".//*[local-name()='Signature']")[0]
        signed_info = signature.xpath(".//*[local-name()='SignedInfo']")[0]
        signature.remove(signed_info)

    invalid = _mutate_assertion_xml(assertion, remove_signed_info)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_empty_signature_value() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def clear_signature_value(root: LET._Element) -> None:
        signature_value = root.xpath(".//*[local-name()='SignatureValue']")[0]
        signature_value.text = "  "

    invalid = _mutate_assertion_xml(assertion, clear_signature_value)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_missing_canonicalization_method() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def drop_canonicalization(root: LET._Element) -> None:
        signed_info = root.xpath(".//*[local-name()='SignedInfo']")[0]
        method = signed_info.xpath(".//*[local-name()='CanonicalizationMethod']")[0]
        signed_info.remove(method)

    invalid = _mutate_assertion_xml(assertion, drop_canonicalization)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_missing_reference() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def drop_reference(root: LET._Element) -> None:
        signed_info = root.xpath(".//*[local-name()='SignedInfo']")[0]
        reference = signed_info.xpath(".//*[local-name()='Reference']")[0]
        signed_info.remove(reference)

    invalid = _mutate_assertion_xml(assertion, drop_reference)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_missing_digest_method() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def remove_digest_method(root: LET._Element) -> None:
        reference = root.xpath(".//*[local-name()='Reference']")[0]
        digest_method = reference.xpath(".//*[local-name()='DigestMethod']")[0]
        reference.remove(digest_method)

    invalid = _mutate_assertion_xml(assertion, remove_digest_method)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_missing_digest_value() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def clear_digest_value(root: LET._Element) -> None:
        digest_value = root.xpath(".//*[local-name()='DigestValue']")[0]
        digest_value.text = ""

    invalid = _mutate_assertion_xml(assertion, clear_digest_value)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_missing_signature_method() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def remove_signature_method(root: LET._Element) -> None:
        signed_info = root.xpath(".//*[local-name()='SignedInfo']")[0]
        signature_method = signed_info.xpath(".//*[local-name()='SignatureMethod']")[0]
        signed_info.remove(signature_method)

    invalid = _mutate_assertion_xml(assertion, remove_signature_method)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_missing_signature_algorithm() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def clear_signature_algorithm(root: LET._Element) -> None:
        signature_method = root.xpath(".//*[local-name()='SignatureMethod']")[0]
        signature_method.attrib["Algorithm"] = ""

    invalid = _mutate_assertion_xml(assertion, clear_signature_algorithm)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_unknown_canonicalization_algorithm() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def set_unknown_c14n(root: LET._Element) -> None:
        method = root.xpath(".//*[local-name()='CanonicalizationMethod']")[0]
        method.attrib["Algorithm"] = "urn:unknown"

    invalid = _mutate_assertion_xml(assertion, set_unknown_c14n)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_unknown_digest_algorithm() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def set_unknown_digest(root: LET._Element) -> None:
        digest_method = root.xpath(".//*[local-name()='DigestMethod']")[0]
        digest_method.attrib["Algorithm"] = "urn:unknown"

    invalid = _mutate_assertion_xml(assertion, set_unknown_digest)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_unresolvable_reference() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def set_missing_reference(root: LET._Element) -> None:
        reference = root.xpath(".//*[local-name()='Reference']")[0]
        reference.attrib["URI"] = "#missing"

    invalid = _mutate_assertion_xml(assertion, set_missing_reference)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_external_reference_uri() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def set_external_reference(root: LET._Element) -> None:
        reference = root.xpath(".//*[local-name()='Reference']")[0]
        reference.attrib["URI"] = "https://example.com"

    invalid = _mutate_assertion_xml(assertion, set_external_reference)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_unsupported_transform() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def set_unknown_transform(root: LET._Element) -> None:
        transform = root.xpath(".//*[local-name()='Transform']")[0]
        transform.attrib["Algorithm"] = "urn:unsupported"

    invalid = _mutate_assertion_xml(assertion, set_unknown_transform)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_signature_algorithm_key_mismatch() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def set_rsa_algorithm(root: LET._Element) -> None:
        signature_method = root.xpath(".//*[local-name()='SignatureMethod']")[0]
        signature_method.attrib["Algorithm"] = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

    invalid = _mutate_assertion_xml(assertion, set_rsa_algorithm)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_supports_unqualified_signature_value() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def strip_signature_namespace(root: LET._Element) -> None:
        signature_value = root.xpath(".//*[local-name()='SignatureValue']")[0]
        signature_value.tag = "SignatureValue"

    invalid = _mutate_assertion_xml(assertion, strip_signature_namespace)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_empty_digest_algorithm_attribute() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def clear_digest_algorithm(root: LET._Element) -> None:
        digest_method = root.xpath(".//*[local-name()='DigestMethod']")[0]
        digest_method.attrib["Algorithm"] = ""

    invalid = _mutate_assertion_xml(assertion, clear_digest_algorithm)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_digest_mismatch() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def tamper_digest(root: LET._Element) -> None:
        digest_value = root.xpath(".//*[local-name()='DigestValue']")[0]
        digest_value.text = base64.b64encode(b"tampered-digest").decode()

    invalid = _mutate_assertion_xml(assertion, tamper_digest)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_saml_authenticator_rejects_unknown_signature_algorithm() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def set_unknown_signature_algorithm(root: LET._Element) -> None:
        signature_method = root.xpath(".//*[local-name()='SignatureMethod']")[0]
        signature_method.attrib["Algorithm"] = "urn:unsupported"

    invalid = _mutate_assertion_xml(assertion, set_unknown_signature_algorithm)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_apply_reference_transforms_processes_transforms() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, _certificate = _generate_saml_signing_material(now)
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )
    document = LET.fromstring(assertion.encode())
    reference = document.xpath(".//*[local-name()='Reference']")[0]
    transformed = authentication_module._apply_reference_transforms(document, reference)
    assert isinstance(transformed, bytes)
    assert transformed


def test_canonicalize_signed_info_requires_algorithm() -> None:
    signed_info = LET.fromstring(
        "<SignedInfo xmlns='http://www.w3.org/2000/09/xmldsig#'><CanonicalizationMethod/></SignedInfo>"
    )
    with pytest.raises(AuthenticationError) as exc:
        authentication_module._canonicalize_signed_info(signed_info)
    assert str(exc.value) == "invalid_signature"


def test_apply_reference_transforms_without_transforms_returns_c14n() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, _certificate = _generate_saml_signing_material(now)
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def remove_transforms(root: LET._Element) -> None:
        reference = root.xpath(".//*[local-name()='Reference']")[0]
        transforms = reference.xpath(".//*[local-name()='Transforms']")
        for node in transforms:
            reference.remove(node)

    mutated = _mutate_assertion_xml(assertion, remove_transforms)
    document = LET.fromstring(mutated.encode())
    reference = document.xpath(".//*[local-name()='Reference']")[0]
    transformed = authentication_module._apply_reference_transforms(document, reference)
    assert isinstance(transformed, bytes)
    assert transformed


def test_apply_reference_transforms_converts_bytes_before_stripping() -> None:
    document = LET.fromstring(
        "<Wrapper><Signature xmlns='http://www.w3.org/2000/09/xmldsig#'><SignedInfo></SignedInfo></Signature></Wrapper>"
    )
    reference = LET.fromstring(
        "<Reference xmlns='http://www.w3.org/2000/09/xmldsig#'>"
        "<Transforms>"
        "<Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/>"
        f"<Transform Algorithm='{authentication_module._XML_ENVELOPED_SIGNATURE_URI}'/>"
        "</Transforms>"
        "</Reference>"
    )
    transformed = authentication_module._apply_reference_transforms(document, reference)
    assert isinstance(transformed, bytes)
    assert b"Signature" not in transformed


def test_inclusive_namespace_prefixes_parses_prefix_list() -> None:
    element = LET.fromstring(
        "<Transform xmlns:ec='http://www.w3.org/2001/10/xml-exc-c14n#'>"
        "<ec:InclusiveNamespaces PrefixList='ds saml2'/></Transform>"
    )
    prefixes = authentication_module._inclusive_namespace_prefixes(element)
    assert prefixes == ("ds", "saml2")


def test_resolve_reference_with_empty_uri_returns_clone() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, _certificate = _generate_saml_signing_material(now)
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )
    document = LET.fromstring(assertion.encode())
    clone = authentication_module._resolve_reference(document, "")
    assert LET.tostring(clone) == LET.tostring(document)


def test_saml_authenticator_rejects_empty_canonicalization_algorithm() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    authenticator = SamlAuthenticator(_make_saml_provider(now, certificate=certificate))
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def clear_canonicalization_algorithm(root: LET._Element) -> None:
        method = root.xpath(".//*[local-name()='CanonicalizationMethod']")[0]
        method.attrib["Algorithm"] = ""

    invalid = _mutate_assertion_xml(assertion, clear_canonicalization_algorithm)
    with pytest.raises(AuthenticationError) as exc:
        authenticator._verify_signature(invalid)
    assert str(exc.value) == "invalid_signature"


def test_apply_reference_transforms_handles_reordered_transforms() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, _certificate = _generate_saml_signing_material(now)
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )

    def reorder_transforms(root: LET._Element) -> None:
        transforms = root.xpath(".//*[local-name()='Transform']")
        first, second = transforms[0], transforms[1]
        first.attrib["Algorithm"], second.attrib["Algorithm"] = second.attrib["Algorithm"], first.attrib["Algorithm"]

    mutated = _mutate_assertion_xml(assertion, reorder_transforms)
    document = LET.fromstring(mutated.encode())
    reference = document.xpath(".//*[local-name()='Reference']")[0]
    transformed = authentication_module._apply_reference_transforms(document, reference)
    assert isinstance(transformed, bytes)


def test_strip_signatures_removes_nodes() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, _certificate = _generate_saml_signing_material(now)
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )
    document = LET.fromstring(assertion.encode())
    authentication_module._strip_signatures(document)
    assert not document.xpath(".//*[local-name()='Signature']")


def test_strip_signatures_handles_parentless_nodes() -> None:
    class DummySignature:
        def getparent(self) -> None:
            return None

    class DummyElement:
        def xpath(self, expression: str) -> list[DummySignature]:
            assert expression == ".//*[local-name()='Signature']"
            return [DummySignature()]

    authentication_module._strip_signatures(DummyElement())  # type: ignore[arg-type]


def test_saml_authenticator_requires_signature() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    _, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate)
    authenticator = SamlAuthenticator(provider)
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject><NameID>user@example.com</NameID></Subject>"
        "</Assertion>"
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion)
    assert str(exc.value) == "missing_signature"


def test_saml_authenticator_accepts_der_certificate() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, pem_certificate = _generate_rsa_signing_material(now)
    der_bytes = x509.load_pem_x509_certificate(pem_certificate.encode()).public_bytes(serialization.Encoding.DER)
    provider = _make_saml_provider(now, certificate=base64.b64encode(der_bytes).decode())
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject=subject,
    )
    result = authenticator.validate(assertion)
    assert result["subject"] == subject


def test_saml_authenticator_accepts_public_key_material() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, _pem_certificate = _generate_rsa_signing_material(now)
    public_key = signing_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    provider = _make_saml_provider(now, certificate=public_pem)
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject=subject,
    )
    result = authenticator.validate(assertion)
    assert result["subject"] == subject


def test_saml_authenticator_accepts_der_public_key() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, _pem_certificate = _generate_rsa_signing_material(now)
    public_key = signing_key.public_key()
    der_key = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    provider = _make_saml_provider(now, certificate=base64.b64encode(der_key).decode())
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject=subject,
    )
    result = authenticator.validate(assertion)
    assert result["subject"] == subject


def test_saml_authenticator_accepts_ecdsa_certificates() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_ecdsa_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate)
    authenticator = SamlAuthenticator(provider)
    assertion = _render_signed_assertion(
        signing_key,
        body="<Subject><NameID>{subject}</NameID></Subject>",
        subject="user@example.com",
    )
    result = authenticator.validate(assertion)
    assert result["subject"] == "user@example.com"


def test_saml_authenticator_rejects_unsupported_certificate_format() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = _make_saml_provider(now, certificate="not-a-certificate")
    with pytest.raises(AuthenticationError) as exc:
        SamlAuthenticator(provider)
    assert str(exc.value) == "invalid_certificate"


def test_saml_authenticator_enforces_temporal_conditions_and_audience() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(
        now,
        certificate=certificate,
        clock_skew_seconds=0,
        allowed_audiences=["urn:example:aud"],
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    not_before = (now - dt.timedelta(minutes=5)).replace(microsecond=0, tzinfo=None)
    not_on_or_after = (now + dt.timedelta(minutes=5)).replace(microsecond=0, tzinfo=None)
    nb = not_before.isoformat()
    noa = not_on_or_after.isoformat()
    assertion = _render_signed_assertion(
        signing_key,
        body=(
            "<Subject>"
            "<NameID>{subject}</NameID>"
            "<SubjectConfirmation>"
            "<SubjectConfirmationData NotBefore='{nb}' NotOnOrAfter='{noa}'/>"
            "</SubjectConfirmation>"
            "</Subject>"
            "<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'>"
            "<AudienceRestriction>"
            "<Audience>urn:example:aud</Audience>"
            "</AudienceRestriction>"
            "</Conditions>"
        ),
        subject=subject,
        nb=nb,
        noa=noa,
    )
    result = authenticator.validate(assertion, now=now.replace(tzinfo=None))
    assert result["subject"] == subject
    assert result["attributes"] == {}


def test_saml_authenticator_rejects_future_conditions() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate, clock_skew_seconds=0)
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    not_before = now + dt.timedelta(minutes=5)
    not_on_or_after = now + dt.timedelta(minutes=10)
    nb = _saml_instant(not_before)
    noa = _saml_instant(not_on_or_after)
    assertion = _render_signed_assertion(
        signing_key,
        body=(
            "<Subject>"
            "<NameID>{subject}</NameID>"
            "<SubjectConfirmation>"
            "<SubjectConfirmationData NotBefore='{nb}' NotOnOrAfter='{noa}'/>"
            "</SubjectConfirmation>"
            "</Subject>"
            "<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'></Conditions>"
        ),
        subject=subject,
        nb=nb,
        noa=noa,
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "assertion_not_yet_valid"


def test_saml_authenticator_rejects_expired_conditions() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate, clock_skew_seconds=0)
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    not_before = now - dt.timedelta(minutes=10)
    not_on_or_after = now - dt.timedelta(minutes=5)
    nb = _saml_instant(not_before)
    noa = _saml_instant(not_on_or_after)
    assertion = _render_signed_assertion(
        signing_key,
        body=(
            "<Subject>"
            "<NameID>{subject}</NameID>"
            "<SubjectConfirmation>"
            "<SubjectConfirmationData NotBefore='{nb}' NotOnOrAfter='{noa}'/>"
            "</SubjectConfirmation>"
            "</Subject>"
            "<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'></Conditions>"
        ),
        subject=subject,
        nb=nb,
        noa=noa,
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "assertion_expired"


def test_saml_authenticator_rejects_expired_subject_confirmation() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate, clock_skew_seconds=0)
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    conditions_not_before = now - dt.timedelta(minutes=5)
    conditions_not_on_or_after = now + dt.timedelta(minutes=5)
    nb = _saml_instant(conditions_not_before)
    noa = _saml_instant(conditions_not_on_or_after)
    expired = _saml_instant(now - dt.timedelta(minutes=1))
    assertion = _render_signed_assertion(
        signing_key,
        body=(
            "<Subject>"
            "<NameID>{subject}</NameID>"
            "<SubjectConfirmation>"
            "<SubjectConfirmationData NotBefore='{nb}' NotOnOrAfter='{expired}'/>"
            "</SubjectConfirmation>"
            "</Subject>"
            "<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'></Conditions>"
        ),
        subject=subject,
        nb=nb,
        expired=expired,
        noa=noa,
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "subject_confirmation_expired"


def test_saml_authenticator_rejects_invalid_audience() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(
        now,
        certificate=certificate,
        clock_skew_seconds=0,
        allowed_audiences=["urn:example:aud"],
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    nb = _saml_instant(now - dt.timedelta(minutes=5))
    noa = _saml_instant(now + dt.timedelta(minutes=5))
    assertion = _render_signed_assertion(
        signing_key,
        body=(
            "<Subject>"
            "<NameID>{subject}</NameID>"
            "<SubjectConfirmation>"
            "<SubjectConfirmationData NotBefore='{nb}' NotOnOrAfter='{noa}'/>"
            "</SubjectConfirmation>"
            "</Subject>"
            "<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'>"
            "<AudienceRestriction>"
            "<Audience>urn:example:other</Audience>"
            "</AudienceRestriction>"
            "</Conditions>"
        ),
        subject=subject,
        nb=nb,
        noa=noa,
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "invalid_audience"


def test_saml_authenticator_allows_missing_temporal_attributes() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate, clock_skew_seconds=0)
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    assertion = _render_signed_assertion(
        signing_key,
        body=(
            "<Subject>"
            "<NameID>{subject}</NameID>"
            "<SubjectConfirmation><SubjectConfirmationData/></SubjectConfirmation>"
            "</Subject>"
            "<Conditions></Conditions>"
        ),
        subject=subject,
    )
    result = authenticator.validate(assertion, now=now)
    assert result["subject"] == subject


def test_saml_authenticator_rejects_future_subject_confirmation() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    signing_key, certificate = _generate_saml_signing_material(now)
    provider = _make_saml_provider(now, certificate=certificate, clock_skew_seconds=0)
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    conditions_not_before = _saml_instant(now - dt.timedelta(minutes=5))
    conditions_not_on_or_after = _saml_instant(now + dt.timedelta(minutes=5))
    confirmation_not_before = _saml_instant(now + dt.timedelta(minutes=5))
    assertion = _render_signed_assertion(
        signing_key,
        body=(
            "<Subject>"
            "<NameID>{subject}</NameID>"
            "<SubjectConfirmation>"
            "<SubjectConfirmationData NotBefore='{confirmation_not_before}' "
            "NotOnOrAfter='{conditions_not_on_or_after}'/>"
            "</SubjectConfirmation>"
            "</Subject>"
            "<Conditions NotBefore='{conditions_not_before}' NotOnOrAfter='{conditions_not_on_or_after}'></Conditions>"
        ),
        subject=subject,
        confirmation_not_before=confirmation_not_before,
        conditions_not_on_or_after=conditions_not_on_or_after,
        conditions_not_before=conditions_not_before,
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "subject_confirmation_not_yet_valid"


def test__argon2_hash_returns_non_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_hash_secret(*args: object, **kwargs: object) -> str:  # pragma: no cover - patched in test
        return "textual-hash"

    monkeypatch.setattr(authentication_module, "argon2_hash_secret", fake_hash_secret)
    result = authentication_module._argon2_hash(
        "password",
        "secret",
        "salt",
        2,
        1024,
        1,
    )
    assert result == "textual-hash"
