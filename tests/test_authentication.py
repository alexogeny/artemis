import base64
import datetime as dt
import hashlib
import hmac
import json

import pytest

import artemis.authentication as authentication_module
from artemis.authentication import (
    AuthenticationError,
    AuthenticationService,
    FederatedIdentityDirectory,
    MfaManager,
    OidcAuthenticator,
    PasskeyManager,
    PasswordHasher,
    SamlAuthenticator,
    compose_admin_secret,
    compose_tenant_secret,
)
from artemis.id57 import generate_id57
from artemis.models import (
    AdminUser,
    AppSecret,
    FederatedProvider,
    MfaCode,
    MfaPurpose,
    SessionLevel,
    TenantFederatedUser,
    TenantOidcProvider,
    TenantSamlProvider,
    TenantSecret,
    TenantUser,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _saml_instant(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@pytest.mark.asyncio
async def test_password_hashing_and_mfa_authentication() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    hasher = PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1)
    service = AuthenticationService(hasher)
    app_secret = AppSecret(id=generate_id57(), secret_value="app", salt="salt", created_at=now)
    tenant_secret = TenantSecret(id=generate_id57(), secret="tenant", created_at=now)
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
    code = manager.issue(user_id=user.id, purpose=MfaPurpose.SIGN_IN, now=now)
    session = await service.authenticate_tenant_password(
        user=user,
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        password="correct horse battery",
        mfa_codes=[code],
        submitted_code=code.code,
        now=now,
    )
    assert session.level is SessionLevel.MFA
    with pytest.raises(AuthenticationError):
        await service.authenticate_tenant_password(
            user=user,
            app_secret=app_secret,
            tenant_secret=tenant_secret,
            password="correct horse battery",
            mfa_codes=[code],
            submitted_code="000000",
            now=now,
        )


def test_secret_composition_differs_between_scopes() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    app_secret = AppSecret(id=generate_id57(), secret_value="app", salt="salt", created_at=now)
    admin = AdminUser(
        id=generate_id57(),
        email="admin@example.com",
        hashed_password="hash",
        created_at=now,
        updated_at=now,
        password_secret="admin",
    )
    tenant_secret = TenantSecret(id=generate_id57(), secret="tenant", created_at=now)
    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        hashed_password="hash",
        created_at=now,
        updated_at=now,
        password_secret="user",
    )
    admin_secret = compose_admin_secret(app_secret, admin)
    tenant_secret_value = compose_tenant_secret(app_secret, tenant_secret, user)
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
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantOidcProvider(
        id=generate_id57(),
        issuer="https://issuer.example.com",
        client_id="client",
        client_secret="oidc-secret",
        jwks_uri="https://issuer.example.com/jwks",
        authorization_endpoint="https://issuer.example.com/auth",
        token_endpoint="https://issuer.example.com/token",
        userinfo_endpoint="https://issuer.example.com/userinfo",
        created_at=now,
        updated_at=now,
        allowed_audiences=["client"],
        allowed_groups=["admins"],
    )
    header = _b64url(json.dumps({"alg": "HS256"}).encode())
    payload = _b64url(
        json.dumps({"iss": provider.issuer, "aud": "client", "nonce": "nonce", "groups": ["admins"]}).encode()
    )
    signature = _b64url(
        hmac.new(
            provider.client_secret.encode(),
            f"{header}.{payload}".encode(),
            hashlib.sha256,
        ).digest()
    )
    token = f"{header}.{payload}.{signature}"
    authenticator = OidcAuthenticator(provider)
    claims = authenticator.validate(token, expected_nonce="nonce")
    assert claims["aud"] == "client"
    with pytest.raises(AuthenticationError):
        authenticator.validate(token, expected_nonce="other")
    other_payload = _b64url(
        json.dumps({"iss": provider.issuer, "aud": "client", "nonce": "nonce", "groups": ["users"]}).encode()
    )
    other_signature = _b64url(
        hmac.new(
            provider.client_secret.encode(),
            f"{header}.{other_payload}".encode(),
            hashlib.sha256,
        ).digest()
    )
    other_token = f"{header}.{other_payload}.{other_signature}"
    with pytest.raises(AuthenticationError):
        authenticator.validate(other_token)


def test_saml_authenticator_validates_and_maps_attributes() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        attribute_mapping={"email": "mail"},
    )
    subject = "user@example.com"
    signature = _b64url(hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest())
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        f"<Subject><NameID>{subject}</NameID></Subject>"
        "<Attribute Name='email'><AttributeValue>user@example.com</AttributeValue></Attribute>"
        "<Attribute><AttributeValue>ignored</AttributeValue></Attribute>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
    )
    authenticator = SamlAuthenticator(provider)
    result = authenticator.validate(assertion)
    assert result["subject"] == subject
    assert result["attributes"]["mail"] == subject
    assert "ignored" not in result["attributes"].values()
    tampered = assertion.replace(signature, "invalid")
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
    service = AuthenticationService(hasher)
    app_secret = AppSecret(id=generate_id57(), secret_value="secret", salt="salt", created_at=now)
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
    service = AuthenticationService(hasher)
    app_secret = AppSecret(id=generate_id57(), secret_value="app", salt="salt", created_at=now)
    tenant_secret = TenantSecret(id=generate_id57(), secret="tenant", created_at=now)
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
    service = AuthenticationService(PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1))
    app_secret = AppSecret(id=generate_id57(), secret_value="app", salt="salt", created_at=now)
    tenant_secret = TenantSecret(id=generate_id57(), secret="tenant", created_at=now)
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
    service = AuthenticationService(PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1))
    app_secret = AppSecret(id=generate_id57(), secret_value="app", salt="salt", created_at=now)
    tenant_secret = TenantSecret(id=generate_id57(), secret="tenant", created_at=now)
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
    service = AuthenticationService(PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1))
    app_secret = AppSecret(id=generate_id57(), secret_value="app", salt="salt", created_at=now)
    tenant_secret = TenantSecret(id=generate_id57(), secret="tenant", created_at=now)
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
    valid = manager.issue(user_id=user.id, purpose=MfaPurpose.SIGN_IN, now=now)
    mismatched_user = MfaCode(
        user_id="other",
        code="111111",
        purpose=MfaPurpose.SIGN_IN,
        expires_at=now + dt.timedelta(minutes=5),
        created_at=now,
    )
    mismatched_purpose = MfaCode(
        user_id=user.id,
        code="222222",
        purpose=MfaPurpose.RECOVERY,
        expires_at=now + dt.timedelta(minutes=5),
        created_at=now,
    )
    session = await service.authenticate_tenant_password(
        user=user,
        app_secret=app_secret,
        tenant_secret=tenant_secret,
        password="p@ss",
        mfa_codes=[mismatched_user, mismatched_purpose, valid],
        submitted_code=valid.code,
        now=now,
    )
    assert session.level is SessionLevel.MFA


def test_passkey_authentication_failures() -> None:
    service = AuthenticationService(PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1))
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
    service = AuthenticationService(PasswordHasher(time_cost=2, memory_cost=8_192, parallelism=1))
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


def test_mfa_manager_invalid_code_paths() -> None:
    manager = MfaManager()
    now = dt.datetime.now(dt.timezone.utc)
    issued = manager.issue(user_id="user", purpose=MfaPurpose.SIGN_IN, now=now)
    with pytest.raises(AuthenticationError):
        manager.verify(codes=[issued], user_id="user", submitted="999999", purpose=MfaPurpose.SIGN_IN, now=now)
    expired = MfaCode(
        user_id="user",
        code="111111",
        purpose=MfaPurpose.SIGN_IN,
        expires_at=now - dt.timedelta(seconds=1),
        created_at=now - dt.timedelta(minutes=1),
    )
    with pytest.raises(AuthenticationError):
        manager.verify(codes=[expired], user_id="user", submitted="111111", purpose=MfaPurpose.SIGN_IN, now=now)


def test_mfa_manager_rejects_consumed_codes() -> None:
    manager = MfaManager()
    now = dt.datetime.now(dt.timezone.utc)
    consumed = MfaCode(
        user_id="user",
        code="123456",
        purpose=MfaPurpose.SIGN_IN,
        expires_at=now + dt.timedelta(minutes=5),
        created_at=now - dt.timedelta(minutes=1),
        consumed_at=now,
    )
    with pytest.raises(AuthenticationError):
        manager.verify(codes=[consumed], user_id="user", submitted="123456", purpose=MfaPurpose.SIGN_IN, now=now)


def test_oidc_authenticator_error_paths() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantOidcProvider(
        id=generate_id57(),
        issuer="https://issuer.example.com",
        client_id="client",
        client_secret="oidc-secret",
        jwks_uri="https://issuer.example.com/jwks",
        authorization_endpoint="https://issuer.example.com/auth",
        token_endpoint="https://issuer.example.com/token",
        userinfo_endpoint="https://issuer.example.com/userinfo",
        created_at=now,
        updated_at=now,
        allowed_audiences=["client"],
        allowed_groups=["admins"],
    )
    header = _b64url(json.dumps({"alg": "HS256"}).encode())
    payload = _b64url(
        json.dumps({"iss": provider.issuer, "aud": "client", "nonce": "nonce", "groups": ["admins"]}).encode()
    )
    bad_signature = _b64url(hmac.new(b"wrong", f"{header}.{payload}".encode(), hashlib.sha256).digest())
    authenticator = OidcAuthenticator(provider)
    with pytest.raises(AuthenticationError):
        authenticator.validate(f"{header}.{payload}.{bad_signature}")
    wrong_issuer_payload = _b64url(json.dumps({"iss": "https://other", "aud": "client", "nonce": "nonce"}).encode())
    sig = _b64url(
        hmac.new(
            provider.client_secret.encode(),
            f"{header}.{wrong_issuer_payload}".encode(),
            hashlib.sha256,
        ).digest()
    )
    with pytest.raises(AuthenticationError):
        authenticator.validate(f"{header}.{wrong_issuer_payload}.{sig}")
    wrong_audience_payload = _b64url(json.dumps({"iss": provider.issuer, "aud": "other", "nonce": "nonce"}).encode())
    sig = _b64url(
        hmac.new(
            provider.client_secret.encode(),
            f"{header}.{wrong_audience_payload}".encode(),
            hashlib.sha256,
        ).digest()
    )
    with pytest.raises(AuthenticationError):
        authenticator.validate(f"{header}.{wrong_audience_payload}.{sig}")
    good_payload = _b64url(
        json.dumps({"iss": provider.issuer, "aud": "client", "nonce": "nonce", "groups": ["users"]}).encode()
    )
    sig = _b64url(
        hmac.new(
            provider.client_secret.encode(),
            f"{header}.{good_payload}".encode(),
            hashlib.sha256,
        ).digest()
    )
    with pytest.raises(AuthenticationError):
        authenticator.validate(f"{header}.{good_payload}.{sig}")


def test_saml_authenticator_error_paths() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
    )
    authenticator = SamlAuthenticator(provider)
    with pytest.raises(AuthenticationError):
        authenticator.validate("<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'></Assertion>")
    subject = "user@example.com"
    signature = _b64url(hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest())
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject><NameID>user@example.com</NameID></Subject>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
    )
    tampered = assertion.replace(signature, "bad")
    with pytest.raises(AuthenticationError):
        authenticator.validate(tampered)


def test_saml_authenticator_requires_signature() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
    )
    authenticator = SamlAuthenticator(provider)
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject><NameID>user@example.com</NameID></Subject>"
        "</Assertion>"
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion)
    assert str(exc.value) == "missing_signature"


def test_saml_authenticator_enforces_temporal_conditions_and_audience() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        clock_skew_seconds=0,
        allowed_audiences=["urn:example:aud"],
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    signature = _b64url(hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest())
    not_before = (now - dt.timedelta(minutes=5)).replace(microsecond=0, tzinfo=None)
    not_on_or_after = (now + dt.timedelta(minutes=5)).replace(microsecond=0, tzinfo=None)
    nb = not_before.isoformat()
    noa = not_on_or_after.isoformat()
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject>"
        f"<NameID>{subject}</NameID>"
        "<SubjectConfirmation>"
        f"<SubjectConfirmationData NotBefore='{nb}' "
        f"NotOnOrAfter='{noa}'/>"
        "</SubjectConfirmation>"
        "</Subject>"
        f"<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'>"
        "<AudienceRestriction>"
        "<Audience>urn:example:aud</Audience>"
        "</AudienceRestriction>"
        "</Conditions>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
    )
    result = authenticator.validate(assertion, now=now.replace(tzinfo=None))
    assert result["subject"] == subject
    assert result["attributes"] == {}


def test_saml_authenticator_rejects_future_conditions() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        clock_skew_seconds=0,
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    signature = _b64url(hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest())
    not_before = now + dt.timedelta(minutes=5)
    not_on_or_after = now + dt.timedelta(minutes=10)
    nb = _saml_instant(not_before)
    noa = _saml_instant(not_on_or_after)
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject>"
        f"<NameID>{subject}</NameID>"
        "<SubjectConfirmation>"
        f"<SubjectConfirmationData NotBefore='{nb}' "
        f"NotOnOrAfter='{noa}'/>"
        "</SubjectConfirmation>"
        "</Subject>"
        f"<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'>"
        "</Conditions>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "assertion_not_yet_valid"


def test_saml_authenticator_rejects_expired_conditions() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        clock_skew_seconds=0,
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    signature = _b64url(hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest())
    not_before = now - dt.timedelta(minutes=10)
    not_on_or_after = now - dt.timedelta(minutes=5)
    nb = _saml_instant(not_before)
    noa = _saml_instant(not_on_or_after)
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject>"
        f"<NameID>{subject}</NameID>"
        "<SubjectConfirmation>"
        f"<SubjectConfirmationData NotBefore='{nb}' "
        f"NotOnOrAfter='{noa}'/>"
        "</SubjectConfirmation>"
        "</Subject>"
        f"<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'>"
        "</Conditions>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "assertion_expired"


def test_saml_authenticator_rejects_expired_subject_confirmation() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        clock_skew_seconds=0,
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    signature = _b64url(hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest())
    conditions_not_before = now - dt.timedelta(minutes=5)
    conditions_not_on_or_after = now + dt.timedelta(minutes=5)
    nb = _saml_instant(conditions_not_before)
    noa = _saml_instant(conditions_not_on_or_after)
    expired = _saml_instant(now - dt.timedelta(minutes=1))
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject>"
        f"<NameID>{subject}</NameID>"
        "<SubjectConfirmation>"
        f"<SubjectConfirmationData NotBefore='{nb}' "
        f"NotOnOrAfter='{expired}'/>"
        "</SubjectConfirmation>"
        "</Subject>"
        f"<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'>"
        "</Conditions>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "subject_confirmation_expired"


def test_saml_authenticator_rejects_invalid_audience() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        clock_skew_seconds=0,
        allowed_audiences=["urn:example:aud"],
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    signature = _b64url(hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest())
    nb = _saml_instant(now - dt.timedelta(minutes=5))
    noa = _saml_instant(now + dt.timedelta(minutes=5))
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject>"
        f"<NameID>{subject}</NameID>"
        "<SubjectConfirmation>"
        f"<SubjectConfirmationData NotBefore='{nb}' "
        f"NotOnOrAfter='{noa}'/>"
        "</SubjectConfirmation>"
        "</Subject>"
        f"<Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'>"
        "<AudienceRestriction>"
        "<Audience>urn:example:other</Audience>"
        "</AudienceRestriction>"
        "</Conditions>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
    )
    with pytest.raises(AuthenticationError) as exc:
        authenticator.validate(assertion, now=now)
    assert str(exc.value) == "invalid_audience"


def test_saml_authenticator_allows_missing_temporal_attributes() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        clock_skew_seconds=0,
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    signature = _b64url(
        hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest()
    )
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject>"
        f"<NameID>{subject}</NameID>"
        "<SubjectConfirmation><SubjectConfirmationData/></SubjectConfirmation>"
        "</Subject>"
        "<Conditions></Conditions>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
    )
    result = authenticator.validate(assertion, now=now)
    assert result["subject"] == subject


def test_saml_authenticator_rejects_future_subject_confirmation() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    provider = TenantSamlProvider(
        id=generate_id57(),
        entity_id="urn:example",
        metadata_url="https://example.com/metadata",
        certificate="saml-secret",
        acs_url="https://app.example.com/acs",
        created_at=now,
        updated_at=now,
        clock_skew_seconds=0,
    )
    authenticator = SamlAuthenticator(provider)
    subject = "user@example.com"
    signature = _b64url(
        hmac.new(provider.certificate.encode(), subject.encode(), hashlib.sha256).digest()
    )
    conditions_not_before = _saml_instant(now - dt.timedelta(minutes=5))
    conditions_not_on_or_after = _saml_instant(now + dt.timedelta(minutes=5))
    confirmation_not_before = _saml_instant(now + dt.timedelta(minutes=5))
    assertion = (
        "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>"
        "<Subject>"
        f"<NameID>{subject}</NameID>"
        "<SubjectConfirmation>"
        f"<SubjectConfirmationData NotBefore='{confirmation_not_before}' "
        f"NotOnOrAfter='{conditions_not_on_or_after}'/>"
        "</SubjectConfirmation>"
        "</Subject>"
        f"<Conditions NotBefore='{conditions_not_before}' NotOnOrAfter='{conditions_not_on_or_after}'>"
        "</Conditions>"
        f"<SignatureValue>{signature}</SignatureValue>"
        "</Assertion>"
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
