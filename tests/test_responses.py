from __future__ import annotations

import datetime as dt

from artemis.exceptions import HTTPError
from artemis.models import (
    AdminUser,
    AppSecret,
    MfaCode,
    MfaPurpose,
    SessionLevel,
    SessionToken,
    TenantSecret,
    TenantUser,
)
import pytest

from artemis.requests import Request
from artemis.responses import (
    DEFAULT_SECURITY_HEADERS,
    JSONResponse,
    PlainTextResponse,
    Response,
    apply_default_security_headers,
    exception_to_response,
    security_headers_middleware,
)
from artemis.serialization import json_decode
from artemis.tenancy import TenantContext, TenantScope


def test_plain_text_response_headers() -> None:
    response = PlainTextResponse("hello")
    assert response.body == b"hello"
    assert ("content-type", "text/plain; charset=utf-8") in response.headers
    for header, value in DEFAULT_SECURITY_HEADERS:
        assert (header, value) in response.headers


def test_response_with_headers() -> None:
    base = Response(status=204)
    updated = base.with_headers((("x-test", "1"),))
    assert updated.headers[-1] == ("x-test", "1")


def test_exception_to_response_serializes() -> None:
    error = HTTPError(400, "bad request")
    response = exception_to_response(error)
    data = json_decode(response.body)
    assert data == {"error": {"status": 400, "reason": "Bad Request", "detail": "bad request"}}
    for header, value in DEFAULT_SECURITY_HEADERS:
        assert (header, value) in response.headers


def test_apply_default_security_headers_preserves_existing() -> None:
    response = Response(status=200, headers=(("strict-transport-security", "custom"),))
    hardened = apply_default_security_headers(response)
    assert hardened.headers.count(("strict-transport-security", "custom")) == 1
    header_names = {name for name, _ in hardened.headers}
    assert "content-security-policy" in header_names


def test_apply_default_security_headers_with_empty_baseline() -> None:
    class EmptyHeaders:
        def __iter__(self):
            return iter(())

        def __bool__(self) -> bool:
            return True

    response = Response(status=204)
    assert apply_default_security_headers(response, headers=EmptyHeaders()) is response


@pytest.mark.asyncio
async def test_security_headers_middleware_adds_defaults() -> None:
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    async def endpoint(_: Request) -> Response:
        return Response(status=200)

    request = Request(method="GET", path="/", tenant=tenant)
    response = await security_headers_middleware(request, endpoint)
    for header, value in DEFAULT_SECURITY_HEADERS:
        assert (header, value) in response.headers


def test_json_response_redacts_admin_user_sensitive_fields() -> None:
    user = AdminUser(
        email="admin@example.com",
        hashed_password="hash",
        password_salt="salt",
        password_secret="secret",
        mfa_enforced=True,
        mfa_enrolled_at=dt.datetime.now(dt.timezone.utc),
    )
    data = json_decode(JSONResponse(user).body)
    assert data["email"] == "admin@example.com"
    for field in {"hashed_password", "password_salt", "password_secret", "mfa_enforced", "mfa_enrolled_at"}:
        assert field not in data


def test_json_response_redacts_tenant_credentials_and_tokens() -> None:
    tenant_user = TenantUser(
        email="user@example.com",
        hashed_password="hash",
        password_salt="salt",
        password_secret="secret",
        mfa_enforced=True,
        mfa_enrolled_at=dt.datetime.now(dt.timezone.utc),
    )
    tenant_secret = TenantSecret(secret="tenant-secret")
    app_secret = AppSecret(secret_value="value", salt="pepper")
    mfa_code = MfaCode(
        user_id="user",
        code="123456",
        purpose=MfaPurpose.SIGN_IN,
        expires_at=dt.datetime.now(dt.timezone.utc),
    )
    session = SessionToken(
        user_id="user",
        token="token",
        expires_at=dt.datetime.now(dt.timezone.utc),
        level=SessionLevel.MFA,
    )
    payload = {
        "user": tenant_user,
        "tenant_secret": tenant_secret,
        "app_secret": app_secret,
        "mfa": mfa_code,
        "session": session,
    }
    data = json_decode(JSONResponse(payload).body)
    for field in {"hashed_password", "password_salt", "password_secret", "mfa_enforced", "mfa_enrolled_at"}:
        assert field not in data["user"]
    assert "secret" not in data["tenant_secret"]
    assert "secret_value" not in data["app_secret"]
    assert "salt" not in data["app_secret"]
    assert "code" not in data["mfa"]
    assert "token" not in data["session"]
