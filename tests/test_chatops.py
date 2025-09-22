from __future__ import annotations

import asyncio
from typing import Any

import pytest

from artemis import (
    AppConfig,
    ArtemisApp,
    ChatMessage,
    ChatOpsConfig,
    ChatOpsError,
    ChatOpsRoute,
    ChatOpsService,
    SlackWebhookConfig,
    TenantContext,
    TenantScope,
    TestClient,
)
from artemis.chatops import _default_transport
from artemis.serialization import json_decode


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[SlackWebhookConfig, bytes, dict[str, str]]] = []

    async def __call__(
        self,
        config: SlackWebhookConfig,
        payload: bytes,
        headers: dict[str, str] | None,
    ) -> None:
        await asyncio.sleep(0)
        self.calls.append((config, payload, dict(headers or {})))


@pytest.mark.asyncio
async def test_chatops_routes_per_tenant() -> None:
    transport = RecordingTransport()
    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(
            webhook_url="https://hooks.slack.com/services/default",
            default_channel="#general",
            username="artemis",
        ),
        routes=(
            ChatOpsRoute(
                tenant="acme",
                config=SlackWebhookConfig(
                    webhook_url="https://hooks.slack.com/services/acme",
                    default_channel="#acme",
                    username="acme-bot",
                    icon_emoji=":rocket:",
                ),
            ),
            ChatOpsRoute(
                scope=TenantScope.ADMIN,
                config=SlackWebhookConfig(
                    webhook_url="https://hooks.slack.com/services/admin",
                    default_channel="#admins",
                ),
            ),
        ),
    )
    service = ChatOpsService(config, transport=transport)

    acme = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    beta = TenantContext(tenant="beta", site="demo", domain="example.com", scope=TenantScope.TENANT)
    admin = TenantContext(tenant="admin", site="demo", domain="example.com", scope=TenantScope.ADMIN)

    await service.send(acme, ChatMessage(text="Acme ready"))
    await service.send(
        beta,
        ChatMessage(
            text="Beta update",
            channel="#beta",
            icon_emoji=":beta:",
            thread_ts="123.45",
            attachments=({"type": "section", "text": {"type": "mrkdwn", "text": "Beta"}},),
            blocks=({"type": "context", "elements": [{"type": "mrkdwn", "text": "Context"}]},),
            extra={"metadata": {"event_type": "beta"}},
        ),
    )
    await service.send(admin, ChatMessage(text="Admin alert"))

    assert [call[0].webhook_url for call in transport.calls] == [
        "https://hooks.slack.com/services/acme",
        "https://hooks.slack.com/services/default",
        "https://hooks.slack.com/services/admin",
    ]

    acme_payload = json_decode(transport.calls[0][1])
    assert acme_payload["channel"] == "#acme"
    assert acme_payload["username"] == "acme-bot"
    assert acme_payload["icon_emoji"] == ":rocket:"
    beta_payload = json_decode(transport.calls[1][1])
    assert beta_payload["channel"] == "#beta"
    assert beta_payload["icon_emoji"] == ":beta:"
    assert beta_payload["thread_ts"] == "123.45"
    assert beta_payload["attachments"] == [
        {"type": "section", "text": {"type": "mrkdwn", "text": "Beta"}},
    ]
    assert beta_payload["blocks"] == [
        {"type": "context", "elements": [{"type": "mrkdwn", "text": "Context"}]},
    ]
    assert beta_payload["metadata"] == {"event_type": "beta"}
    admin_payload = json_decode(transport.calls[2][1])
    assert admin_payload["channel"] == "#admins"


@pytest.mark.asyncio
async def test_chatops_requires_route() -> None:
    service = ChatOpsService(ChatOpsConfig(enabled=True))
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    with pytest.raises(ChatOpsError):
        await service.send(tenant, ChatMessage(text="missing"))


@pytest.mark.asyncio
async def test_chatops_disabled_config() -> None:
    config = ChatOpsConfig(
        enabled=False,
        default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default"),
    )
    service = ChatOpsService(config)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    assert not service.enabled
    assert not service.is_configured(tenant)
    with pytest.raises(ChatOpsError):
        await service.send(tenant, ChatMessage(text="disabled"))


@pytest.mark.asyncio
async def test_chatops_dependency_integration() -> None:
    transport = RecordingTransport()
    chatops_config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(
            webhook_url="https://hooks.slack.com/services/default",
            default_channel="#general",
        ),
    )
    config = AppConfig(
        site="demo",
        domain="example.com",
        allowed_tenants=("acme", "beta"),
        chatops=chatops_config,
    )
    chatops_service = ChatOpsService(chatops_config, transport=transport)
    app = ArtemisApp(config=config, chatops=chatops_service)

    @app.post("/notify")
    async def notify(chatops: ChatOpsService, tenant: TenantContext) -> dict[str, Any]:
        await chatops.send(tenant, ChatMessage(text=f"update::{tenant.tenant}"))
        return {"ok": True}

    async with TestClient(app) as client:
        acme = await client.post("/notify", tenant="acme")
        beta = await client.post("/notify", tenant="beta")

    assert json_decode(acme.body) == {"ok": True}
    assert json_decode(beta.body) == {"ok": True}
    assert [json_decode(call[1])["text"] for call in transport.calls] == [
        "update::acme",
        "update::beta",
    ]


@pytest.mark.asyncio
async def test_chatops_broadcast_and_sync_transport() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def sync_transport(config: SlackWebhookConfig, payload: bytes, headers: dict[str, str]) -> None:
        calls.append((config.webhook_url, json_decode(payload)))

    config = ChatOpsConfig(
        enabled=True,
        default=SlackWebhookConfig(
            webhook_url="https://hooks.slack.com/services/default",
            default_channel="#general",
        ),
    )
    service = ChatOpsService(config, transport=sync_transport)
    tenants = [
        TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
        TenantContext(tenant="beta", site="demo", domain="example.com", scope=TenantScope.TENANT),
    ]

    await service.broadcast(tenants, ChatMessage(text="broadcast"))

    assert [call[0] for call in calls] == [
        "https://hooks.slack.com/services/default",
        "https://hooks.slack.com/services/default",
    ]
    assert all(payload["text"] == "broadcast" for _, payload in calls)


@pytest.mark.asyncio
async def test_chatops_minimal_payload() -> None:
    recorded: list[dict[str, Any]] = []

    def transport(config: SlackWebhookConfig, payload: bytes, headers: dict[str, str]) -> None:
        recorded.append(json_decode(payload))

    config = ChatOpsConfig(enabled=True, default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default"))
    service = ChatOpsService(config, transport=transport)
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)

    await service.send(tenant, ChatMessage(text="minimal"))

    assert recorded == [{"text": "minimal"}]


@pytest.mark.asyncio
async def test_default_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, float, dict[str, str]]] = []

    class DummyResponse:
        def __init__(self, status: int) -> None:
            self.status = status

        def getcode(self) -> int:
            return self.status

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_urlopen(request, timeout: float) -> DummyResponse:
        captured.append((request.full_url, timeout, dict(request.headers)))
        return DummyResponse(status=202)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    config = SlackWebhookConfig(
        webhook_url="https://hooks.slack.com/services/default",
        default_channel="#general",
        timeout=3.0,
    )

    await _default_transport(config, b"{}", {"content-type": "application/json"})

    assert len(captured) == 1
    url, timeout, headers = captured[0]
    assert url == "https://hooks.slack.com/services/default"
    assert timeout == 3.0
    assert {k.lower(): v for k, v in headers.items()} == {"content-type": "application/json"}


@pytest.mark.asyncio
async def test_default_transport_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyResponse:
        def __init__(self, status: int) -> None:
            self.status = status

        def getcode(self) -> int:
            return self.status

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def fake_urlopen(request, timeout: float) -> DummyResponse:
        return DummyResponse(status=503)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    config = SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/default", timeout=1.0)

    with pytest.raises(ChatOpsError):
        await _default_transport(config, b"{}", {})
