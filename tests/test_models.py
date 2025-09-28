from mere import (
    BillingRecord,
    BillingStatus,
    TenantUser,
    default_registry,
)


def test_model_registry_metadata() -> None:
    registry = default_registry()
    billing = registry.info_for(BillingRecord)
    assert billing.scope == "admin"
    assert billing.table == "billing"
    assert "plan_code" in billing.field_map
    assert billing.field_map["status"].python_type is BillingStatus

    tenant = registry.info_for(TenantUser)
    assert tenant.scope == "tenant"
    assert tenant.table == "users"
    assert registry.get_by_accessor("tenant", "users") is tenant
