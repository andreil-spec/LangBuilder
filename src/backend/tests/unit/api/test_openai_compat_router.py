from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from langbuilder.api.openai_compat_router import (
    _apply_rbac,
    _ensure_flow_group_access,
    _extract_required_groups,
    _resolve_current_user,
)
from langbuilder.services.auth.oidc import AuthenticatedCaller
from langbuilder.services.database.models.flow.model import AccessTypeEnum
from langbuilder.services.database.models.user.model import UserRead


class _DummySettings:
    def __init__(self, *, oidc_enabled: bool, prefix: str = "group:"):
        self.auth_settings = SimpleNamespace(
            OIDC_ENABLED=oidc_enabled,
            OIDC_RBAC_TAG_PREFIX=prefix,
        )


@pytest.mark.anyio
async def test_resolve_current_user_requires_auth(monkeypatch):
    monkeypatch.setattr(
        "langbuilder.api.openai_compat_router.get_settings_service",
        lambda: _DummySettings(oidc_enabled=True),
    )

    with pytest.raises(HTTPException) as exc:
        await _resolve_current_user(authorization=None, query_key=None, header_key=None)

    assert exc.value.status_code == 401
    assert "Missing" in exc.value.detail


@pytest.mark.anyio
async def test_resolve_current_user_api_key_fallback(monkeypatch):
    user = UserRead(
        id=uuid4(),
        username="apitester",
        profile_image=None,
        store_api_key=None,
        is_active=True,
        is_superuser=False,
        create_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        last_login_at=None,
        optins=None,
    )

    async def mock_api_key_security(_query_param, header_param):
        assert header_param == "APIKEY"
        return user

    monkeypatch.setattr(
        "langbuilder.api.openai_compat_router.api_key_security",
        mock_api_key_security,
    )
    monkeypatch.setattr(
        "langbuilder.api.openai_compat_router.get_settings_service",
        lambda: _DummySettings(oidc_enabled=False),
    )

    caller = await _resolve_current_user(authorization="Bearer APIKEY")
    assert caller.source == "api_key"
    assert caller.id == user.id
    assert caller.user == user


def test_extract_required_groups():
    result = _extract_required_groups(["group:Admin", "other"], "group:")
    assert result == {"admin"}
    assert _extract_required_groups(None, "group:") == set()


def test_apply_rbac_filters(monkeypatch):
    monkeypatch.setattr(
        "langbuilder.api.openai_compat_router.get_settings_service",
        lambda: _DummySettings(oidc_enabled=True),
    )

    flows = [
        SimpleNamespace(tags=["group:admin"], access_type=AccessTypeEnum.PUBLIC),
        SimpleNamespace(tags=["group:builder"], access_type=AccessTypeEnum.PUBLIC),
        SimpleNamespace(tags=None, access_type=AccessTypeEnum.PUBLIC),
    ]
    user = AuthenticatedCaller(
        id=None,
        username="bob",
        groups={"admin"},
        roles=set(),
        source="oidc",
    )

    filtered = _apply_rbac(flows, user)
    assert len(filtered) == 2
    assert filtered[0].tags == ["group:admin"]
    assert filtered[1].tags is None


def test_apply_rbac_skipped_for_api_key(monkeypatch):
    monkeypatch.setattr(
        "langbuilder.api.openai_compat_router.get_settings_service",
        lambda: _DummySettings(oidc_enabled=True),
    )
    flows = [SimpleNamespace(tags=["group:admin"], access_type=AccessTypeEnum.PUBLIC)]
    user = AuthenticatedCaller(
        id=None,
        username="service",
        groups=set(),
        roles=set(),
        source="api_key",
    )
    assert _apply_rbac(flows, user) == flows


def test_ensure_flow_group_access_enforces(monkeypatch):
    monkeypatch.setattr(
        "langbuilder.api.openai_compat_router.get_settings_service",
        lambda: _DummySettings(oidc_enabled=True),
    )
    flow = SimpleNamespace(tags=["group:builder"])
    user = AuthenticatedCaller(
        id=None,
        username="alice",
        groups=set(),
        roles=set(),
        source="oidc",
    )
    with pytest.raises(HTTPException) as exc:
        _ensure_flow_group_access(flow, user)
    assert exc.value.status_code == 403
