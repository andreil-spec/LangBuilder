# Router for base api
# Force reload after removing duplicate RBAC routers
from fastapi import APIRouter

from langflow.api.v1 import (
    api_key_router,
    chat_router,
    endpoints_router,
    files_router,
    flows_router,
    folders_router,
    login_router,
    mcp_projects_router,
    mcp_router,
    monitor_router,
    permissions_router,
    projects_router,
    rbac_projects_router,
    rbac_router,
    roles_router,
    starter_projects_router,
    store_router,
    users_router,
    validate_router,
    variables_router,
    workspaces_router,
)
from langflow.api.v1.scim import router as scim_router
from langflow.api.v1.voice_mode import router as voice_mode_router
from langflow.api.v2 import files_router as files_router_v2
from langflow.api.v2 import mcp_router as mcp_router_v2

router_v1 = APIRouter(
    prefix="/v1",
)

router_v2 = APIRouter(
    prefix="/v2",
)

router_v1.include_router(chat_router)
router_v1.include_router(endpoints_router)
router_v1.include_router(validate_router)
router_v1.include_router(store_router)
router_v1.include_router(flows_router)
router_v1.include_router(users_router)
router_v1.include_router(api_key_router)
router_v1.include_router(login_router)
router_v1.include_router(variables_router)
router_v1.include_router(files_router)
router_v1.include_router(monitor_router)
router_v1.include_router(folders_router)
router_v1.include_router(projects_router)
router_v1.include_router(starter_projects_router)
router_v1.include_router(mcp_router)
router_v1.include_router(voice_mode_router)
router_v1.include_router(mcp_projects_router)
# SCIM provisioning endpoints
router_v1.include_router(scim_router)
# Unified RBAC router (includes all RBAC endpoints under /rbac prefix)
router_v1.include_router(rbac_router)
# Individual RBAC routers removed to prevent duplicate route registrations
# The rbac_router above already includes all RBAC endpoints:
# - rbac_projects_router (as projects_router)
# - roles_router
# - permissions_router
# - role_assignments_router
# - workspaces_router

router_v2.include_router(files_router_v2)
router_v2.include_router(mcp_router_v2)

router = APIRouter(
    prefix="/api",
)
router.include_router(router_v1)
router.include_router(router_v2)
