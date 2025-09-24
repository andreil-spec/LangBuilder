"""RBAC API module - Unified router for all RBAC endpoints."""

from fastapi import APIRouter

from .permissions import router as permissions_router
from .projects import router as projects_router
from .roles import router as roles_router
from .unified_projects import router as unified_projects_router
from .workspaces import router as workspaces_router

# Simple routers are disabled - they bypass authentication
# Only use for development/debugging when needed
# from .simple_roles import simple_router as simple_roles_router
# from .simple_service_accounts import simple_router as simple_service_accounts_router
# from .simple_environments import simple_router as simple_environments_router
# from .simple_projects import simple_router as simple_projects_router
# from .simple_workspaces import simple_router as simple_workspaces_router

# Import additional routers that need to be created
try:
    from .service_accounts import router as service_accounts_router
    HAS_SERVICE_ACCOUNTS = True
except ImportError:
    HAS_SERVICE_ACCOUNTS = False

try:
    from .environments import router as environments_router
    HAS_ENVIRONMENTS = True
except ImportError:
    HAS_ENVIRONMENTS = False

try:
    from .audit import router as audit_router
    HAS_AUDIT = True
except ImportError:
    HAS_AUDIT = False

try:
    from .user_groups import router as user_groups_router
    HAS_USER_GROUPS = True
except ImportError:
    HAS_USER_GROUPS = False

try:
    from .role_assignments import router as role_assignments_router
    HAS_ROLE_ASSIGNMENTS = True
except ImportError:
    HAS_ROLE_ASSIGNMENTS = False
except Exception as e:
    # Log role_assignments import issues
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import role_assignments router: {e}")
    HAS_ROLE_ASSIGNMENTS = False

# Main RBAC router with unified prefix
rbac_router = APIRouter(
    prefix="/rbac",
    tags=["RBAC"],
    responses={
        401: {"description": "Unauthorized - Invalid or missing authentication"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Not Found - Resource does not exist"},
        422: {"description": "Validation Error - Invalid request data"},
    },
)

# Include all RBAC sub-routers (with proper authentication)
rbac_router.include_router(workspaces_router)
rbac_router.include_router(projects_router)
rbac_router.include_router(roles_router)
rbac_router.include_router(unified_projects_router)
rbac_router.include_router(permissions_router)

# Simple routers are disabled - they bypass authentication
# rbac_router.include_router(simple_roles_router)
# rbac_router.include_router(simple_service_accounts_router)
# rbac_router.include_router(simple_environments_router)
# rbac_router.include_router(simple_projects_router)
# rbac_router.include_router(simple_workspaces_router)

# Include optional routers if available
if HAS_SERVICE_ACCOUNTS:
    rbac_router.include_router(service_accounts_router)
if HAS_ENVIRONMENTS:
    rbac_router.include_router(environments_router)
if HAS_AUDIT:
    rbac_router.include_router(audit_router)
if HAS_USER_GROUPS:
    rbac_router.include_router(user_groups_router)
if HAS_ROLE_ASSIGNMENTS:
    rbac_router.include_router(role_assignments_router)

# Export the main router and individual routers for backwards compatibility
__all__ = [
    "permissions_router",
    "projects_router",
    "rbac_router",
    "roles_router",
    "workspaces_router",
]
