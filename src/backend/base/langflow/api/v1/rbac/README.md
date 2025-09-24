# RBAC API Documentation - Phase 2

This document provides comprehensive documentation for the Role-Based Access Control (RBAC) REST API endpoints implemented in Phase 2 of the LangBuilder RBAC system.

## Overview

The RBAC API provides a complete set of endpoints for managing multi-tenant access control in LangBuilder. The API follows FastAPI patterns and integrates with the existing authentication system.

### Base URL
```
/api/v1/rbac/
```

### Authentication
All endpoints require authentication via the existing LangBuilder authentication system. The current user is automatically injected via the `get_current_active_user` dependency.

### High-Performance Permission Engine
The API integrates with a high-performance permission engine that provides:
- **Sub-100ms p95 latency** for permission checks
- **Redis caching** with intelligent cache invalidation
- **Hierarchical permission resolution** (workspace → project → environment → flow)
- **Comprehensive audit logging**

## API Modules

### 1. Workspace Management (`/workspaces`)

Workspaces are the top-level organization unit in the RBAC hierarchy.

#### Endpoints

##### `POST /api/v1/rbac/workspaces/`
**Create a new workspace**

```json
{
  "name": "My Workspace",
  "description": "A workspace for my team",
  "organization": "ACME Corp",
  "settings": {}
}
```

**Response:** `201 Created`
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My Workspace",
  "description": "A workspace for my team",
  "organization": "ACME Corp",
  "owner_id": "550e8400-e29b-41d4-a716-446655440001",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

##### `GET /api/v1/rbac/workspaces/`
**List accessible workspaces**

**Query Parameters:**
- `skip` (int): Number of records to skip (default: 0)
- `limit` (int): Maximum records to return (default: 100, max: 1000)
- `search` (str): Search in name/description
- `organization` (str): Filter by organization
- `is_active` (bool): Filter by active status

**Response:** `200 OK`
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "My Workspace",
    "description": "A workspace for my team",
    "organization": "ACME Corp",
    "owner_id": "550e8400-e29b-41d4-a716-446655440001",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

##### `GET /api/v1/rbac/workspaces/{workspace_id}`
**Get workspace by ID**

**Response:** `200 OK` - Returns workspace details

##### `PUT /api/v1/rbac/workspaces/{workspace_id}`
**Update workspace**

**Permissions Required:** `workspace:update`

##### `DELETE /api/v1/rbac/workspaces/{workspace_id}`
**Soft delete workspace**

**Permissions Required:** `workspace:delete`

**Response:** `204 No Content`

##### `POST /api/v1/rbac/workspaces/{workspace_id}/invite`
**Invite user to workspace**

**Permissions Required:** `workspace:manage`

```json
{
  "email": "user@example.com",
  "role_id": "550e8400-e29b-41d4-a716-446655440002"
}
```

##### `GET /api/v1/rbac/workspaces/{workspace_id}/users`
**List workspace users and their roles**

**Permissions Required:** `workspace:read`

##### `GET /api/v1/rbac/workspaces/{workspace_id}/projects`
**List projects in workspace**

**Permissions Required:** `workspace:read`

##### `GET /api/v1/rbac/workspaces/{workspace_id}/stats`
**Get workspace statistics**

**Permissions Required:** `workspace:read`

```json
{
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "project_count": 5,
  "user_count": 12,
  "group_count": 3,
  "flow_count": 25,
  "created_at": "2024-01-01T00:00:00Z",
  "last_updated": "2024-01-15T10:30:00Z"
}
```

### 2. Project Management (`/projects`)

Projects organize flows and environments within workspaces.

#### Endpoints

##### `POST /api/v1/rbac/projects/`
**Create a new project**

```json
{
  "name": "ML Pipeline Project",
  "description": "A project for machine learning pipelines",
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "tags": ["ml", "production"],
  "metadata": {}
}
```

##### `GET /api/v1/rbac/projects/`
**List accessible projects**

**Query Parameters:**
- `workspace_id` (UUID): Filter by workspace
- `skip`, `limit`: Pagination
- `search` (str): Search in name/description
- `is_active` (bool): Filter by active status
- `is_archived` (bool): Filter by archived status

##### `GET /api/v1/rbac/projects/{project_id}`
**Get project by ID**

**Permissions Required:** `project:read`

##### `PUT /api/v1/rbac/projects/{project_id}`
**Update project**

**Permissions Required:** `project:update`

##### `DELETE /api/v1/rbac/projects/{project_id}`
**Archive project (soft delete)**

**Permissions Required:** `project:delete`

##### `GET /api/v1/rbac/projects/{project_id}/environments`
**List environments in project**

**Permissions Required:** `project:read`

##### `GET /api/v1/rbac/projects/{project_id}/flows`
**List flows in project**

**Permissions Required:** `project:read`

##### `GET /api/v1/rbac/projects/{project_id}/stats`
**Get project statistics**

**Permissions Required:** `project:read`

```json
{
  "project_id": "550e8400-e29b-41d4-a716-446655440003",
  "total_flows": 10,
  "active_flows": 8,
  "total_environments": 3,
  "active_environments": 2,
  "total_deployments": 25,
  "successful_deployments": 20,
  "failed_deployments": 5,
  "last_deployment_at": "2024-01-15T10:30:00Z"
}
```

### 3. Role Management (`/roles`)

Roles define sets of permissions that can be assigned to users and groups.

#### Endpoints

##### `POST /api/v1/rbac/roles/`
**Create a new role**

```json
{
  "name": "Data Scientist",
  "description": "Role for data scientists with ML pipeline access",
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "custom",
  "permissions": ["flow:read", "flow:execute", "project:read"],
  "parent_role_id": null
}
```

##### `GET /api/v1/rbac/roles/`
**List accessible roles**

**Query Parameters:**
- `workspace_id` (UUID): Filter by workspace
- `skip`, `limit`: Pagination
- `search` (str): Search in name/description
- `type` (str): Filter by role type
- `is_system` (bool): Filter system/custom roles
- `is_active` (bool): Filter by active status

##### `GET /api/v1/rbac/roles/{role_id}`
**Get role by ID**

**Permissions Required:** Role must be accessible to user

##### `PUT /api/v1/rbac/roles/{role_id}`
**Update role**

**Permissions Required:** `role:update` in workspace or superuser for system roles

**Note:** System roles cannot be modified

##### `DELETE /api/v1/rbac/roles/{role_id}`
**Delete role (deactivate)**

**Permissions Required:** `role:delete` in workspace or superuser for system roles

**Note:** System roles cannot be deleted. Roles with active assignments cannot be deleted.

##### `GET /api/v1/rbac/roles/{role_id}/permissions`
**List permissions assigned to role**

##### `POST /api/v1/rbac/roles/{role_id}/permissions`
**Assign permission to role**

```json
{
  "permission_id": "550e8400-e29b-41d4-a716-446655440004",
  "reason": "Required for ML model training workflows"
}
```

##### `DELETE /api/v1/rbac/roles/{role_id}/permissions/{permission_id}`
**Remove permission from role**

##### `POST /api/v1/rbac/roles/initialize-system-roles`
**Initialize system roles and permissions**

**Permissions Required:** Superuser only

### 4. Permission Management (`/permissions`)

Permission endpoints for checking and managing access control.

#### Endpoints

##### `GET /api/v1/rbac/permissions/`
**List available permissions**

**Permissions Required:** Superuser only

**Query Parameters:**
- `skip`, `limit`: Pagination
- `search` (str): Search in name/description/code
- `resource_type` (str): Filter by resource type
- `action` (str): Filter by action

##### `GET /api/v1/rbac/permissions/{permission_id}`
**Get permission by ID**

**Permissions Required:** Superuser only

##### `POST /api/v1/rbac/permissions/check`
**Check if current user has a specific permission**

```json
{
  "resource_type": "flow",
  "action": "execute",
  "resource_id": "550e8400-e29b-41d4-a716-446655440005",
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "project_id": "550e8400-e29b-41d4-a716-446655440003"
}
```

**Response:** `200 OK`
```json
{
  "allowed": true,
  "reason": "User has direct permission through role assignment",
  "source": "role_assignment",
  "cached": true,
  "evaluated_at": "2024-01-15T10:30:00Z"
}
```

##### `POST /api/v1/rbac/permissions/batch-check`
**Check multiple permissions at once**

**Request:** Array of permission check objects (max 50)

**Response:** Array of permission results

##### `POST /api/v1/rbac/permissions/initialize-system-permissions`
**Initialize system permissions**

**Permissions Required:** Superuser only

##### `GET /api/v1/rbac/permissions/resource-types`
**List available resource types**

**Response:** `200 OK`
```json
["workspace", "project", "environment", "flow", "role", "user", "group"]
```

##### `GET /api/v1/rbac/permissions/actions`
**List available actions**

**Query Parameters:**
- `resource_type` (str): Filter actions by resource type

**Response:** `200 OK`
```json
["read", "create", "update", "delete", "execute", "manage"]
```

## Permission System

### Hierarchical Permission Model

The RBAC system implements a hierarchical permission model:

```
Workspace
├── Projects
│   ├── Environments
│   │   └── Flows
│   └── Flows (direct)
└── Roles & Users
```

### Permission Inheritance

- **Workspace permissions** inherit to all projects, environments, and flows within
- **Project permissions** inherit to all environments and flows within the project
- **Environment permissions** inherit to all flows within the environment

### Permission Sources

Permissions are evaluated in the following order:

1. **Superuser Status** - Superusers have all permissions
2. **Direct Ownership** - Resource owners have all permissions on their resources
3. **Role Assignments** - Direct role assignments to users
4. **Group Memberships** - Permissions through group role assignments
5. **Inherited Permissions** - Permissions inherited from parent resources

### Caching Strategy

The permission engine implements intelligent caching:

- **User permission cache** - 15 minutes TTL
- **Role permission cache** - 1 hour TTL
- **System permission cache** - 24 hours TTL
- **Automatic invalidation** on role/permission changes

## Error Responses

All endpoints return standard HTTP error responses:

### 400 Bad Request
```json
{
  "detail": "Validation error message"
}
```

### 401 Unauthorized
```json
{
  "detail": "Authentication required"
}
```

### 403 Forbidden
```json
{
  "detail": "Insufficient permissions: workspace:update. Reason: User not found in workspace roles"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 422 Unprocessable Entity
```json
{
  "detail": [
    {
      "loc": ["body", "name"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

## Rate Limiting

The API implements rate limiting to ensure system stability:

- **General endpoints**: 100 requests/minute per user
- **Permission checks**: 1000 requests/minute per user
- **Batch operations**: 10 requests/minute per user

## Performance Characteristics

- **Permission checks**: <100ms p95 latency
- **CRUD operations**: <500ms p95 latency
- **List operations**: <1s p95 latency (with pagination)
- **Statistics**: <2s p95 latency

## Integration Examples

### FastAPI Route Protection

```python
from langflow.api.v1.rbac.dependencies import check_workspace_permission

@router.get("/my-endpoint")
async def my_endpoint(
    workspace: Workspace = Depends(check_workspace_permission("read")),
    current_user: User = Depends(get_current_user),
):
    # Endpoint logic here
    pass
```

### Permission Checking in Business Logic

```python
from langflow.services.rbac.permission_engine import PermissionEngine

async def my_business_logic(session, user, flow_id):
    permission_engine = PermissionEngine()

    result = await permission_engine.check_permission(
        session=session,
        user=user,
        resource_type="flow",
        action="execute",
        resource_id=flow_id,
    )

    if not result.allowed:
        raise HTTPException(403, detail=f"Access denied: {result.reason}")

    # Continue with business logic
```

## Testing

The API includes comprehensive test coverage:

- **Unit tests** for individual endpoints
- **Integration tests** for permission flows
- **Performance tests** for latency requirements
- **Security tests** for access control validation

Run tests with:
```bash
pytest src/backend/base/langflow/api/v1/rbac/tests/
```

## Migration and Deployment

### Database Migrations

The RBAC system includes Alembic migrations for database schema updates:

```bash
alembic upgrade head
```

### Environment Variables

Required configuration:
```env
RBAC_CACHE_TTL=900  # 15 minutes
RBAC_REDIS_URL=redis://localhost:6379/1
RBAC_AUDIT_ENABLED=true
```

### Initialization

Initialize system roles and permissions:

```bash
curl -X POST http://localhost:7860/api/v1/rbac/roles/initialize-system-roles \
  -H "Authorization: Bearer <superuser-token>"

curl -X POST http://localhost:7860/api/v1/rbac/permissions/initialize-system-permissions \
  -H "Authorization: Bearer <superuser-token>"
```

## Support and Documentation

For additional support:
- **API Reference**: OpenAPI/Swagger documentation available at `/docs`
- **GitHub Issues**: Report bugs and feature requests
- **Development Guide**: See `RBAC_IMPLEMENTATION_PLAN.md`
- **Architecture**: See AppGraph documentation for system design