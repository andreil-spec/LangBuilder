"""OpenAPI schemas and documentation for RBAC API endpoints."""

from typing import Any

# Common error responses used across all RBAC endpoints
COMMON_RESPONSES: dict[int, dict[str, Any]] = {
    401: {
        "description": "Unauthorized - Invalid or missing authentication",
        "content": {
            "application/json": {
                "example": {
                    "detail": "Could not validate credentials"
                }
            }
        }
    },
    403: {
        "description": "Forbidden - Insufficient permissions",
        "content": {
            "application/json": {
                "example": {
                    "detail": "Insufficient permissions to perform this action"
                }
            }
        }
    },
    404: {
        "description": "Not Found - Resource does not exist",
        "content": {
            "application/json": {
                "example": {
                    "detail": "Resource not found"
                }
            }
        }
    },
    422: {
        "description": "Validation Error - Invalid request data",
        "content": {
            "application/json": {
                "example": {
                    "detail": [
                        {
                            "loc": ["body", "name"],
                            "msg": "field required",
                            "type": "value_error.missing"
                        }
                    ]
                }
            }
        }
    },
    500: {
        "description": "Internal Server Error - Unexpected server error",
        "content": {
            "application/json": {
                "example": {
                    "detail": "Internal server error"
                }
            }
        }
    }
}

# Permission check response schemas
PERMISSION_CHECK_RESPONSES = {
    200: {
        "description": "Permission check result",
        "content": {
            "application/json": {
                "example": {
                    "allowed": True,
                    "reason": "User has direct permission",
                    "source": "role_assignment",
                    "cached": False,
                    "evaluated_at": "2024-01-15T10:30:00Z"
                }
            }
        }
    }
}

# Batch permission check response schemas
BATCH_PERMISSION_CHECK_RESPONSES = {
    200: {
        "description": "Batch permission check results",
        "content": {
            "application/json": {
                "example": [
                    {
                        "allowed": True,
                        "reason": "User has workspace access",
                        "source": "role_assignment",
                        "cached": False,
                        "evaluated_at": "2024-01-15T10:30:00Z"
                    },
                    {
                        "allowed": False,
                        "reason": "User lacks project permissions",
                        "source": "default_deny",
                        "cached": True,
                        "evaluated_at": "2024-01-15T10:29:45Z"
                    }
                ]
            }
        }
    }
}

# Workspace examples
WORKSPACE_EXAMPLES = {
    "create_workspace": {
        "summary": "Create a development workspace",
        "description": "Example of creating a new workspace for development",
        "value": {
            "name": "Development Team",
            "description": "Workspace for the development team to collaborate on projects",
            "organization": "Acme Corp",
            "settings": {
                "default_project_visibility": "private",
                "allow_external_collaborators": False
            }
        }
    },
    "workspace_response": {
        "summary": "Workspace details",
        "description": "Example workspace response with full details",
        "value": {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Development Team",
            "description": "Workspace for the development team",
            "organization": "Acme Corp",
            "owner_id": "987fcdeb-51a2-43d7-8f9e-123456789abc",
            "is_active": True,
            "is_deleted": False,
            "created_at": "2024-01-15T09:00:00Z",
            "updated_at": "2024-01-15T09:00:00Z",
            "settings": {
                "default_project_visibility": "private",
                "allow_external_collaborators": False
            }
        }
    }
}

# Project examples
PROJECT_EXAMPLES = {
    "create_project": {
        "summary": "Create a machine learning project",
        "description": "Example of creating a new ML project within a workspace",
        "value": {
            "name": "Customer Segmentation ML",
            "description": "Machine learning project for customer segmentation analysis",
            "workspace_id": "123e4567-e89b-12d3-a456-426614174000",
            "tags": ["ml", "customer-analysis", "segmentation"],
            "settings": {
                "auto_deploy": True,
                "environment": "development"
            }
        }
    },
    "project_response": {
        "summary": "Project details",
        "description": "Example project response with statistics",
        "value": {
            "id": "456e7890-e89b-12d3-a456-426614174111",
            "name": "Customer Segmentation ML",
            "description": "Machine learning project for customer segmentation",
            "workspace_id": "123e4567-e89b-12d3-a456-426614174000",
            "owner_id": "987fcdeb-51a2-43d7-8f9e-123456789abc",
            "is_active": True,
            "is_archived": False,
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:30:00Z",
            "tags": ["ml", "customer-analysis"],
            "flow_count": 5,
            "environment_count": 2,
            "last_deployment": "2024-01-15T09:45:00Z"
        }
    }
}

# Role examples
ROLE_EXAMPLES = {
    "create_role": {
        "summary": "Create a project contributor role",
        "description": "Example of creating a custom role for project contributors",
        "value": {
            "name": "Project Contributor",
            "description": "Can view and edit project content but cannot manage settings",
            "workspace_id": "123e4567-e89b-12d3-a456-426614174000",
            "type": "custom",
            "permissions": [
                "project:read",
                "project:update",
                "flow:create",
                "flow:read",
                "flow:update"
            ]
        }
    },
    "role_response": {
        "summary": "Role details",
        "description": "Example role response with permissions",
        "value": {
            "id": "789e1234-e89b-12d3-a456-426614174222",
            "name": "Project Contributor",
            "description": "Can view and edit project content",
            "workspace_id": "123e4567-e89b-12d3-a456-426614174000",
            "type": "custom",
            "is_system": False,
            "is_active": True,
            "created_by_id": "987fcdeb-51a2-43d7-8f9e-123456789abc",
            "created_at": "2024-01-15T11:00:00Z",
            "updated_at": "2024-01-15T11:00:00Z",
            "version": 1,
            "permission_count": 5
        }
    }
}

# Permission examples
PERMISSION_EXAMPLES = {
    "permission_check": {
        "summary": "Check workspace read permission",
        "description": "Example of checking if user can read a workspace",
        "value": {
            "resource_type": "workspace",
            "action": "read",
            "resource_id": "123e4567-e89b-12d3-a456-426614174000",
            "workspace_id": "123e4567-e89b-12d3-a456-426614174000"
        }
    },
    "batch_permission_check": {
        "summary": "Check multiple permissions at once",
        "description": "Example of batch checking various permissions for efficiency",
        "value": [
            {
                "resource_type": "workspace",
                "action": "read",
                "workspace_id": "123e4567-e89b-12d3-a456-426614174000"
            },
            {
                "resource_type": "project",
                "action": "create",
                "workspace_id": "123e4567-e89b-12d3-a456-426614174000"
            },
            {
                "resource_type": "environment",
                "action": "deploy",
                "workspace_id": "123e4567-e89b-12d3-a456-426614174000",
                "project_id": "456e7890-e89b-12d3-a456-426614174111"
            }
        ]
    }
}

# API tag descriptions for OpenAPI documentation
API_TAGS = [
    {
        "name": "RBAC",
        "description": "Role-Based Access Control system for managing permissions and access to resources"
    },
    {
        "name": "Workspaces",
        "description": "Workspace management - top-level containers for organizing projects and teams"
    },
    {
        "name": "Projects",
        "description": "Project management - containers for flows, environments and deployments within workspaces"
    },
    {
        "name": "Roles",
        "description": "Role management - define sets of permissions that can be assigned to users and groups"
    },
    {
        "name": "Permissions",
        "description": "Permission management - check and validate user access to specific resources and actions"
    }
]

# API description for the RBAC system
RBAC_API_DESCRIPTION = """
## LangBuilder RBAC API

The Role-Based Access Control (RBAC) API provides comprehensive access management for LangBuilder resources.

### Key Features

- **Multi-tenant Workspaces**: Isolated environments for different teams and organizations
- **Hierarchical Permissions**: Inheritance from workspace → project → environment → flow levels
- **High-Performance Caching**: Sub-100ms permission checks with Redis caching
- **Flexible Role System**: Custom roles and system-defined roles with granular permissions
- **Audit Trail**: Complete audit logging of all permission changes and access attempts

### Resource Hierarchy

```
Workspace (top-level)
├── Projects
│   ├── Environments
│   │   └── Deployments
│   └── Flows
├── Roles (workspace-scoped)
└── User Groups
```

### Permission Model

Permissions follow the format `resource:action` (e.g., `workspace:read`, `project:create`, `flow:deploy`).

Common actions:
- `read` - View resource details
- `create` - Create new resources
- `update` - Modify existing resources
- `delete` - Remove resources
- `manage` - Full administrative access

### Authentication

All endpoints require authentication via:
- Bearer token in `Authorization` header
- API key in `X-API-Key` header (for service accounts)

### Rate Limiting

- Standard endpoints: 1000 requests/minute per user
- Permission check endpoints: 10000 requests/minute per user (optimized for high frequency)
- Batch operations: 100 requests/minute per user

### Error Handling

The API uses standard HTTP status codes and returns detailed error information:

- `400` - Bad Request (validation errors)
- `401` - Unauthorized (authentication required)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found (resource doesn't exist)
- `422` - Validation Error (invalid data format)
- `429` - Too Many Requests (rate limit exceeded)
- `500` - Internal Server Error (unexpected error)
"""
