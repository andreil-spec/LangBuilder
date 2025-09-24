"""Infrastructure-as-Code API endpoints for RBAC policy management.

This module provides REST API endpoints for exporting, importing, and managing
RBAC policies as YAML/JSON configurations and Terraform resources.
"""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from langflow.api.utils import CurrentActiveUser, DbSession
from langflow.services.database.models.user.model import User
from langflow.api.v1.rbac.security_middleware import (
    SecurityRequirement,
    ValidationRequirement,
    get_authenticated_user,
    secure_endpoint,
)
from langflow.services.auth.authorization_patterns import get_enhanced_enforcement_context
from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext
from langflow.services.rbac.iac_service import IaCImportResult, RBACIaCService, RBACPolicy

router = APIRouter(
    prefix="/iac",
    tags=["RBAC", "Infrastructure-as-Code"],
    responses={
        400: {"description": "Bad Request - Invalid IaC configuration"},
        401: {"description": "Unauthorized - Authentication required"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Not Found - Resource not found"},
        422: {"description": "Unprocessable Entity - Invalid configuration format"},
        500: {"description": "Internal Server Error - IaC processing failed"},
    },
)


class ExportRequest(BaseModel):
    """Request for exporting RBAC configuration."""

    format: str = Field(default="yaml", description="Export format (yaml, json, terraform)")
    include_system: bool = Field(default=False, description="Include system roles and permissions")
    scope: str = Field(default="workspace", description="Export scope (workspace, global)")


class ImportRequest(BaseModel):
    """Request for importing RBAC configuration."""

    config: str | dict[str, Any] = Field(description="RBAC configuration")
    format: str = Field(default="yaml", description="Configuration format (yaml, json)")
    dry_run: bool = Field(default=False, description="Perform validation only")
    workspace_id: str | None = Field(default=None, description="Target workspace ID")


class ValidationResult(BaseModel):
    """Result of configuration validation."""

    valid: bool = Field(description="Whether the configuration is valid")
    errors: list[str] = Field(default_factory=list, description="Validation errors")
    warnings: list[str] = Field(default_factory=list, description="Validation warnings")


class TemplateRequest(BaseModel):
    """Request for generating configuration templates."""

    template_type: str = Field(description="Template type (basic, advanced, enterprise)")
    workspace_name: str = Field(description="Workspace name")
    include_examples: bool = Field(default=True, description="Include example data")


@router.get("/export/workspace/{workspace_id}")
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="export",
        require_workspace_access=True,
        audit_action="export_infrastructure",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def export_workspace_config(
    request: Request,
    workspace_id: UUID,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    format: str = "yaml",
    include_system: bool = False,
) -> dict[str, Any] | PlainTextResponse:
    """Export RBAC configuration for a specific workspace."""
    try:
        # Check permissions
        # TODO: Add permission check for workspace access

        iac_service = RBACIaCService()
        policy = await iac_service.export_workspace_config(
            session=session,
            workspace_id=workspace_id,
            include_system=include_system
        )

        if format.lower() == "json":
            return policy.model_dump(exclude_none=True)
        if format.lower() == "terraform":
            terraform_config = iac_service.generate_terraform_config(policy)
            return PlainTextResponse(
                content=terraform_config,
                media_type="text/plain",
                headers={"Content-Disposition": f"attachment; filename=workspace-{workspace_id}.tf"}
            )
        # Default to YAML
        yaml_config = iac_service.export_to_yaml(policy)
        return PlainTextResponse(
            content=yaml_config,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=workspace-{workspace_id}.yaml"}
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Export failed: {e!s}"
        )


@router.get("/export/global")
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="export",
        require_workspace_access=False,
        audit_action="export_global_infrastructure",
    ),
    validation_req=None,
    audit_enabled=True,
)
async def export_global_config(
    request: Request,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    format: str = "yaml",
    include_system: bool = True,
) -> dict[str, Any] | PlainTextResponse:
    """Export global RBAC configuration."""
    try:
        # Check global admin permissions
        # TODO: Add permission check for global configuration access

        iac_service = RBACIaCService()
        policy = await iac_service.export_global_config(
            session=session,
            include_system=include_system
        )

        if format.lower() == "json":
            return policy.model_dump(exclude_none=True)
        if format.lower() == "terraform":
            terraform_config = iac_service.generate_terraform_config(policy)
            return PlainTextResponse(
                content=terraform_config,
                media_type="text/plain",
                headers={"Content-Disposition": "attachment; filename=global-rbac.tf"}
            )
        # Default to YAML
        yaml_config = iac_service.export_to_yaml(policy)
        return PlainTextResponse(
            content=yaml_config,
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=global-rbac.yaml"}
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Export failed: {e!s}"
        )


@router.post("/validate")
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="read",
        require_workspace_access=False,
        audit_action="validate_infrastructure",
    ),
    validation_req=None,
    audit_enabled=True,
)
async def validate_config(
    request: Request,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    config: str = Form(..., description="RBAC configuration to validate"),
    format: str = Form(default="yaml", description="Configuration format"),
) -> ValidationResult:
    """Validate RBAC configuration without importing."""
    try:
        iac_service = RBACIaCService()
        is_valid, errors = await iac_service.validate_config(config)

        return ValidationResult(
            valid=is_valid,
            errors=errors,
            warnings=[]  # TODO: Add warning detection
        )

    except Exception as e:
        return ValidationResult(
            valid=False,
            errors=[f"Validation failed: {e!s}"],
            warnings=[]
        )


@router.post("/import/preview")
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="read",
        require_workspace_access=True,
        audit_action="preview_import_infrastructure",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def preview_import(
    request: Request,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    config: str = Form(..., description="RBAC configuration to preview"),
    workspace_id: str | None = Form(default=None, description="Target workspace ID"),
    format: str = Form(default="yaml", description="Configuration format"),
) -> dict[str, Any]:
    """Preview changes that would be made by importing configuration."""
    try:
        # Check permissions
        # TODO: Add permission check for import preview

        workspace_uuid = UUID(workspace_id) if workspace_id else None

        iac_service = RBACIaCService()
        preview = await iac_service.preview_import(
            session=session,
            config=config,
            workspace_id=workspace_uuid
        )

        return preview

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid configuration: {e!s}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Preview failed: {e!s}"
        )


@router.post("/import/apply")
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="update",
        require_workspace_access=True,
        audit_action="apply_infrastructure",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def apply_import(
    request: Request,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    config: str = Form(..., description="RBAC configuration to import"),
    workspace_id: str | None = Form(default=None, description="Target workspace ID"),
    dry_run: bool = Form(default=False, description="Perform dry run only"),
    format: str = Form(default="yaml", description="Configuration format"),
) -> IaCImportResult:
    """Import RBAC configuration."""
    try:
        # Check permissions
        # TODO: Add permission check for import operations

        workspace_uuid = UUID(workspace_id) if workspace_id else None

        iac_service = RBACIaCService()
        result = await iac_service.import_config(
            session=session,
            config=config,
            workspace_id=workspace_uuid,
            dry_run=dry_run
        )

        if not result.success and not dry_run:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Import failed: {result.message}"
            )

        return result

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid configuration: {e!s}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Import failed: {e!s}"
        )


@router.post("/import/file")
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="update",
        require_workspace_access=True,
        audit_action="import_file_infrastructure",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def import_from_file(
    request: Request,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    file: UploadFile = File(..., description="RBAC configuration file"),
    workspace_id: str | None = Form(default=None, description="Target workspace ID"),
    dry_run: bool = Form(default=False, description="Perform dry run only"),
) -> IaCImportResult:
    """Import RBAC configuration from uploaded file."""
    try:
        # Check file type
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file provided"
            )

        if not any(file.filename.endswith(ext) for ext in [".yaml", ".yml", ".json"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only YAML (.yaml, .yml) and JSON (.json) files are supported"
            )

        # Read file content
        content = await file.read()
        config_str = content.decode("utf-8")

        # Check permissions
        # TODO: Add permission check for import operations

        workspace_uuid = UUID(workspace_id) if workspace_id else None

        iac_service = RBACIaCService()
        result = await iac_service.import_config(
            session=session,
            config=config_str,
            workspace_id=workspace_uuid,
            dry_run=dry_run
        )

        if not result.success and not dry_run:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Import failed: {result.message}"
            )

        return result

    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be valid UTF-8 text"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File import failed: {e!s}"
        )


@router.get("/templates")
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="read",
        require_workspace_access=False,
        audit_action="list_templates",
    ),
    validation_req=None,
    audit_enabled=True,
)
async def list_templates(
    request: Request,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
) -> list[dict[str, Any]]:
    """List available RBAC configuration templates."""
    return [
        {
            "name": "basic-workspace",
            "title": "Basic Workspace RBAC",
            "description": "Simple role-based access control for a workspace",
            "roles": ["viewer", "editor", "admin"],
            "use_cases": ["Small teams", "Simple projects"]
        },
        {
            "name": "advanced-workspace",
            "title": "Advanced Workspace RBAC",
            "description": "Comprehensive RBAC with project and environment scoping",
            "roles": ["viewer", "developer", "maintainer", "admin"],
            "use_cases": ["Medium teams", "Multi-project workspaces"]
        },
        {
            "name": "enterprise-workspace",
            "title": "Enterprise Workspace RBAC",
            "description": "Full-featured RBAC with compliance and governance",
            "roles": ["guest", "analyst", "developer", "lead", "manager", "admin"],
            "use_cases": ["Large enterprises", "Compliance requirements", "Complex hierarchies"]
        },
        {
            "name": "service-account-template",
            "title": "Service Account Configuration",
            "description": "Template for service account and API access configuration",
            "roles": ["api-reader", "api-writer", "automation"],
            "use_cases": ["CI/CD integration", "API access", "Automation"]
        }
    ]


@router.post("/templates/generate")
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="read",
        require_workspace_access=False,
        audit_action="generate_template",
    ),
    validation_req=None,
    audit_enabled=True,
)
async def generate_template(
    http_request: Request,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    request: TemplateRequest,
) -> dict[str, Any] | PlainTextResponse:
    """Generate RBAC configuration template."""
    try:
        templates = {
            "basic": _generate_basic_template,
            "advanced": _generate_advanced_template,
            "enterprise": _generate_enterprise_template,
            "service-account": _generate_service_account_template
        }

        if request.template_type not in templates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown template type: {request.template_type}"
            )

        template_func = templates[request.template_type]
        policy = template_func(request.workspace_name, request.include_examples)

        iac_service = RBACIaCService()
        yaml_config = iac_service.export_to_yaml(policy)

        return PlainTextResponse(
            content=yaml_config,
            media_type="text/plain",
            headers={
                "Content-Disposition": f"attachment; filename={request.template_type}-{request.workspace_name}.yaml"
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Template generation failed: {e!s}"
        )


def _generate_basic_template(workspace_name: str, include_examples: bool) -> RBACPolicy:
    """Generate basic workspace template."""
    from langflow.services.rbac.iac_service import (
        RBACAssignmentSpec,
        RBACMetadata,
        RBACPermissionSpec,
        RBACPolicy,
        RBACPolicySpec,
        RBACRoleSpec,
    )

    metadata = RBACMetadata(
        name=f"{workspace_name}-basic-rbac",
        workspace=workspace_name,
        description=f"Basic RBAC configuration for {workspace_name} workspace",
        labels={"template": "basic", "generated": "true"}
    )

    # Basic permissions
    permissions = [
        RBACPermissionSpec(
            name="flow:read",
            description="Read flows",
            resource_type="flow",
            action="read"
        ),
        RBACPermissionSpec(
            name="flow:write",
            description="Create and modify flows",
            resource_type="flow",
            action="write"
        ),
        RBACPermissionSpec(
            name="flow:execute",
            description="Execute flows",
            resource_type="flow",
            action="execute"
        ),
        RBACPermissionSpec(
            name="workspace:admin",
            description="Administer workspace",
            resource_type="workspace",
            action="admin"
        )
    ]

    # Basic roles
    roles = [
        RBACRoleSpec(
            name="viewer",
            description="Can view flows and results",
            permissions=["flow:read"],
            priority=100
        ),
        RBACRoleSpec(
            name="editor",
            description="Can create and modify flows",
            permissions=["flow:read", "flow:write", "flow:execute"],
            priority=200
        ),
        RBACRoleSpec(
            name="admin",
            description="Full workspace administration",
            permissions=["flow:read", "flow:write", "flow:execute", "workspace:admin"],
            priority=300
        )
    ]

    # Example assignments
    assignments = []
    if include_examples:
        assignments = [
            RBACAssignmentSpec(
                user="admin@example.com",
                roles=["admin"],
                scope_type="workspace"
            ),
            RBACAssignmentSpec(
                user="developer@example.com",
                roles=["editor"],
                scope_type="workspace"
            ),
            RBACAssignmentSpec(
                user="analyst@example.com",
                roles=["viewer"],
                scope_type="workspace"
            )
        ]

    spec = RBACPolicySpec(
        roles=roles,
        permissions=permissions,
        assignments=assignments
    )

    return RBACPolicy(metadata=metadata, spec=spec)


def _generate_advanced_template(workspace_name: str, include_examples: bool) -> RBACPolicy:
    """Generate advanced workspace template with project scoping."""
    from langflow.services.rbac.iac_service import (
        RBACAssignmentSpec,
        RBACMetadata,
        RBACPermissionSpec,
        RBACPolicy,
        RBACPolicySpec,
        RBACRoleSpec,
        RBACUserGroupSpec,
    )

    metadata = RBACMetadata(
        name=f"{workspace_name}-advanced-rbac",
        workspace=workspace_name,
        description=f"Advanced RBAC configuration for {workspace_name} workspace with project scoping",
        labels={"template": "advanced", "generated": "true"}
    )

    # Advanced permissions with project scoping
    permissions = [
        RBACPermissionSpec(name="flow:read", resource_type="flow", action="read"),
        RBACPermissionSpec(name="flow:write", resource_type="flow", action="write"),
        RBACPermissionSpec(name="flow:execute", resource_type="flow", action="execute"),
        RBACPermissionSpec(name="flow:deploy", resource_type="flow", action="deploy"),
        RBACPermissionSpec(name="project:read", resource_type="project", action="read"),
        RBACPermissionSpec(name="project:write", resource_type="project", action="write"),
        RBACPermissionSpec(name="project:admin", resource_type="project", action="admin"),
        RBACPermissionSpec(name="environment:read", resource_type="environment", action="read"),
        RBACPermissionSpec(name="environment:write", resource_type="environment", action="write"),
        RBACPermissionSpec(name="workspace:admin", resource_type="workspace", action="admin")
    ]

    # Advanced roles with hierarchy
    roles = [
        RBACRoleSpec(
            name="viewer",
            description="Can view flows and projects",
            permissions=["flow:read", "project:read", "environment:read"],
            priority=100
        ),
        RBACRoleSpec(
            name="developer",
            description="Can develop and test flows",
            permissions=["flow:read", "flow:write", "flow:execute", "project:read", "environment:read"],
            priority=200
        ),
        RBACRoleSpec(
            name="maintainer",
            description="Can deploy and manage project resources",
            permissions=[
                "flow:read", "flow:write", "flow:execute", "flow:deploy",
                "project:read", "project:write", "environment:read", "environment:write"
            ],
            priority=250
        ),
        RBACRoleSpec(
            name="admin",
            description="Full workspace administration",
            permissions=[
                "flow:read", "flow:write", "flow:execute", "flow:deploy",
                "project:read", "project:write", "project:admin",
                "environment:read", "environment:write",
                "workspace:admin"
            ],
            priority=300
        )
    ]

    # User groups
    groups = []
    assignments = []

    if include_examples:
        groups = [
            RBACUserGroupSpec(
                name="data-science-team",
                description="Data science team members",
                members=["alice@example.com", "bob@example.com"],
                auto_assign_roles=["developer"]
            ),
            RBACUserGroupSpec(
                name="ml-engineers",
                description="ML engineering team",
                members=["charlie@example.com", "diana@example.com"],
                auto_assign_roles=["maintainer"]
            )
        ]

        assignments = [
            RBACAssignmentSpec(
                user="admin@example.com",
                roles=["admin"],
                scope_type="workspace"
            ),
            RBACAssignmentSpec(
                group="data-science-team",
                roles=["developer"],
                scope_type="project",
                scope_id="ml-experiments"
            ),
            RBACAssignmentSpec(
                group="ml-engineers",
                roles=["maintainer"],
                scope_type="project",
                scope_id="production-models"
            )
        ]

    spec = RBACPolicySpec(
        roles=roles,
        permissions=permissions,
        assignments=assignments,
        groups=groups
    )

    return RBACPolicy(metadata=metadata, spec=spec)


def _generate_enterprise_template(workspace_name: str, include_examples: bool) -> RBACPolicy:
    """Generate enterprise template with compliance features."""
    # Implementation for enterprise template with governance, compliance, and audit features
    return _generate_advanced_template(workspace_name, include_examples)  # Placeholder


def _generate_service_account_template(workspace_name: str, include_examples: bool) -> RBACPolicy:
    """Generate service account template for API access."""
    # Implementation for service account template
    return _generate_basic_template(workspace_name, include_examples)  # Placeholder
