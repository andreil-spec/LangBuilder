"""Advanced RBAC API endpoints for Phase 5 features.

This module provides API endpoints for advanced RBAC features including:
- Multi-environment permission management
- Service account management with token scoping
- Break-glass emergency access
- Advanced audit logging and compliance reporting
- Conditional permissions management

Implementation follows existing LangBuilder API patterns and includes
comprehensive permission checking and audit logging.
"""

# NO future annotations per Phase 1 requirements
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from loguru import logger
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession

# Import conditional policy schemas
from langflow.api.v1.schemas.conditional_policy_schemas import (
    BulkPolicyOperation,
    ConditionalPolicyCreate,
    ConditionalPolicyRead,
    ConditionalPolicyUpdate,
    PolicyAnalytics,
    PolicyEvaluationRequest,
    PolicyEvaluationResult,
)

# from langflow.api.utils import build_content_type_to_response  # Function doesn't exist
from langflow.services.auth.utils import get_current_active_user
from langflow.services.deps import get_session

# Import advanced features service
from langflow.services.rbac.advanced_features_service import AdvancedRBACFeaturesService, ConditionalPermissionContext
from langflow.services.rbac.conditional_policy_manager import ConditionalPolicyManager
from langflow.services.rbac.dependencies import RBACAdmin, WorkspaceAdmin

router = APIRouter(prefix="/rbac-advanced", tags=["RBAC Advanced Features"])

# Request/Response Models


class EnvironmentPermissionRequest(BaseModel):
    """Request model for environment permission check."""

    environment_id: str = Field(description="Environment ID to check")
    action: str = Field(description="Action to perform (deploy, read, write, delete)")
    context: dict | None = Field(default=None, description="Additional context for conditional permissions")


class EnvironmentPermissionResponse(BaseModel):
    """Response model for environment permission check."""

    granted: bool = Field(description="Whether permission is granted")
    environment_id: str = Field(description="Environment ID")
    action: str = Field(description="Action checked")
    user_id: str = Field(description="User ID")
    evaluation_time_ms: float = Field(description="Time taken for evaluation")


class ServiceAccountCreateRequest(BaseModel):
    """Request model for creating service account with token."""

    workspace_id: str = Field(description="Workspace ID for service account")
    account_name: str = Field(description="Name of the service account")
    token_name: str = Field(description="Name of the token")
    scoped_permissions: list[str] = Field(description="List of permissions for the token")
    scope_type: str = Field(default="workspace", description="Type of scope (workspace, project, environment)")
    scope_id: str | None = Field(default=None, description="ID of the scope entity")
    allowed_ips: list[str] | None = Field(default=None, description="List of allowed IP addresses")
    expires_days: int = Field(default=365, description="Token expiration in days")


class ServiceAccountTokenValidationRequest(BaseModel):
    """Request model for service account token validation."""

    token_hash: str = Field(description="Hashed token value")
    requested_action: str = Field(description="Action being requested")
    resource_type: str = Field(description="Type of resource being accessed")
    resource_id: str | None = Field(default=None, description="ID of specific resource")


class BreakGlassAccessRequest(BaseModel):
    """Request model for break-glass emergency access."""

    justification: str = Field(min_length=20, description="Justification for emergency access")
    emergency_level: str = Field(default="medium", description="Level of emergency (low, medium, high, critical)")
    requested_permissions: list[str] | None = Field(default=None, description="Specific permissions being requested")
    resource_context: dict | None = Field(default=None, description="Context about resources being accessed")


class BreakGlassAccessResponse(BaseModel):
    """Response model for break-glass access evaluation."""

    granted: bool = Field(description="Whether access is granted")
    justification: str = Field(description="Provided justification")
    emergency_level: str = Field(description="Emergency level")
    approval_required: bool = Field(description="Whether additional approval is required")
    approval_timeout_minutes: int = Field(description="Timeout for approval process")
    evaluation_time_ms: float = Field(description="Time taken for evaluation")


class ComplianceReportRequest(BaseModel):
    """Request model for compliance report generation."""

    report_type: str = Field(default="soc2", description="Type of compliance report (soc2, iso27001, gdpr, ccpa)")
    start_date: datetime | None = Field(default=None, description="Start date for report period")
    end_date: datetime | None = Field(default=None, description="End date for report period")
    workspace_id: str | None = Field(default=None, description="Workspace ID to filter report")


# API Endpoints


@router.post(
    "/environment/check-permission",
    status_code=status.HTTP_200_OK,
)
async def check_environment_permission(
    request: Request,
    permission_request: EnvironmentPermissionRequest,
    current_user: Annotated[dict, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> EnvironmentPermissionResponse:
    """Check if user has permission for specific environment action.

    This endpoint evaluates environment-scoped permissions including
    conditional checks based on IP, time, risk score, and MFA status.
    """
    try:
        # Initialize advanced features service
        advanced_service = AdvancedRBACFeaturesService()
        await advanced_service.initialize_service()

        # Create conditional permission context from request
        context = ConditionalPermissionContext(
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            request_time=datetime.now(timezone.utc),
            custom_attributes=permission_request.context or {},
        )

        start_time = datetime.now(timezone.utc)

        # Check environment permission
        granted = await advanced_service.check_environment_permission(
            session=session,
            user=current_user,
            environment_id=permission_request.environment_id,
            action=permission_request.action,
            context=context,
        )

        evaluation_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        logger.info(
            "Environment permission check completed",
            extra={
                "user_id": str(current_user.id),
                "environment_id": permission_request.environment_id,
                "action": permission_request.action,
                "granted": granted,
                "evaluation_time_ms": evaluation_time,
            },
        )

        return EnvironmentPermissionResponse(
            granted=granted,
            environment_id=permission_request.environment_id,
            action=permission_request.action,
            user_id=str(current_user.id),
            evaluation_time_ms=evaluation_time,
        )

    except Exception as exc:
        logger.error(
            "Error checking environment permission",
            extra={
                "user_id": str(current_user.id),
                "environment_id": permission_request.environment_id,
                "error": str(exc),
            },
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error during environment permission check",
        ) from exc


@router.post(
    "/service-account/create-with-token",
    status_code=status.HTTP_201_CREATED,
)
async def create_service_account_with_token(
    create_request: ServiceAccountCreateRequest,
    current_user: Annotated[dict, Depends(WorkspaceAdmin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Create service account with scoped token.

    This endpoint creates a new service account and generates a scoped
    API token with specific permissions and scope restrictions.
    """
    try:
        # Initialize advanced features service
        advanced_service = AdvancedRBACFeaturesService()
        await advanced_service.initialize_service()

        # Create service account with scoped token
        result = await advanced_service.create_service_account_with_scoped_token(
            session=session,
            creator=current_user,
            workspace_id=create_request.workspace_id,
            account_name=create_request.account_name,
            token_name=create_request.token_name,
            scoped_permissions=create_request.scoped_permissions,
            scope_type=create_request.scope_type,
            scope_id=create_request.scope_id,
            allowed_ips=create_request.allowed_ips,
            expires_days=create_request.expires_days,
        )

        logger.info(
            "Service account created with scoped token",
            extra={
                "creator_id": str(current_user.id),
                "workspace_id": create_request.workspace_id,
                "service_account_id": result["service_account"]["id"],
                "token_id": result["token"]["id"],
            },
        )

    except Exception as exc:
        logger.error(
            "Error creating service account with token",
            extra={"creator_id": str(current_user.id), "workspace_id": create_request.workspace_id, "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error during service account creation"
        ) from exc
    else:
        return result


@router.post(
    "/service-account/validate-token-scope",
    status_code=status.HTTP_200_OK,
)
async def validate_service_account_token_scope(
    request: Request,
    validation_request: ServiceAccountTokenValidationRequest,
    _current_user: Annotated[dict, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Validate service account token scope for requested action.

    This endpoint validates whether a service account token has the
    necessary scope and permissions for the requested action.
    """
    try:
        # Initialize advanced features service
        advanced_service = AdvancedRBACFeaturesService()
        await advanced_service.initialize_service()

        # Create context for validation
        context = ConditionalPermissionContext(
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            request_time=datetime.now(timezone.utc),
        )

        start_time = datetime.now(timezone.utc)

        # Validate token scope
        valid = await advanced_service.validate_service_account_token_scope(
            session=session,
            token_hash=validation_request.token_hash,
            requested_action=validation_request.requested_action,
            resource_type=validation_request.resource_type,
            resource_id=validation_request.resource_id,
            context=context,
        )

        evaluation_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        logger.info(
            "Service account token validation completed",
            extra={
                "token_prefix": validation_request.token_hash[:8] + "...",
                "requested_action": validation_request.requested_action,
                "resource_type": validation_request.resource_type,
                "valid": valid,
                "evaluation_time_ms": evaluation_time,
            },
        )

    except Exception as exc:
        logger.error(
            "Error validating service account token scope",
            extra={
                "token_prefix": validation_request.token_hash[:8] + "...",
                "requested_action": validation_request.requested_action,
                "error": str(exc),
            },
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error during token validation"
        ) from exc
    else:
        return {
            "valid": valid,
            "requested_action": validation_request.requested_action,
            "resource_type": validation_request.resource_type,
            "resource_id": validation_request.resource_id,
            "evaluation_time_ms": evaluation_time,
        }


@router.post(
    "/break-glass/request-access",
    status_code=status.HTTP_200_OK,
)
async def request_break_glass_access(
    break_glass_request: BreakGlassAccessRequest,
    current_user: Annotated[dict, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> BreakGlassAccessResponse:
    """Request break-glass emergency access.

    This endpoint evaluates break-glass access requests for emergency
    situations requiring elevated permissions with proper justification.
    """
    try:
        # Initialize advanced features service
        advanced_service = AdvancedRBACFeaturesService()
        await advanced_service.initialize_service()

        start_time = datetime.now(timezone.utc)

        # Evaluate break-glass access
        result = await advanced_service.evaluate_break_glass_access(
            session=session,
            user=current_user,
            justification=break_glass_request.justification,
            emergency_level=break_glass_request.emergency_level,
            requested_permissions=break_glass_request.requested_permissions,
            resource_context=break_glass_request.resource_context,
        )

        evaluation_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        logger.warning(
            "Break-glass access request evaluated",
            extra={
                "user_id": str(current_user.id),
                "emergency_level": break_glass_request.emergency_level,
                "granted": result.granted,
                "approval_required": result.approval_required,
                "evaluation_time_ms": evaluation_time,
            },
        )

        return BreakGlassAccessResponse(
            granted=result.granted,
            justification=result.justification or break_glass_request.justification,
            emergency_level=result.emergency_level,
            approval_required=result.approval_required,
            approval_timeout_minutes=result.approval_timeout_minutes,
            evaluation_time_ms=evaluation_time,
        )

    except Exception as exc:
        logger.error(
            "Error evaluating break-glass access",
            extra={
                "user_id": str(current_user.id),
                "emergency_level": break_glass_request.emergency_level,
                "error": str(exc),
            },
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error during break-glass access evaluation",
        ) from exc


@router.post(
    "/compliance/generate-report",
    status_code=status.HTTP_200_OK,
)
async def generate_compliance_report(
    report_request: ComplianceReportRequest,
    current_user: Annotated[dict, Depends(RBACAdmin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Generate compliance report for audit purposes.

    This endpoint generates comprehensive compliance reports for various
    standards including SOC 2, ISO 27001, GDPR, and CCPA.
    """
    try:
        # Initialize advanced features service
        advanced_service = AdvancedRBACFeaturesService()
        await advanced_service.initialize_service()

        start_time = datetime.now(timezone.utc)

        # Generate compliance report
        report = await advanced_service.generate_compliance_report(
            session=session,
            report_type=report_request.report_type,
            start_date=report_request.start_date,
            end_date=report_request.end_date,
            workspace_id=report_request.workspace_id,
        )

        generation_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        # Add generation metadata
        report["generation_metadata"] = {
            "requested_by": str(current_user.id),
            "generation_time_ms": generation_time,
            "langbuilder_version": "2.0.0",  # TODO: Get from version info
            "report_format": "json",
        }

        logger.info(
            "Compliance report generated",
            extra={
                "user_id": str(current_user.id),
                "report_type": report_request.report_type,
                "workspace_id": report_request.workspace_id,
                "total_events": report.get("total_events", 0),
                "generation_time_ms": generation_time,
            },
        )

        return report

    except Exception as exc:
        logger.error(
            "Error generating compliance report",
            extra={
                "user_id": str(current_user.id),
                "report_type": report_request.report_type,
                "workspace_id": report_request.workspace_id,
                "error": str(exc),
            },
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error during compliance report generation",
        ) from exc


@router.get(
    "/environment/{environment_id}/permissions",
    status_code=status.HTTP_200_OK,
)
async def get_environment_permissions(
    environment_id: str,
    current_user: Annotated[dict, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Get user's permissions for a specific environment.

    This endpoint returns all permissions the current user has for
    the specified environment, including conditional restrictions.
    """
    try:
        # Import necessary models
        from sqlalchemy import and_, select

        from langflow.services.database.models.rbac.environment import Environment
        from langflow.services.database.models.rbac.permission import Permission
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment
        from langflow.services.database.models.rbac.role_permission import RolePermission

        # Get environment details
        environment_result = await session.exec(select(Environment).where(Environment.id == environment_id))
        environment = environment_result.first()

        if not environment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found")

        # Get user's role assignments for this environment
        role_assignments_result = await session.exec(
            select(RoleAssignment).where(
                and_(
                    RoleAssignment.user_id == current_user.id,
                    RoleAssignment.environment_id == environment_id,
                    RoleAssignment.is_active,
                )
            )
        )
        role_assignments = role_assignments_result.all()

        # Get permissions for assigned roles
        permissions = []
        for assignment in role_assignments:
            role_permissions_result = await session.exec(
                select(Permission).join(RolePermission).where(RolePermission.role_id == assignment.role_id)
            )
            role_permissions = role_permissions_result.all()
            permissions.extend(
                [
                    {
                        "name": perm.name,
                        "description": perm.description,
                        "role_id": str(assignment.role_id),
                        "assignment_id": str(assignment.id),
                    }
                    for perm in role_permissions
                ]
            )

        # Get conditional restrictions
        conditional_restrictions = {
            "ip_restrictions": environment.type == "production",
            "time_restrictions": environment.type == "production",
            "mfa_required": environment.type == "production",
            "risk_threshold": 0.7 if environment.type == "production" else 0.9,
        }

        logger.info(
            "Environment permissions retrieved",
            extra={
                "user_id": str(current_user.id),
                "environment_id": environment_id,
                "permission_count": len(permissions),
                "environment_type": environment.type,
            },
        )

        return {
            "environment": {
                "id": str(environment.id),
                "name": environment.name,
                "type": environment.type,
                "project_id": str(environment.project_id),
            },
            "permissions": permissions,
            "conditional_restrictions": conditional_restrictions,
            "user_id": str(current_user.id),
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Error getting environment permissions",
            extra={"user_id": str(current_user.id), "environment_id": environment_id, "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error retrieving environment permissions",
        ) from exc


@router.get(
    "/service-accounts/{workspace_id}",
    status_code=status.HTTP_200_OK,
)
async def list_workspace_service_accounts(
    workspace_id: str,
    current_user: Annotated[dict, Depends(WorkspaceAdmin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    include_tokens: Annotated[bool, Query(description="Include token information")] = False,
) -> dict:
    """List service accounts for a workspace.

    This endpoint returns all service accounts in the specified workspace
    with optional token information for administrative purposes.
    """
    try:
        from sqlalchemy import select

        from langflow.services.database.models.rbac.service_account import ServiceAccount, ServiceAccountToken

        # Get service accounts for workspace
        service_accounts_result = await session.exec(
            select(ServiceAccount).where(ServiceAccount.workspace_id == workspace_id)
        )
        service_accounts = service_accounts_result.all()

        accounts_data = []
        for account in service_accounts:
            account_data = {
                "id": str(account.id),
                "name": account.name,
                "description": account.description,
                "service_type": account.service_type,
                "is_active": account.is_active,
                "created_at": account.created_at.isoformat(),
                "last_used_at": account.last_used_at.isoformat() if account.last_used_at else None,
                "created_by_id": str(account.created_by_id),
            }

            if include_tokens:
                # Get token information (without sensitive data)
                tokens_result = await session.exec(
                    select(ServiceAccountToken).where(ServiceAccountToken.service_account_id == account.id)
                )
                tokens = tokens_result.all()

                account_data["tokens"] = [
                    {
                        "id": str(token.id),
                        "name": token.name,
                        "token_prefix": token.token_prefix,
                        "is_active": token.is_active,
                        "scoped_permissions": token.scoped_permissions,
                        "scope_type": token.scope_type,
                        "scope_id": str(token.scope_id) if token.scope_id else None,
                        "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
                        "expires_at": token.expires_at.isoformat() if token.expires_at else None,
                        "usage_count": token.usage_count,
                    }
                    for token in tokens
                ]

                account_data["active_token_count"] = len([t for t in tokens if t.is_active])
                account_data["total_token_count"] = len(tokens)

            accounts_data.append(account_data)

        logger.info(
            "Service accounts listed",
            extra={
                "user_id": str(current_user.id),
                "workspace_id": workspace_id,
                "account_count": len(accounts_data),
                "include_tokens": include_tokens,
            },
        )

        return {"workspace_id": workspace_id, "service_accounts": accounts_data, "total_count": len(accounts_data)}

    except Exception as exc:
        logger.error(
            "Error listing service accounts",
            extra={"user_id": str(current_user.id), "workspace_id": workspace_id, "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error listing service accounts"
        ) from exc


# Conditional Policy Management Endpoints


@router.post(
    "/policies",
    status_code=status.HTTP_201_CREATED,
)
async def create_conditional_policy(
    policy_data: ConditionalPolicyCreate,
    current_user: Annotated[dict, Depends(RBACAdmin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConditionalPolicyRead:
    """Create a new conditional permission policy.

    This endpoint creates a configurable conditional permission policy
    that can be dynamically evaluated based on various conditions.
    """
    try:
        policy_manager = ConditionalPolicyManager()

        policy = await policy_manager.create_policy(
            session=session,
            name=policy_data.name,
            description=policy_data.description,
            permission=policy_data.permission,
            workspace_id=policy_data.workspace_id,
            environment_type=policy_data.environment_type,
            conditions=policy_data.conditions,
            enabled=policy_data.enabled,
            priority=policy_data.priority,
            failure_action=policy_data.failure_action,
            bypass_roles=policy_data.bypass_roles,
            effective_from=policy_data.effective_from,
            effective_until=policy_data.effective_until,
            created_by_id=current_user.id,
        )

        logger.info(
            "Conditional policy created",
            extra={
                "policy_id": policy.id,
                "creator_id": str(current_user.id),
                "permission": policy.permission,
                "priority": policy.priority,
            },
        )

        return ConditionalPolicyRead.model_validate(policy)

    except Exception as exc:
        logger.error(
            "Error creating conditional policy",
            extra={"creator_id": str(current_user.id), "permission": policy_data.permission, "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error creating conditional policy"
        ) from exc


@router.get(
    "/policies",
    status_code=status.HTTP_200_OK,
)
async def list_conditional_policies(
    current_user: Annotated[dict, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    permission: Annotated[str | None, Query(description="Filter by permission")] = None,
    workspace_id: Annotated[str | None, Query(description="Filter by workspace ID")] = None,
    enabled_only: Annotated[bool, Query(description="Only return enabled policies")] = True,
) -> list[ConditionalPolicyRead]:
    """List conditional permission policies.

    This endpoint returns a list of conditional policies with optional filtering.
    """
    try:
        policy_manager = ConditionalPolicyManager()

        # Convert workspace_id to UUID if needed
        workspace_uuid = UUID(workspace_id) if workspace_id else None

        if permission:
            policies = await policy_manager.get_policies_for_permission(
                session=session, permission=permission, workspace_id=workspace_uuid, enabled_only=enabled_only
            )
        else:
            policies = await policy_manager.get_all_policies(
                session=session, workspace_id=workspace_uuid, enabled_only=enabled_only
            )

        logger.info(
            "Conditional policies listed",
            extra={
                "user_id": str(current_user.id),
                "permission_filter": permission,
                "workspace_filter": workspace_id,
                "policy_count": len(policies),
            },
        )

        return [ConditionalPolicyRead.model_validate(policy) for policy in policies]

    except Exception as exc:
        logger.error(
            "Error listing conditional policies",
            extra={"user_id": str(current_user.id), "permission_filter": permission, "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error listing conditional policies"
        ) from exc


@router.get(
    "/policies/{policy_id}",
    status_code=status.HTTP_200_OK,
)
async def get_conditional_policy(
    policy_id: str,
    current_user: Annotated[dict, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConditionalPolicyRead:
    """Get a specific conditional permission policy by ID."""
    try:
        policy_manager = ConditionalPolicyManager()

        policy = await policy_manager.get_policy_by_id(session=session, policy_id=policy_id)

        if not policy:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conditional policy not found")

        logger.info("Conditional policy retrieved", extra={"user_id": str(current_user.id), "policy_id": policy_id})

        return ConditionalPolicyRead.model_validate(policy)

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Error getting conditional policy",
            extra={"user_id": str(current_user.id), "policy_id": policy_id, "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error retrieving conditional policy"
        ) from exc


@router.put(
    "/policies/{policy_id}",
    status_code=status.HTTP_200_OK,
)
async def update_conditional_policy(
    policy_id: str,
    policy_updates: ConditionalPolicyUpdate,
    current_user: Annotated[dict, Depends(RBACAdmin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConditionalPolicyRead:
    """Update a conditional permission policy."""
    try:
        policy_manager = ConditionalPolicyManager()

        updated_policy = await policy_manager.update_policy(
            session=session,
            policy_id=policy_id,
            **policy_updates.model_dump(exclude_unset=True),
            updated_by_id=current_user.id,
        )

        if not updated_policy:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conditional policy not found")

        logger.info("Conditional policy updated", extra={"policy_id": policy_id, "updater_id": str(current_user.id)})

        return ConditionalPolicyRead.model_validate(updated_policy)

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Error updating conditional policy",
            extra={"policy_id": policy_id, "updater_id": str(current_user.id), "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error updating conditional policy"
        ) from exc


@router.delete(
    "/policies/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_conditional_policy(
    policy_id: str,
    current_user: Annotated[dict, Depends(RBACAdmin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a conditional permission policy."""
    try:
        policy_manager = ConditionalPolicyManager()

        success = await policy_manager.delete_policy(session=session, policy_id=policy_id)

        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conditional policy not found")

        logger.info("Conditional policy deleted", extra={"policy_id": policy_id, "deleter_id": str(current_user.id)})

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Error deleting conditional policy",
            extra={"policy_id": policy_id, "deleter_id": str(current_user.id), "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error deleting conditional policy"
        ) from exc


@router.post(
    "/policies/{policy_id}/toggle",
    status_code=status.HTTP_200_OK,
)
async def toggle_policy_status(
    policy_id: str,
    current_user: Annotated[dict, Depends(RBACAdmin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConditionalPolicyRead:
    """Toggle a policy's enabled status."""
    try:
        policy_manager = ConditionalPolicyManager()

        policy = await policy_manager.toggle_policy_status(
            session=session, policy_id=policy_id, updated_by_id=current_user.id
        )

        if not policy:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conditional policy not found")

        logger.info(
            "Conditional policy toggled",
            extra={"policy_id": policy_id, "new_status": policy.enabled, "updater_id": str(current_user.id)},
        )

        return ConditionalPolicyRead.model_validate(policy)

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Error toggling conditional policy",
            extra={"policy_id": policy_id, "updater_id": str(current_user.id), "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error toggling conditional policy"
        ) from exc


@router.post(
    "/policies/evaluate",
    status_code=status.HTTP_200_OK,
)
async def evaluate_conditional_policies(
    request: Request,
    evaluation_request: PolicyEvaluationRequest,
    current_user: Annotated[dict, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicyEvaluationResult:
    """Evaluate conditional policies for a specific permission and context.

    This endpoint evaluates all applicable conditional policies for the given
    permission and returns a comprehensive result.
    """
    try:
        from langflow.services.rbac.conditional_permissions import ConditionalPermissionService, PermissionContext

        conditional_service = ConditionalPermissionService()

        # Create permission context from request
        context = PermissionContext(
            user_id=evaluation_request.user_id,
            ip_address=evaluation_request.ip_address or (request.client.host if request.client else None),
            user_agent=evaluation_request.user_agent or request.headers.get("user-agent"),
            session_id=evaluation_request.session_id,
            environment_type=evaluation_request.environment_type,
            workspace_id=evaluation_request.workspace_id,
            mfa_verified=evaluation_request.mfa_verified,
            vpn_detected=evaluation_request.vpn_detected,
            request_metadata=evaluation_request.additional_context,
        )

        start_time = datetime.now(timezone.utc)

        # Evaluate conditional permission
        result = await conditional_service.evaluate_conditional_permission(
            session=session, permission=evaluation_request.permission, context=context
        )

        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        logger.info(
            "Conditional policies evaluated",
            extra={
                "user_id": str(evaluation_request.user_id),
                "permission": evaluation_request.permission,
                "allowed": result.get("allowed", False),
                "execution_time_ms": execution_time,
            },
        )

        # Convert to policy evaluation result
        return PolicyEvaluationResult(
            allowed=result.get("allowed", False),
            policies_evaluated=result.get("policies_evaluated", 0),
            failing_policies=result.get("failing_policies", []),
            require_approval=result.get("require_approval", False),
            approval_reason=result.get("reason") if result.get("require_approval") else None,
            execution_time_ms=execution_time,
        )

    except Exception as exc:
        logger.error(
            "Error evaluating conditional policies",
            extra={
                "user_id": str(evaluation_request.user_id),
                "permission": evaluation_request.permission,
                "error": str(exc),
            },
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error evaluating conditional policies"
        ) from exc


@router.get(
    "/policies/{policy_id}/analytics",
    status_code=status.HTTP_200_OK,
)
async def get_policy_analytics(
    policy_id: str,
    current_user: Annotated[dict, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicyAnalytics:
    """Get analytics data for a conditional policy."""
    try:
        policy_manager = ConditionalPolicyManager()

        analytics = await policy_manager.get_policy_analytics(session=session, policy_id=policy_id)

        if not analytics:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conditional policy not found or no analytics data available",
            )

        logger.info("Policy analytics retrieved", extra={"user_id": str(current_user.id), "policy_id": policy_id})

        return analytics

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Error getting policy analytics",
            extra={"user_id": str(current_user.id), "policy_id": policy_id, "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error retrieving policy analytics"
        ) from exc


@router.post(
    "/policies/bulk-operation",
    status_code=status.HTTP_200_OK,
)
async def execute_bulk_policy_operation(
    bulk_operation: BulkPolicyOperation,
    current_user: Annotated[dict, Depends(RBACAdmin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Execute bulk operations on multiple conditional policies."""
    try:
        policy_manager = ConditionalPolicyManager()

        if bulk_operation.operation == "enable":
            results = []
            for policy_id in bulk_operation.policy_ids:
                success = await policy_manager.enable_policy(
                    session=session, policy_id=policy_id, updated_by_id=current_user.id
                )
                results.append({"policy_id": policy_id, "success": success})

        elif bulk_operation.operation == "disable":
            results = []
            for policy_id in bulk_operation.policy_ids:
                success = await policy_manager.disable_policy(
                    session=session, policy_id=policy_id, updated_by_id=current_user.id
                )
                results.append({"policy_id": policy_id, "success": success})

        elif bulk_operation.operation == "delete":
            results = []
            for policy_id in bulk_operation.policy_ids:
                success = await policy_manager.delete_policy(session=session, policy_id=policy_id)
                results.append({"policy_id": policy_id, "success": success})

        elif bulk_operation.operation == "update_priority":
            priority = bulk_operation.parameters.get("priority", 0)
            results = []
            for policy_id in bulk_operation.policy_ids:
                policy = await policy_manager.update_policy(
                    session=session, policy_id=policy_id, priority=priority, updated_by_id=current_user.id
                )
                results.append({"policy_id": policy_id, "success": policy is not None})

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported bulk operation: {bulk_operation.operation}",
            )

        successful_operations = len([r for r in results if r["success"]])

        logger.info(
            "Bulk policy operation executed",
            extra={
                "operator_id": str(current_user.id),
                "operation": bulk_operation.operation,
                "total_policies": len(bulk_operation.policy_ids),
                "successful_operations": successful_operations,
            },
        )

        return {
            "operation": bulk_operation.operation,
            "total_policies": len(bulk_operation.policy_ids),
            "successful_operations": successful_operations,
            "failed_operations": len(bulk_operation.policy_ids) - successful_operations,
            "results": results,
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Error executing bulk policy operation",
            extra={"operator_id": str(current_user.id), "operation": bulk_operation.operation, "error": str(exc)},
            exc_info=True,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error executing bulk policy operation"
        ) from exc
