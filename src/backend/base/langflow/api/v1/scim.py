"""SCIM 2.0 API endpoints for user and group provisioning.

This module implements SCIM 2.0 protocol endpoints for automated user lifecycle
management, following LangBuilder API patterns and RBAC integration.
"""

# NO future annotations per Phase 1 requirements
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger
from pydantic import BaseModel, Field

from langflow.api.utils import DbSession

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

# SCIM 2.0 Bearer token security
scim_security = HTTPBearer(scheme_name="SCIM Bearer Token")

router = APIRouter(
    prefix="/scim/v2",
    tags=["SCIM", "Provisioning"],
    responses={
        400: {"description": "Bad Request - Invalid SCIM request"},
        401: {"description": "Unauthorized - Invalid SCIM bearer token"},
        403: {"description": "Forbidden - Insufficient SCIM permissions"},
        404: {"description": "Not Found - SCIM resource not found"},
        409: {"description": "Conflict - SCIM resource already exists"},
        500: {"description": "Internal Server Error - SCIM processing failed"},
    },
)


class SCIMError(BaseModel):
    """SCIM error response model."""

    schemas: list[str] = Field(default=["urn:ietf:params:scim:api:messages:2.0:Error"])
    status: str
    detail: str
    scim_type: str | None = None


class SCIMListResponse(BaseModel):
    """SCIM list response model."""

    schemas: list[str] = Field(default=["urn:ietf:params:scim:api:messages:2.0:ListResponse"])
    total_results: int = Field(alias="totalResults")
    start_index: int = Field(alias="startIndex", default=1)
    items_per_page: int = Field(alias="itemsPerPage")
    resources: list[dict[str, Any]] = Field(alias="Resources", default=[])


class SCIMUserRequest(BaseModel):
    """SCIM User request model."""

    schemas: list[str] = Field(default=["urn:ietf:params:scim:schemas:core:2.0:User"])
    id: str | None = None
    external_id: str | None = Field(None, alias="externalId")
    user_name: str = Field(alias="userName")
    name: dict[str, str] | None = None
    display_name: str | None = Field(None, alias="displayName")
    emails: list[dict[str, Any]] = []
    active: bool = True
    groups: list[dict[str, str]] | None = []
    title: str | None = None
    department: str | None = None
    organization: str | None = None


class SCIMGroupRequest(BaseModel):
    """SCIM Group request model."""

    schemas: list[str] = Field(default=["urn:ietf:params:scim:schemas:core:2.0:Group"])
    id: str | None = None
    external_id: str | None = Field(None, alias="externalId")
    display_name: str = Field(alias="displayName")
    members: list[dict[str, str]] = []


class SCIMPatchOperation(BaseModel):
    """SCIM PATCH operation model."""

    op: str  # "add", "remove", "replace"
    path: str | None = None
    value: Any | None = None


class SCIMPatchRequest(BaseModel):
    """SCIM PATCH request model."""

    schemas: list[str] = Field(default=["urn:ietf:params:scim:api:messages:2.0:PatchOp"])
    operations: list[SCIMPatchOperation] = Field(alias="Operations")


async def verify_scim_token(
    session: DbSession,
    credentials: HTTPAuthorizationCredentials = Depends(scim_security),
) -> "SSOConfiguration":
    """Verify SCIM bearer token and return associated SSO configuration."""
    from sqlmodel import select

    from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SCIM bearer token required"
        )

    # Find SSO configuration by SCIM token
    scim_token = credentials.credentials
    query = select(SSOConfiguration).where(
        SSOConfiguration.scim_token == scim_token,
        SSOConfiguration.is_active is True,
        SSOConfiguration.scim_enabled is True,
    )
    result = await session.exec(query)
    config = result.first()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SCIM bearer token"
        )

    return config


@router.get("/ServiceProviderConfig")
async def get_service_provider_config() -> dict[str, Any]:
    """Get SCIM service provider configuration."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://docs.langbuilder.com/scim",
        "patch": {
            "supported": True
        },
        "bulk": {
            "supported": True,
            "maxOperations": 1000,
            "maxPayloadSize": 1048576
        },
        "filter": {
            "supported": True,
            "maxResults": 200
        },
        "changePassword": {
            "supported": False
        },
        "sort": {
            "supported": True
        },
        "etag": {
            "supported": False
        },
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using OAuth Bearer Token",
                "specUri": "http://www.rfc-editor.org/info/rfc6750",
                "documentationUri": "https://docs.langbuilder.com/scim/auth",
                "type": "oauthbearertoken"
            }
        ]
    }


@router.get("/ResourceTypes")
async def get_resource_types() -> list[dict[str, Any]]:
    """Get supported SCIM resource types."""
    return [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:User"
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Group",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"
        }
    ]


@router.get("/Schemas")
async def get_schemas() -> list[dict[str, Any]]:
    """Get SCIM schemas."""
    return [
        {
            "id": "urn:ietf:params:scim:schemas:core:2.0:User",
            "name": "User",
            "description": "User Account",
            "attributes": [
                {
                    "name": "userName",
                    "type": "string",
                    "required": True,
                    "description": "Unique identifier for the User"
                },
                {
                    "name": "name",
                    "type": "complex",
                    "description": "The components of the user's real name"
                },
                {
                    "name": "emails",
                    "type": "complex",
                    "multiValued": True,
                    "description": "Email addresses for the user"
                },
                {
                    "name": "active",
                    "type": "boolean",
                    "description": "A Boolean value indicating the User's administrative status"
                }
            ]
        },
        {
            "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "name": "Group",
            "description": "Group",
            "attributes": [
                {
                    "name": "displayName",
                    "type": "string",
                    "required": True,
                    "description": "A human-readable name for the Group"
                },
                {
                    "name": "members",
                    "type": "complex",
                    "multiValued": True,
                    "description": "A list of members of the Group"
                }
            ]
        }
    ]


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: SCIMUserRequest,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Create a new user via SCIM."""
    try:
        from langflow.services.auth.scim_service import SCIMOperationType, SCIMProvisioningService

        # Convert request to internal format
        scim_user_dict = user_data.model_dump(by_alias=True)

        # Process user creation
        scim_service = SCIMProvisioningService()
        result = await scim_service.process_scim_user(
            session=session,
            scim_user_data=scim_user_dict,
            provider_id=str(config.id),
            operation=SCIMOperationType.CREATE,
            dry_run=False,
        )

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message or "User creation failed"
            )

        # Return SCIM user representation
        response = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": result.resource_id,
            "externalId": user_data.external_id,
            "userName": user_data.user_name,
            "displayName": user_data.display_name,
            "emails": user_data.emails,
            "active": user_data.active,
            "meta": {
                "resourceType": "User",
                "created": datetime.now(timezone.utc).isoformat(),
                "lastModified": datetime.now(timezone.utc).isoformat(),
                "location": f"/scim/v2/Users/{result.resource_id}"
            }
        }

        if user_data.name:
            response["name"] = user_data.name

        logger.info(f"SCIM: Created user {user_data.user_name} via provider {config.name}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM user creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during user creation"
        )


@router.get("/Users")
async def list_users(
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
    start_index: Annotated[int, Query(alias="startIndex", ge=1)] = 1,
    count: Annotated[int, Query(ge=1, le=200)] = 100,
    filter: Annotated[str | None, Query()] = None,
) -> SCIMListResponse:
    """List users via SCIM."""
    try:
        from sqlmodel import select

        from langflow.services.database.models.user.model import User

        # Build query
        query = select(User).where(User.is_active is True)

        # Apply filter if provided
        if filter:
            # Simple filter parsing for userName and emails
            if "userName eq" in filter:
                username = filter.split('"')[1]
                query = query.where(User.username == username)
            elif "emails" in filter and "value eq" in filter:
                email = filter.split('"')[1]
                query = query.where(User.email == email)

        # Apply pagination
        query = query.offset(start_index - 1).limit(count)

        result = await session.exec(query)
        users = result.all()

        # Convert users to SCIM format
        scim_users = []
        for user in users:
            scim_user = {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": str(user.id),
                "externalId": user.external_id,
                "userName": user.username,
                "displayName": f"{user.first_name} {user.last_name}".strip() or user.username,
                "emails": [
                    {
                        "value": user.email,
                        "type": "work",
                        "primary": True
                    }
                ] if user.email else [],
                "active": user.is_active,
                "name": {
                    "givenName": user.first_name,
                    "familyName": user.last_name,
                    "formatted": f"{user.first_name} {user.last_name}".strip()
                } if user.first_name or user.last_name else None,
                "meta": {
                    "resourceType": "User",
                    "created": user.created_at.isoformat() if user.created_at else None,
                    "lastModified": user.updated_at.isoformat() if user.updated_at else None,
                    "location": f"/scim/v2/Users/{user.id}"
                }
            }
            scim_users.append(scim_user)

        return SCIMListResponse(
            total_results=len(scim_users),
            start_index=start_index,
            items_per_page=len(scim_users),
            resources=scim_users
        )

    except Exception as e:
        logger.error(f"SCIM user listing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during user listing"
        )


@router.get("/Users/{user_id}")
async def get_user(
    user_id: str,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Get user by ID via SCIM."""
    try:
        from langflow.services.database.models.user.model import User

        # Find user by ID or external ID
        user = None
        try:
            # Try UUID first
            uuid_id = UUID(user_id)
            user = await session.get(User, uuid_id)
        except ValueError:
            # Try external ID
            from sqlmodel import select
            query = select(User).where(User.external_id == user_id)
            result = await session.exec(query)
            user = result.first()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Convert to SCIM format
        scim_user = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": str(user.id),
            "externalId": user.external_id,
            "userName": user.username,
            "displayName": f"{user.first_name} {user.last_name}".strip() or user.username,
            "emails": [
                {
                    "value": user.email,
                    "type": "work",
                    "primary": True
                }
            ] if user.email else [],
            "active": user.is_active,
            "meta": {
                "resourceType": "User",
                "created": user.created_at.isoformat() if user.created_at else None,
                "lastModified": user.updated_at.isoformat() if user.updated_at else None,
                "location": f"/scim/v2/Users/{user.id}"
            }
        }

        if user.first_name or user.last_name:
            scim_user["name"] = {
                "givenName": user.first_name,
                "familyName": user.last_name,
                "formatted": f"{user.first_name} {user.last_name}".strip()
            }

        return scim_user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM user retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during user retrieval"
        )


@router.put("/Users/{user_id}")
async def update_user(
    user_id: str,
    user_data: SCIMUserRequest,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Update user via SCIM."""
    try:
        from langflow.services.auth.scim_service import SCIMOperationType, SCIMProvisioningService

        # Convert request to internal format
        scim_user_dict = user_data.model_dump(by_alias=True)
        scim_user_dict["id"] = user_id

        # Process user update
        scim_service = SCIMProvisioningService()
        result = await scim_service.process_scim_user(
            session=session,
            scim_user_data=scim_user_dict,
            provider_id=str(config.id),
            operation=SCIMOperationType.UPDATE,
            dry_run=False,
        )

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message or "User update failed"
            )

        # Return updated SCIM user representation
        response = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": user_id,
            "externalId": user_data.external_id,
            "userName": user_data.user_name,
            "displayName": user_data.display_name,
            "emails": user_data.emails,
            "active": user_data.active,
            "meta": {
                "resourceType": "User",
                "lastModified": datetime.now(timezone.utc).isoformat(),
                "location": f"/scim/v2/Users/{user_id}"
            }
        }

        if user_data.name:
            response["name"] = user_data.name

        logger.info(f"SCIM: Updated user {user_data.user_name} via provider {config.name}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM user update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during user update"
        )


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: str,
    patch_request: SCIMPatchRequest,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Partially update user via SCIM PATCH."""
    try:
        from sqlmodel import select

        from langflow.services.auth.scim_service import SCIMOperationType, SCIMProvisioningService
        from langflow.services.database.models.user.model import User

        # Find user by ID or external ID
        user = None
        try:
            uuid_id = UUID(user_id)
            user = await session.get(User, uuid_id)
        except ValueError:
            query = select(User).where(User.external_id == user_id)
            result = await session.exec(query)
            user = result.first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Apply PATCH operations
        user_data = {
            "id": str(user.id),
            "userName": user.username,
            "active": user.is_active,
            "externalId": getattr(user, "external_id", None),
        }

        # Add optional fields if they exist
        if hasattr(user, "email") and user.email:
            user_data["emails"] = [{"value": user.email, "type": "work", "primary": True}]
        if hasattr(user, "first_name") and hasattr(user, "last_name"):
            user_data["name"] = {
                "givenName": user.first_name,
                "familyName": user.last_name,
                "formatted": f"{user.first_name} {user.last_name}".strip()
            }
            user_data["displayName"] = f"{user.first_name} {user.last_name}".strip() or user.username

        # Process PATCH operations
        for operation in patch_request.operations:
            op = operation.op.lower()
            path = operation.path
            value = operation.value

            if op == "replace":
                if path == "active":
                    user_data["active"] = bool(value)
                elif path == "userName":
                    user_data["userName"] = str(value)
                elif path == "displayName":
                    user_data["displayName"] = str(value)
                elif path and path.startswith("emails"):
                    if isinstance(value, list):
                        user_data["emails"] = value
                    else:
                        user_data["emails"] = [{"value": str(value), "type": "work", "primary": True}]
                elif path and path.startswith("name"):
                    if isinstance(value, dict):
                        user_data["name"] = value
            elif op == "add":
                if path == "emails" and isinstance(value, list):
                    user_data.setdefault("emails", []).extend(value)
            elif op == "remove":
                if path == "emails":
                    user_data.pop("emails", None)

        # Process the updated user data
        scim_service = SCIMProvisioningService()
        result = await scim_service.process_scim_user(
            session=session,
            scim_user_data=user_data,
            provider_id=str(config.id),
            operation=SCIMOperationType.UPDATE,
            dry_run=False,
        )

        if not result.success:
            if "not found" in (result.error_message or "").lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message or "User patch failed"
            )

        # Return updated user in SCIM format
        response = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": str(user.id),
            "externalId": user_data.get("externalId"),
            "userName": user_data["userName"],
            "displayName": user_data.get("displayName"),
            "emails": user_data.get("emails", []),
            "active": user_data["active"],
            "meta": {
                "resourceType": "User",
                "lastModified": datetime.now(timezone.utc).isoformat(),
                "location": f"/scim/v2/Users/{user_id}"
            }
        }

        if user_data.get("name"):
            response["name"] = user_data["name"]

        logger.info(f"SCIM: Patched user {user_data['userName']} via provider {config.name}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM user patch failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during user patch"
        )


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
):
    """Delete (deactivate) user via SCIM."""
    try:
        from langflow.services.auth.scim_service import SCIMOperationType, SCIMProvisioningService

        # Process user deactivation
        scim_service = SCIMProvisioningService()
        result = await scim_service.process_scim_user(
            session=session,
            scim_user_data={"id": user_id, "userName": user_id, "active": False},
            provider_id=str(config.id),
            operation=SCIMOperationType.DEACTIVATE,
            dry_run=False,
        )

        if not result.success:
            if "not found" in (result.error_message or "").lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message or "User deactivation failed"
            )

        logger.info(f"SCIM: Deactivated user {user_id} via provider {config.name}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM user deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during user deletion"
        )


@router.post("/Groups", status_code=status.HTTP_201_CREATED)
async def create_group(
    group_data: SCIMGroupRequest,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Create a new group via SCIM."""
    try:
        from langflow.services.auth.scim_service import SCIMProvisioningService

        # Convert request to internal format
        scim_group_dict = group_data.model_dump(by_alias=True)

        # Process group creation
        scim_service = SCIMProvisioningService()
        result = await scim_service.process_scim_group(
            session=session,
            scim_group_data=scim_group_dict,
            provider_id=str(config.id),
            dry_run=False,
        )

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message or "Group creation failed"
            )

        # Return SCIM group representation
        response = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": result.resource_id,
            "externalId": group_data.external_id,
            "displayName": group_data.display_name,
            "members": group_data.members,
            "meta": {
                "resourceType": "Group",
                "created": datetime.now(timezone.utc).isoformat(),
                "lastModified": datetime.now(timezone.utc).isoformat(),
                "location": f"/scim/v2/Groups/{result.resource_id}"
            }
        }

        logger.info(f"SCIM: Created group {group_data.display_name} via provider {config.name}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM group creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during group creation"
        )


@router.get("/Groups")
async def list_groups(
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
    start_index: Annotated[int, Query(alias="startIndex", ge=1)] = 1,
    count: Annotated[int, Query(ge=1, le=200)] = 100,
    filter: Annotated[str | None, Query()] = None,
) -> SCIMListResponse:
    """List groups via SCIM."""
    try:
        from sqlmodel import select

        from langflow.services.database.models.rbac.user_group import UserGroup

        # Build query for SSO-managed groups
        query = select(UserGroup).where(
            UserGroup.is_active is True,
            UserGroup.sso_provider_id == config.id,
        )

        # Apply filter if provided
        if filter and "displayName eq" in filter:
            display_name = filter.split('"')[1]
            query = query.where(UserGroup.name == display_name)

        # Apply pagination
        query = query.offset(start_index - 1).limit(count)

        result = await session.exec(query)
        groups = result.all()

        # Convert groups to SCIM format
        scim_groups = []
        for group in groups:
            scim_group = {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "id": str(group.id),
                "externalId": group.external_id,
                "displayName": group.name,
                "members": [],  # Would need to load members if required
                "meta": {
                    "resourceType": "Group",
                    "created": group.created_at.isoformat() if group.created_at else None,
                    "lastModified": group.updated_at.isoformat() if group.updated_at else None,
                    "location": f"/scim/v2/Groups/{group.id}"
                }
            }
            scim_groups.append(scim_group)

        return SCIMListResponse(
            total_results=len(scim_groups),
            start_index=start_index,
            items_per_page=len(scim_groups),
            resources=scim_groups
        )

    except Exception as e:
        logger.error(f"SCIM group listing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during group listing"
        )


@router.get("/Groups/{group_id}")
async def get_group(
    group_id: str,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Get group by ID via SCIM."""
    try:
        from sqlmodel import select

        from langflow.services.database.models.rbac.user_group import UserGroup, UserGroupMembership
        from langflow.services.database.models.user.model import User

        # Find group by ID or external ID
        group = None
        try:
            # Try UUID first
            uuid_id = UUID(group_id)
            group = await session.get(UserGroup, uuid_id)
        except ValueError:
            # Try external ID
            query = select(UserGroup).where(
                UserGroup.external_id == group_id,
                UserGroup.sso_provider_id == config.id,
            )
            result = await session.exec(query)
            group = result.first()

        if not group or not group.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found"
            )

        # Get group members
        members_query = select(UserGroupMembership).join(User).where(
            UserGroupMembership.group_id == group.id,
            UserGroupMembership.is_active is True,
        )
        members_result = await session.exec(members_query)
        memberships = members_result.all()

        # Convert members to SCIM format
        scim_members = []
        for membership in memberships:
            if membership.user:
                scim_members.append({
                    "value": str(membership.user.id),
                    "display": membership.user.username,
                    "type": "User"
                })

        # Convert to SCIM format
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": str(group.id),
            "externalId": group.external_id,
            "displayName": group.name,
            "members": scim_members,
            "meta": {
                "resourceType": "Group",
                "created": group.created_at.isoformat() if group.created_at else None,
                "lastModified": group.updated_at.isoformat() if group.updated_at else None,
                "location": f"/scim/v2/Groups/{group.id}"
            }
        }


    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM group retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during group retrieval"
        )


@router.put("/Groups/{group_id}")
async def update_group(
    group_id: str,
    group_data: SCIMGroupRequest,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Update group via SCIM."""
    try:
        from langflow.services.auth.scim_service import SCIMProvisioningService

        # Convert request to internal format
        scim_group_dict = group_data.model_dump(by_alias=True)
        scim_group_dict["id"] = group_id

        # Process group update
        scim_service = SCIMProvisioningService()
        result = await scim_service.process_scim_group(
            session=session,
            scim_group_data=scim_group_dict,
            provider_id=str(config.id),
            dry_run=False,
        )

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message or "Group update failed"
            )

        # Return updated SCIM group representation
        response = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": group_id,
            "externalId": group_data.external_id,
            "displayName": group_data.display_name,
            "members": group_data.members,
            "meta": {
                "resourceType": "Group",
                "lastModified": datetime.now(timezone.utc).isoformat(),
                "location": f"/scim/v2/Groups/{group_id}"
            }
        }

        logger.info(f"SCIM: Updated group {group_data.display_name} via provider {config.name}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM group update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during group update"
        )


@router.patch("/Groups/{group_id}")
async def patch_group(
    group_id: str,
    patch_request: SCIMPatchRequest,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Partially update group via SCIM PATCH."""
    try:
        from sqlmodel import select

        from langflow.services.auth.scim_service import SCIMProvisioningService
        from langflow.services.database.models.rbac.user_group import UserGroup

        # Find group by ID or external ID
        group = None
        try:
            uuid_id = UUID(group_id)
            query = select(UserGroup).where(
                (UserGroup.id == uuid_id) &
                (UserGroup.sso_provider_id == UUID(config.id))
            )
            result = await session.exec(query)
            group = result.first()
        except ValueError:
            query = select(UserGroup).where(
                (UserGroup.external_id == group_id) &
                (UserGroup.sso_provider_id == UUID(config.id))
            )
            result = await session.exec(query)
            group = result.first()

        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found"
            )

        # Build current group data
        group_data = {
            "id": str(group.id),
            "externalId": group.external_id,
            "displayName": group.name,
            "members": []  # Will be populated from group memberships
        }

        # Get current members
        from langflow.services.database.models.rbac.user_group import UserGroupMembership
        from langflow.services.database.models.user.model import User

        member_query = select(UserGroupMembership, User).join(
            User, UserGroupMembership.user_id == User.id
        ).where(UserGroupMembership.group_id == group.id)
        member_result = await session.exec(member_query)

        current_members = []
        for membership, user in member_result.all():
            current_members.append({
                "value": str(user.id),
                "display": user.username,
                "type": "User"
            })
        group_data["members"] = current_members

        # Process PATCH operations
        for operation in patch_request.operations:
            op = operation.op.lower()
            path = operation.path
            value = operation.value

            if op == "replace":
                if path == "displayName":
                    group_data["displayName"] = str(value)
                elif path == "members":
                    if isinstance(value, list):
                        group_data["members"] = value
            elif op == "add":
                if path == "members":
                    if isinstance(value, list):
                        # Add new members to existing list
                        existing_member_ids = {m.get("value") for m in group_data["members"]}
                        for new_member in value:
                            if new_member.get("value") not in existing_member_ids:
                                group_data["members"].append(new_member)
                    elif isinstance(value, dict) and value.get("value"):
                        # Add single member
                        existing_member_ids = {m.get("value") for m in group_data["members"]}
                        if value["value"] not in existing_member_ids:
                            group_data["members"].append(value)
            elif op == "remove":
                if path == "members":
                    if isinstance(value, list):
                        # Remove specified members
                        remove_ids = {m.get("value") for m in value if m.get("value")}
                        group_data["members"] = [
                            m for m in group_data["members"]
                            if m.get("value") not in remove_ids
                        ]
                    elif isinstance(value, dict) and value.get("value"):
                        # Remove single member
                        member_id = value["value"]
                        group_data["members"] = [
                            m for m in group_data["members"]
                            if m.get("value") != member_id
                        ]
                    else:
                        # Remove all members
                        group_data["members"] = []

        # Process the updated group data
        scim_service = SCIMProvisioningService()
        result = await scim_service.process_scim_group(
            session=session,
            scim_group_data=group_data,
            provider_id=str(config.id),
            dry_run=False,
        )

        if not result.success:
            if "not found" in (result.error_message or "").lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Group not found"
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message or "Group patch failed"
            )

        # Return updated group in SCIM format
        response = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": str(group.id),
            "externalId": group_data.get("externalId"),
            "displayName": group_data["displayName"],
            "members": group_data["members"],
            "meta": {
                "resourceType": "Group",
                "lastModified": datetime.now(timezone.utc).isoformat(),
                "location": f"/scim/v2/Groups/{group_id}"
            }
        }

        logger.info(f"SCIM: Patched group {group_data['displayName']} via provider {config.name}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM group patch failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during group patch"
        )


@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: str,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
):
    """Delete (deactivate) group via SCIM."""
    try:
        from sqlmodel import select

        from langflow.services.database.models.rbac.user_group import UserGroup

        # Find group by ID or external ID
        group = None
        try:
            # Try UUID first
            uuid_id = UUID(group_id)
            group = await session.get(UserGroup, uuid_id)
        except ValueError:
            # Try external ID
            query = select(UserGroup).where(
                UserGroup.external_id == group_id,
                UserGroup.sso_provider_id == config.id,
            )
            result = await session.exec(query)
            group = result.first()

        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found"
            )

        # Deactivate group
        group.is_active = False
        group.updated_at = datetime.now(timezone.utc)

        await session.commit()

        logger.info(f"SCIM: Deactivated group {group.name} via provider {config.name}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCIM group deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during group deletion"
        )


@router.post("/Bulk")
async def bulk_operations(
    request: Request,
    session: DbSession,
    config: Annotated["SSOConfiguration", Depends(verify_scim_token)],
) -> dict[str, Any]:
    """Handle SCIM bulk operations."""
    try:
        bulk_request = await request.json()

        if "Operations" not in bulk_request:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing Operations in bulk request"
            )

        operations = bulk_request["Operations"]
        results = []

        from langflow.services.auth.scim_service import SCIMProvisioningService
        scim_service = SCIMProvisioningService()

        for _i, operation in enumerate(operations[:1000]):  # Limit to 1000 operations
            op_result = {
                "method": operation.get("method", "").upper(),
                "bulkId": operation.get("bulkId"),
                "version": operation.get("version"),
                "location": operation.get("path", ""),
                "status": "200"
            }

            try:
                method = operation.get("method", "").upper()
                path = operation.get("path", "")
                data = operation.get("data", {})

                if method == "POST" and "/Users" in path:
                    result = await scim_service.process_scim_user(
                        session=session,
                        scim_user_data=data,
                        provider_id=str(config.id),
                        dry_run=False,
                    )
                    if not result.success:
                        op_result["status"] = "400"
                        op_result["response"] = {"detail": result.error_message}

                elif method == "POST" and "/Groups" in path:
                    result = await scim_service.process_scim_group(
                        session=session,
                        scim_group_data=data,
                        provider_id=str(config.id),
                        dry_run=False,
                    )
                    if not result.success:
                        op_result["status"] = "400"
                        op_result["response"] = {"detail": result.error_message}

                else:
                    op_result["status"] = "501"
                    op_result["response"] = {"detail": "Operation not supported in bulk"}

            except Exception as e:
                op_result["status"] = "500"
                op_result["response"] = {"detail": str(e)}

            results.append(op_result)

        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
            "Operations": results
        }

    except Exception as e:
        logger.error(f"SCIM bulk operations failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during bulk operations"
        )
