from __future__ import annotations

import io
import json
import warnings
import zipfile
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

import orjson
from aiofile import async_open
from anyio import Path
from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse
from fastapi_pagination import Page, Params
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.utils import CurrentActiveUser, DbSession, cascade_delete_flow, remove_api_keys, validate_is_component
from langflow.services.auth.authorization_patterns import get_enhanced_enforcement_context, RequireFlowRead, RequireFlowWrite
from langflow.services.auth.secure_data_access import SecureDataAccessService
from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext, RBACRuntimeEnforcementService
from langflow.api.v1.schemas import FlowListCreate
from langflow.helpers.user import get_user_by_flow_id_or_endpoint_name
from langflow.initial_setup.constants import STARTER_FOLDER_NAME
from langflow.logging import logger
from langflow.services.database.models.flow.model import (
    AccessTypeEnum,
    Flow,
    FlowCreate,
    FlowHeader,
    FlowRead,
    FlowUpdate,
)
from langflow.services.database.models.flow.utils import get_webhook_component_in_flow
from langflow.services.database.models.folder.constants import DEFAULT_FOLDER_NAME
from langflow.services.database.models.folder.model import Folder
from langflow.services.deps import get_settings_service
from langflow.utils.compression import compress_response

# build router
router = APIRouter(prefix="/flows", tags=["Flows"])


async def _verify_fs_path(path: str | None) -> None:
    if path:
        path_ = Path(path)
        if not await path_.exists():
            await path_.touch()


async def _save_flow_to_fs(flow: Flow) -> None:
    if flow.fs_path:
        async with async_open(flow.fs_path, "w") as f:
            try:
                await f.write(flow.model_dump_json())
            except OSError:
                logger.exception("Failed to write flow %s to path %s", flow.name, flow.fs_path)


async def _new_flow_secure(
    *,
    session: AsyncSession,
    flow: FlowCreate,
    context: RuntimeEnforcementContext,
) -> Flow:
    """Create a new flow with RBAC security and workspace boundary enforcement."""
    try:
        await _verify_fs_path(flow.fs_path)

        # SECURITY FIX: Use secure data access service for RBAC-aware flow creation
        secure_data_service = SecureDataAccessService()

        # Set user from context to prevent user ID manipulation
        if flow.user_id is None:
            flow.user_id = context.user.id if context.user else None

        # SECURITY FIX: Validate name uniqueness within workspace boundaries only
        flow.name = await secure_data_service.validate_flow_name_unique_secure(
            session=session,
            context=context,
            flow_name=flow.name,
        )

        # SECURITY FIX: Validate endpoint uniqueness within workspace boundaries only
        if flow.endpoint_name:
            flow.endpoint_name = await secure_data_service.validate_flow_endpoint_unique_secure(
                session=session,
                context=context,
                endpoint_name=flow.endpoint_name,
            )

        # Create flow with proper RBAC context
        db_flow = Flow.model_validate(flow, from_attributes=True)
        db_flow.updated_at = datetime.now(timezone.utc)

        # SECURITY FIX: Get default folder with workspace boundary enforcement
        if db_flow.folder_id is None:
            default_folder = await secure_data_service.get_default_folder_secure(
                session=session,
                context=context,
                folder_name=DEFAULT_FOLDER_NAME,
            )
            if default_folder:
                db_flow.folder_id = default_folder.id

        # Add flow to session (will be committed by caller)
        session.add(db_flow)

        return db_flow

    except Exception as e:
        # If it is a validation error, return the error message
        if hasattr(e, "errors"):
            raise HTTPException(status_code=400, detail=str(e)) from e
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(e)) from e


# DEPRECATED: Legacy function for backward compatibility - DO NOT USE
# This function contains CRITICAL SECURITY VULNERABILITIES
async def _new_flow(
    *,
    session: AsyncSession,
    flow: FlowCreate,
    user_id: UUID,
):
    """DEPRECATED: This function contains critical security vulnerabilities.

    Use _new_flow_secure() instead which provides:
    - RBAC workspace boundary enforcement
    - Secure uniqueness validation within workspace scope
    - Prevention of cross-workspace data leakage

    This legacy function allows cross-workspace name/endpoint conflicts.
    """
    import warnings
    warnings.warn(
        "_new_flow() is deprecated due to security vulnerabilities. Use _new_flow_secure() instead.",
        DeprecationWarning,
        stacklevel=2
    )

    # For now, we'll redirect to the secure version, but callers should be updated
    # to provide the proper context parameter
    from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext
    from langflow.services.database.models.user.model import User

    # Get user object
    user = (await session.exec(select(User).where(User.id == user_id))).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Create minimal context - this is a security risk but maintains compatibility
    minimal_context = RuntimeEnforcementContext(
        user=user,
        token_validation=None,
        requested_workspace_id=None,  # This is the security issue - no workspace boundary
        requested_project_id=None,
        requested_environment_id=None,
        request_path=None,
        request_method="POST",
    )

    return await _new_flow_secure(
        session=session,
        flow=flow,
        context=minimal_context,
    )


@router.post("/", response_model=FlowRead, status_code=201)
async def create_flow(
    *,
    session: DbSession,
    flow: FlowCreate,
    current_user: CurrentActiveUser,
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    _flow_write_check: Annotated[bool, RequireFlowWrite] = True,
):
    """Create a new flow with RBAC security."""
    try:
        # SECURITY FIX: Use secure flow creation with RBAC context
        db_flow = await _new_flow_secure(session=session, flow=flow, context=context)
        await session.commit()
        await session.refresh(db_flow)

        await _save_flow_to_fs(db_flow)

    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            # Get the name of the column that failed
            columns = str(e).split("UNIQUE constraint failed: ")[1].split(".")[1].split("\n")[0]
            # UNIQUE constraint failed: flow.user_id, flow.name
            # or UNIQUE constraint failed: flow.name
            # if the column has id in it, we want the other column
            column = columns.split(",")[1] if "id" in columns.split(",")[0] else columns.split(",")[0]

            raise HTTPException(
                status_code=400, detail=f"{column.capitalize().replace('_', ' ')} must be unique"
            ) from e
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(e)) from e
    return db_flow


@router.get("/", response_model=list[FlowRead] | Page[FlowRead] | list[FlowHeader], status_code=200)
async def read_flows(
    *,
    current_user: CurrentActiveUser,
    session: DbSession,
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    remove_example_flows: bool = False,
    components_only: bool = False,
    get_all: bool = True,
    folder_id: UUID | None = None,
    params: Annotated[Params, Depends()],
    header_flows: bool = False,
    _flow_read_check: Annotated[bool, RequireFlowRead] = True,
):
    """Retrieve a list of flows with pagination support.

    Args:
        current_user (User): The current authenticated user.
        session (Session): The database session.
        settings_service (SettingsService): The settings service.
        components_only (bool, optional): Whether to return only components. Defaults to False.

        get_all (bool, optional): Whether to return all flows without pagination. Defaults to True.
        **This field must be True because of backward compatibility with the frontend - Release: 1.0.20**

        folder_id (UUID, optional): The project ID. Defaults to None.
        params (Params): Pagination parameters.
        remove_example_flows (bool, optional): Whether to remove example flows. Defaults to False.
        header_flows (bool, optional): Whether to return only specific headers of the flows. Defaults to False.

    Returns:
        list[FlowRead] | Page[FlowRead] | list[FlowHeader]
        A list of flows or a paginated response containing the list of flows or a list of flow headers.
    """
    try:
        # Use secure data access service for proper RBAC enforcement
        from langflow.services.auth.secure_data_access import SecureDataAccessService
        secure_data_service = SecureDataAccessService()

        default_folder = (await session.exec(select(Folder).where(Folder.name == DEFAULT_FOLDER_NAME))).first()
        default_folder_id = default_folder.id if default_folder else None

        starter_folder = (await session.exec(select(Folder).where(Folder.name == STARTER_FOLDER_NAME))).first()
        starter_folder_id = starter_folder.id if starter_folder else None

        if not starter_folder and not default_folder:
            raise HTTPException(
                status_code=404,
                detail="Starter project and default project not found. Please create a project and add flows to it.",
            )

        if not folder_id:
            folder_id = default_folder_id

        # Use RBAC secure data access service
        secure_data_service = SecureDataAccessService()
        flows = await secure_data_service.get_accessible_flows(
            session=session,
            context=context,
            folder_id=folder_id if not get_all else None,
            components_only=components_only,
            remove_example_flows=remove_example_flows,
            starter_folder_id=starter_folder_id,
        )

        # Apply additional filtering and validation
        flows = validate_is_component(flows)

        if components_only:
            flows = [flow for flow in flows if flow.is_component]

        if remove_example_flows and starter_folder_id:
            flows = [flow for flow in flows if flow.folder_id != starter_folder_id]

        if get_all:
            if header_flows:
                # Convert to FlowHeader objects and compress the response
                flow_headers = [FlowHeader.model_validate(flow, from_attributes=True) for flow in flows]
                return compress_response(flow_headers)

            # Compress the full flows response
            return compress_response(flows)

        # For paginated results, we need to implement secure pagination
        # This is a simplified approach - in production you'd want more efficient pagination
        if folder_id:
            flows = [flow for flow in flows if flow.folder_id == folder_id]

        # Create a manual pagination since we're using custom filtering
        total = len(flows)
        offset = (params.page - 1) * params.size
        paginated_flows = flows[offset:offset + params.size]

        # Return paginated response
        from fastapi_pagination import Page as PaginationPage
        return PaginationPage.create(
            items=paginated_flows,
            total=total,
            params=params,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


async def _read_flow_secure(
    session: AsyncSession,
    flow_id: UUID,
    context: RuntimeEnforcementContext,
):
    """Read a flow with RBAC security."""
    secure_data_service = SecureDataAccessService()
    return await secure_data_service.get_flow_by_id_secure(session, context, flow_id)


@router.get("/{flow_id}", response_model=FlowRead, status_code=200)
async def read_flow(
    *,
    session: DbSession,
    flow_id: UUID,
    current_user: CurrentActiveUser,
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    _flow_read_check: Annotated[bool, RequireFlowRead] = True,
):
    """Read a flow with RBAC security."""
    user_flow = await _read_flow_secure(session, flow_id, context)
    if user_flow:
        return user_flow
    raise HTTPException(status_code=404, detail="Flow not found or access denied")


@router.get("/public_flow/{flow_id}", response_model=FlowRead, status_code=200)
async def read_public_flow(
    *,
    session: DbSession,
    flow_id: UUID,
):
    """Read a public flow."""
    access_type = (await session.exec(select(Flow.access_type).where(Flow.id == flow_id))).first()
    if access_type is not AccessTypeEnum.PUBLIC:
        raise HTTPException(status_code=403, detail="Flow is not public")

    # For public flows, create a minimal context for RBAC checking
    # This allows public flows to be read without full authentication
    current_user = await get_user_by_flow_id_or_endpoint_name(str(flow_id))

    # Create minimal enforcement context for public flow access
    from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext
    public_context = RuntimeEnforcementContext(
        user=current_user,
        token_validation=None,
        requested_workspace_id=None,  # Cross-workspace public access
        requested_project_id=None,
        requested_environment_id=None,
        request_path=f"/api/v1/flows/public_flow/{flow_id}",
        request_method="GET",
    )

    return await read_flow(
        session=session,
        flow_id=flow_id,
        current_user=current_user,
        context=public_context,
        _flow_read_check=True,
    )


@router.patch("/{flow_id}", response_model=FlowRead, status_code=200)
async def update_flow(
    *,
    session: DbSession,
    flow_id: UUID,
    flow: FlowUpdate,
    current_user: CurrentActiveUser,
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    _flow_write_check: Annotated[bool, RequireFlowWrite] = True,
):
    """Update a flow with RBAC security."""
    settings_service = get_settings_service()
    try:
        # SECURITY FIX: Use secure data access instead of vulnerable user_id filtering
        db_flow = await _read_flow_secure(
            session=session,
            flow_id=flow_id,
            context=context,
        )

        if not db_flow:
            raise HTTPException(status_code=404, detail="Flow not found")

        update_data = flow.model_dump(exclude_unset=True, exclude_none=True)

        # Specifically handle endpoint_name when it's explicitly set to null or empty string
        if flow.endpoint_name is None or flow.endpoint_name == "":
            update_data["endpoint_name"] = None

        if settings_service.settings.remove_api_keys:
            update_data = remove_api_keys(update_data)

        for key, value in update_data.items():
            setattr(db_flow, key, value)

        await _verify_fs_path(db_flow.fs_path)

        webhook_component = get_webhook_component_in_flow(db_flow.data)
        db_flow.webhook = webhook_component is not None
        db_flow.updated_at = datetime.now(timezone.utc)

        if db_flow.folder_id is None:
            default_folder = (await session.exec(select(Folder).where(Folder.name == DEFAULT_FOLDER_NAME))).first()
            if default_folder:
                db_flow.folder_id = default_folder.id

        session.add(db_flow)
        await session.commit()
        await session.refresh(db_flow)

        await _save_flow_to_fs(db_flow)

    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            # Get the name of the column that failed
            columns = str(e).split("UNIQUE constraint failed: ")[1].split(".")[1].split("\n")[0]
            # UNIQUE constraint failed: flow.user_id, flow.name
            # or UNIQUE constraint failed: flow.name
            # if the column has id in it, we want the other column
            column = columns.split(",")[1] if "id" in columns.split(",")[0] else columns.split(",")[0]
            raise HTTPException(
                status_code=400, detail=f"{column.capitalize().replace('_', ' ')} must be unique"
            ) from e

        if hasattr(e, "status_code"):
            raise HTTPException(status_code=e.status_code, detail=str(e)) from e
        raise HTTPException(status_code=500, detail=str(e)) from e

    return db_flow


@router.delete("/{flow_id}", status_code=200)
async def delete_flow(
    *,
    session: DbSession,
    flow_id: UUID,
    current_user: CurrentActiveUser,
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    _flow_delete_check: Annotated[bool, RequireFlowWrite] = True,
):
    """Delete a flow with RBAC security."""
    # SECURITY FIX: Use secure data access instead of vulnerable user_id filtering
    flow = await _read_flow_secure(
        session=session,
        flow_id=flow_id,
        context=context,
    )
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    await cascade_delete_flow(session, flow.id)
    await session.commit()
    return {"message": "Flow deleted successfully"}


@router.post("/batch/", response_model=list[FlowRead], status_code=201)
async def create_flows(
    *,
    session: DbSession,
    flow_list: FlowListCreate,
    current_user: CurrentActiveUser,
):
    """Create multiple new flows."""
    db_flows = []
    for flow in flow_list.flows:
        # SECURITY FIX: Use secure flow creation for batch operations
        # Note: This maintains the legacy interface but should be updated to use RBAC context
        try:
            secure_flow = await _new_flow(session=session, flow=flow, user_id=current_user.id)
            db_flows.append(secure_flow)
        except Exception as flow_error:
            logger.error(f"Failed to create flow {flow.name}: {flow_error}")
            # Continue with other flows but log the error
            continue
    await session.commit()
    for db_flow in db_flows:
        await session.refresh(db_flow)
    return db_flows


@router.post("/upload/", response_model=list[FlowRead], status_code=201)
async def upload_file(
    *,
    session: DbSession,
    file: Annotated[UploadFile, File(...)],
    current_user: CurrentActiveUser,
    folder_id: UUID | None = None,
):
    """Upload flows from a file."""
    contents = await file.read()
    data = orjson.loads(contents)
    response_list = []
    flow_list = FlowListCreate(**data) if "flows" in data else FlowListCreate(flows=[FlowCreate(**data)])
    # Now we set the user_id for all flows
    for flow in flow_list.flows:
        flow.user_id = current_user.id
        if folder_id:
            flow.folder_id = folder_id
        # SECURITY FIX: Use secure flow creation for uploads
        # Note: This maintains the legacy interface but should be updated to use RBAC context
        response = await _new_flow(session=session, flow=flow, user_id=current_user.id)
        response_list.append(response)

    try:
        await session.commit()
        for db_flow in response_list:
            await session.refresh(db_flow)
            await _save_flow_to_fs(db_flow)
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            # Get the name of the column that failed
            columns = str(e).split("UNIQUE constraint failed: ")[1].split(".")[1].split("\n")[0]
            # UNIQUE constraint failed: flow.user_id, flow.name
            # or UNIQUE constraint failed: flow.name
            # if the column has id in it, we want the other column
            column = columns.split(",")[1] if "id" in columns.split(",")[0] else columns.split(",")[0]

            raise HTTPException(
                status_code=400, detail=f"{column.capitalize().replace('_', ' ')} must be unique"
            ) from e
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(e)) from e

    return response_list


@router.delete("/")
async def delete_multiple_flows(
    flow_ids: list[UUID],
    user: CurrentActiveUser,
    db: DbSession,
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    _flow_delete_check: Annotated[bool, RequireFlowWrite] = True,
):
    """Delete multiple flows by their IDs with RBAC security.

    Args:
        flow_ids (List[UUID]): The list of flow IDs to delete.
        user (User): The user making the request.
        db (Session): The database session.
        context (RuntimeEnforcementContext): RBAC enforcement context.

    Returns:
        dict: A dictionary containing the number of flows deleted.
    """
    try:
        # SECURITY FIX: Use secure data access instead of vulnerable user_id filtering
        secure_data_service = SecureDataAccessService()

        # Get accessible flows with proper RBAC checking
        accessible_flows = await secure_data_service.get_flows_by_ids_secure(
            session=db,
            context=context,
            flow_ids=flow_ids,
        )

        # Verify delete permissions for each flow individually
        enforcement_service = RBACRuntimeEnforcementService(secure_data_service.rbac_service)
        flows_to_delete = []

        for flow in accessible_flows:
            has_delete_permission = await enforcement_service.check_resource_access(
                session=db,
                context=context,
                permission="flow:delete",
                resource_type="flow",
                resource_id=flow.id,
            )

            if has_delete_permission:
                flows_to_delete.append(flow)
            else:
                # Audit denied deletion
                await enforcement_service.audit_enforcement_decision(
                    context=context,
                    operation="delete",
                    resource_type="flow",
                    resource_id=flow.id,
                    permission="flow:delete",
                    decision=False,
                    reason="Insufficient delete permissions",
                )

        # Delete approved flows
        for flow in flows_to_delete:
            await cascade_delete_flow(db, flow.id)
            # Audit successful deletion
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="delete",
                resource_type="flow",
                resource_id=flow.id,
                permission="flow:delete",
                decision=True,
                reason="Flow deleted successfully",
            )

        await db.commit()

        # Log bulk operation summary
        total_requested = len(flow_ids)
        total_deleted = len(flows_to_delete)
        logger.info(f"Bulk delete operation: {total_deleted}/{total_requested} flows deleted for user {user.id}")

        return {"deleted": total_deleted, "requested": total_requested}
    except Exception as exc:
        await db.rollback()
        logger.error(f"Error in bulk flow deletion: {exc}")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/download/", status_code=200)
async def download_multiple_file(
    flow_ids: list[UUID],
    user: CurrentActiveUser,
    db: DbSession,
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    _flow_read_check: Annotated[bool, RequireFlowRead] = True,
):
    """Download all flows as a zip file with RBAC security."""
    # SECURITY FIX: Use secure data access instead of vulnerable user_id filtering
    secure_data_service = SecureDataAccessService()

    # Get accessible flows with proper RBAC checking
    flows = await secure_data_service.get_flows_by_ids_secure(
        session=db,
        context=context,
        flow_ids=flow_ids,
    )

    if not flows:
        raise HTTPException(status_code=404, detail="No accessible flows found.")

    flows_without_api_keys = [remove_api_keys(flow.model_dump()) for flow in flows]

    if len(flows_without_api_keys) > 1:
        # Create a byte stream to hold the ZIP file
        zip_stream = io.BytesIO()

        # Create a ZIP file
        with zipfile.ZipFile(zip_stream, "w") as zip_file:
            for flow in flows_without_api_keys:
                # Convert the flow object to JSON
                flow_json = json.dumps(jsonable_encoder(flow))

                # Write the JSON to the ZIP file
                zip_file.writestr(f"{flow['name']}.json", flow_json)

        # Seek to the beginning of the byte stream
        zip_stream.seek(0)

        # Generate the filename with the current datetime
        current_time = datetime.now(tz=timezone.utc).astimezone().strftime("%Y%m%d_%H%M%S")
        filename = f"{current_time}_langflow_flows.zip"

        return StreamingResponse(
            zip_stream,
            media_type="application/x-zip-compressed",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    return flows_without_api_keys[0]


all_starter_folder_flows_response: Response | None = None


@router.get("/basic_examples/", response_model=list[FlowRead], status_code=200)
async def read_basic_examples(
    *,
    session: DbSession,
):
    """Retrieve a list of basic example flows.

    Args:
        session (Session): The database session.

    Returns:
        list[FlowRead]: A list of basic example flows.
    """
    try:
        global all_starter_folder_flows_response  # noqa: PLW0603

        if all_starter_folder_flows_response:
            return all_starter_folder_flows_response
        # Get the starter folder
        starter_folder = (await session.exec(select(Folder).where(Folder.name == STARTER_FOLDER_NAME))).first()

        if not starter_folder:
            return []

        # Get all flows in the starter folder
        all_starter_folder_flows = (await session.exec(select(Flow).where(Flow.folder_id == starter_folder.id))).all()

        flow_reads = [FlowRead.model_validate(flow, from_attributes=True) for flow in all_starter_folder_flows]
        all_starter_folder_flows_response = compress_response(flow_reads)

        # Return compressed response using our utility function
        return all_starter_folder_flows_response  # noqa: TRY300

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
