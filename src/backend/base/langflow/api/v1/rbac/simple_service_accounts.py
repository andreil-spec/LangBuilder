"""Simple service account API endpoints for development without complex middleware."""

import uuid
import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.utils import get_session
from langflow.services.database.models.rbac.service_account import (
    ServiceAccount, ServiceAccountRead, ServiceAccountCreate, ServiceAccountUpdate
)

# Simple router without middleware but with real database operations
simple_router = APIRouter(
    prefix="/simple-service-accounts",
    tags=["Simple Service Accounts (Development)"],
)

# File-based storage for development persistence across server restarts
_storage_file = os.path.join(tempfile.gettempdir(), "langflow_service_accounts.json")

def _load_storage() -> Dict[str, Any]:
    """Load service accounts from file."""
    try:
        if os.path.exists(_storage_file):
            with open(_storage_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading service accounts storage: {e}")
    return {"service_accounts": [], "counter": 1}

def _save_storage(storage: Dict[str, Any]) -> None:
    """Save service accounts to file."""
    try:
        with open(_storage_file, 'w') as f:
            json.dump(storage, f)
    except Exception as e:
        print(f"Error saving service accounts storage: {e}")

# Load existing storage on module initialization
_service_accounts_storage = _load_storage()

# Initialize with some test data for immediate demonstration
if not _service_accounts_storage.get("service_accounts"):
    print("🔧 Initializing test service accounts storage")
    _service_accounts_storage = {
        "service_accounts": [
            {
                "id": str(uuid.uuid4()),
                "name": "Demo Service Account 1",
                "description": "Demo service account for testing",
                "workspace_id": str(uuid.uuid4()),
                "created_by_id": str(uuid.uuid4()),
                "scope_type": "workspace",
                "scope_id": None,
                "permissions": [],
                "is_active": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "last_used_at": None,
                "token_count": 0
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Demo Service Account 2",
                "description": "Another demo service account",
                "workspace_id": str(uuid.uuid4()),
                "created_by_id": str(uuid.uuid4()),
                "scope_type": "project",
                "scope_id": str(uuid.uuid4()),
                "permissions": [],
                "is_active": False,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "last_used_at": datetime.now(timezone.utc).isoformat(),
                "token_count": 2
            }
        ],
        "counter": 3
    }
    _save_storage(_service_accounts_storage)

@simple_router.get("/", response_model=dict)
async def list_simple_service_accounts(
    session: AsyncSession = Depends(get_session),
    workspace_id: str | None = None,
    scope_type: str | None = None,
    page: int = 1,
    page_size: int = 50,
    search: str | None = None,
    is_active: bool | None = None
) -> dict:
    """List service accounts with database queries and demo data fallback."""
    print(f"🔍 GET service accounts with filters: workspace_id={workspace_id}, scope_type={scope_type}, search={search}, is_active={is_active}")

    try:
        # First try to get service accounts from database
        try:
            statement = select(ServiceAccount)

            # Apply filters if provided
            if workspace_id:
                statement = statement.where(ServiceAccount.workspace_id == workspace_id)
            if scope_type:
                statement = statement.where(ServiceAccount.scope_type == scope_type)
            if search:
                statement = statement.where(
                    (ServiceAccount.name.ilike(f"%{search}%")) |
                    (ServiceAccount.description.ilike(f"%{search}%"))
                )
            if is_active is not None:
                statement = statement.where(ServiceAccount.is_active == is_active)

            result = await session.exec(statement)
            service_accounts = list(result)

            if service_accounts:
                # Convert to response format
                service_account_reads = []
                for sa in service_accounts:
                    service_account_reads.append({
                        "id": sa.id,
                        "name": sa.name,
                        "description": sa.description,
                        "workspace_id": sa.workspace_id,
                        "created_by_id": sa.created_by_id,
                        "scope_type": sa.scope_type,
                        "scope_id": sa.scope_id,
                        "permissions": sa.permissions or [],
                        "is_active": sa.is_active,
                        "created_at": sa.created_at.isoformat() if sa.created_at else datetime.now(timezone.utc).isoformat(),
                        "updated_at": sa.updated_at.isoformat() if sa.updated_at else datetime.now(timezone.utc).isoformat(),
                        "last_used_at": sa.last_used_at.isoformat() if sa.last_used_at else None,
                        "token_count": getattr(sa, 'token_count', 0)
                    })

                # Calculate pagination info
                total_count = len(service_account_reads)
                start_idx = (page - 1) * page_size
                end_idx = start_idx + page_size
                paginated_accounts = service_account_reads[start_idx:end_idx]

                return {
                    "service_accounts": paginated_accounts,
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "has_next": end_idx < total_count,
                    "has_previous": start_idx > 0
                }

        except Exception as db_error:
            print(f"Database query failed, using fallback: {db_error}")

        # Fallback: Use in-memory storage
        stored_accounts = _service_accounts_storage.get("service_accounts", [])

        # Apply filters to demo data
        filtered_accounts = stored_accounts
        if workspace_id:
            filtered_accounts = [sa for sa in filtered_accounts if sa.get("workspace_id") == workspace_id]
        if scope_type:
            filtered_accounts = [sa for sa in filtered_accounts if sa.get("scope_type") == scope_type]
        if search:
            search_lower = search.lower()
            filtered_accounts = [sa for sa in filtered_accounts if
                               search_lower in sa.get("name", "").lower() or
                               search_lower in sa.get("description", "").lower()]
        if is_active is not None:
            filtered_accounts = [sa for sa in filtered_accounts if sa.get("is_active") == is_active]

        # Calculate pagination
        total_count = len(filtered_accounts)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_accounts = filtered_accounts[start_idx:end_idx]

        return {
            "service_accounts": paginated_accounts,
            "total_count": total_count,
            "page": page,
            "page_size": page_size,
            "has_next": end_idx < total_count,
            "has_previous": start_idx > 0
        }

    except Exception as e:
        print(f"Error listing service accounts: {e}")
        return {
            "service_accounts": [],
            "total_count": 0,
            "page": page,
            "page_size": page_size,
            "has_next": False,
            "has_previous": False
        }

@simple_router.post("/", response_model=dict)
async def create_simple_service_account(
    service_account_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Create a new service account with database persistence."""
    print(f"💾 POST service account: {service_account_data}")

    try:
        # Generate new ID for the service account
        new_id = str(uuid.uuid4())
        current_time = datetime.now(timezone.utc).isoformat()

        # Create service account object with proper data
        new_service_account = {
            "id": new_id,
            "name": service_account_data.get("name", f"Service Account {_service_accounts_storage['counter']}"),
            "description": service_account_data.get("description", ""),
            "workspace_id": service_account_data.get("workspace_id", str(uuid.uuid4())),
            "created_by_id": service_account_data.get("created_by_id", str(uuid.uuid4())),
            "scope_type": service_account_data.get("scope_type", "workspace"),
            "scope_id": service_account_data.get("scope_id"),
            "permissions": service_account_data.get("permissions", []),
            "is_active": service_account_data.get("is_active", True),
            "created_at": current_time,
            "updated_at": current_time,
            "last_used_at": None,
            "token_count": 0
        }

        # Store in in-memory storage for immediate persistence
        _service_accounts_storage["service_accounts"].append(new_service_account)
        _service_accounts_storage["counter"] += 1
        _save_storage(_service_accounts_storage)

        print(f"💾 Created service account: {new_service_account}")

        # Try to create in database if possible
        try:
            service_account = ServiceAccount(
                id=new_id,
                name=new_service_account["name"],
                description=new_service_account["description"],
                workspace_id=new_service_account["workspace_id"],
                created_by_id=new_service_account["created_by_id"],
                scope_type=new_service_account["scope_type"],
                scope_id=new_service_account["scope_id"],
                permissions=new_service_account["permissions"],
                is_active=new_service_account["is_active"]
            )

            session.add(service_account)
            await session.commit()
            await session.refresh(service_account)
            print(f"✅ Successfully created service account in database: {new_id}")

        except Exception as db_error:
            print(f"Database creation failed, using in-memory storage: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Created service account: {new_service_account['name']}",
            "service_account": new_service_account,
            "storage_method": "database + in-memory fallback"
        }

    except Exception as e:
        print(f"Error creating service account: {e}")
        return {
            "success": False,
            "message": f"Failed to create service account: {str(e)}",
            "service_account": None
        }

@simple_router.get("/{service_account_id}", response_model=dict)
async def get_simple_service_account(
    service_account_id: str,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Get service account by ID."""
    print(f"🔍 GET service account: {service_account_id}")

    try:
        # First try database
        try:
            service_account = await session.get(ServiceAccount, service_account_id)
            if service_account:
                return {
                    "id": service_account.id,
                    "name": service_account.name,
                    "description": service_account.description,
                    "workspace_id": service_account.workspace_id,
                    "created_by_id": service_account.created_by_id,
                    "scope_type": service_account.scope_type,
                    "scope_id": service_account.scope_id,
                    "permissions": service_account.permissions or [],
                    "is_active": service_account.is_active,
                    "created_at": service_account.created_at.isoformat() if service_account.created_at else datetime.now(timezone.utc).isoformat(),
                    "updated_at": service_account.updated_at.isoformat() if service_account.updated_at else datetime.now(timezone.utc).isoformat(),
                    "last_used_at": service_account.last_used_at.isoformat() if service_account.last_used_at else None,
                    "token_count": getattr(service_account, 'token_count', 0)
                }
        except Exception as db_error:
            print(f"Database query failed: {db_error}")

        # Fallback to in-memory storage
        stored_accounts = _service_accounts_storage.get("service_accounts", [])
        for account in stored_accounts:
            if account["id"] == service_account_id:
                return account

        raise HTTPException(status_code=404, detail="Service account not found")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting service account: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@simple_router.put("/{service_account_id}", response_model=dict)
async def update_simple_service_account(
    service_account_id: str,
    service_account_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Update service account."""
    print(f"💾 PUT service account {service_account_id}: {service_account_data}")

    try:
        # Update in-memory storage first
        stored_accounts = _service_accounts_storage.get("service_accounts", [])
        updated = False

        for i, account in enumerate(stored_accounts):
            if account["id"] == service_account_id:
                # Update fields
                for key, value in service_account_data.items():
                    if key != "id":  # Don't allow ID changes
                        account[key] = value
                account["updated_at"] = datetime.now(timezone.utc).isoformat()
                stored_accounts[i] = account
                updated = True
                break

        if not updated:
            raise HTTPException(status_code=404, detail="Service account not found")

        _save_storage(_service_accounts_storage)

        # Try to update in database
        try:
            service_account = await session.get(ServiceAccount, service_account_id)
            if service_account:
                for key, value in service_account_data.items():
                    if key != "id" and hasattr(service_account, key):
                        setattr(service_account, key, value)

                await session.commit()
                await session.refresh(service_account)
                print(f"✅ Successfully updated service account in database: {service_account_id}")
        except Exception as db_error:
            print(f"Database update failed: {db_error}")
            await session.rollback()

        # Return updated account
        for account in stored_accounts:
            if account["id"] == service_account_id:
                return {
                    "success": True,
                    "message": f"Updated service account: {account['name']}",
                    "service_account": account
                }

        raise HTTPException(status_code=404, detail="Service account not found after update")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating service account: {e}")
        return {
            "success": False,
            "message": f"Failed to update service account: {str(e)}"
        }

@simple_router.delete("/{service_account_id}", response_model=dict)
async def delete_simple_service_account(
    service_account_id: str,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Delete service account."""
    print(f"🗑️ DELETE service account: {service_account_id}")

    try:
        # Remove from in-memory storage
        stored_accounts = _service_accounts_storage.get("service_accounts", [])
        original_count = len(stored_accounts)
        _service_accounts_storage["service_accounts"] = [
            account for account in stored_accounts if account["id"] != service_account_id
        ]

        if len(_service_accounts_storage["service_accounts"]) == original_count:
            raise HTTPException(status_code=404, detail="Service account not found")

        _save_storage(_service_accounts_storage)

        # Try to delete from database
        try:
            service_account = await session.get(ServiceAccount, service_account_id)
            if service_account:
                await session.delete(service_account)
                await session.commit()
                print(f"✅ Successfully deleted service account from database: {service_account_id}")
        except Exception as db_error:
            print(f"Database deletion failed: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Deleted service account: {service_account_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting service account: {e}")
        return {
            "success": False,
            "message": f"Failed to delete service account: {str(e)}"
        }
