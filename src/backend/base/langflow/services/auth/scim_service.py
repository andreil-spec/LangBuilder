"""SCIM (System for Cross-domain Identity Management) provisioning service.

This module provides automated user and group lifecycle management following
SCIM 2.0 protocol and LangBuilder service patterns.
"""

# NO future annotations per Phase 1 requirements
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

from loguru import logger
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.user_group import UserGroup
    from langflow.services.database.models.user.model import User


class SCIMResourceType(str, Enum):
    """SCIM resource types."""

    USER = "User"
    GROUP = "Group"


class SCIMOperationType(str, Enum):
    """SCIM operation types."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    ACTIVATE = "activate"
    DEACTIVATE = "deactivate"


class SCIMUserStatus(str, Enum):
    """SCIM user status values."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


@dataclass
class SCIMName:
    """SCIM name structure."""

    formatted: str | None = None
    family_name: str | None = None
    given_name: str | None = None
    middle_name: str | None = None
    honorific_prefix: str | None = None
    honorific_suffix: str | None = None


@dataclass
class SCIMEmail:
    """SCIM email structure."""

    value: str
    type: str = "work"
    primary: bool = True


@dataclass
class SCIMGroup:
    """SCIM group reference."""

    value: str  # Group ID
    display: str  # Group name
    type: str = "direct"


class SCIMUserResource(BaseModel):
    """SCIM User resource representation."""

    id: str | None = None
    external_id: str | None = None
    user_name: str
    name: SCIMName | None = None
    display_name: str | None = None
    emails: list[SCIMEmail] = []
    active: bool = True
    groups: list[SCIMGroup] = []
    title: str | None = None
    department: str | None = None
    organization: str | None = None
    created: datetime | None = None
    last_modified: datetime | None = None


class SCIMGroupResource(BaseModel):
    """SCIM Group resource representation."""

    id: str | None = None
    external_id: str | None = None
    display_name: str
    members: list[dict[str, str]] = []
    created: datetime | None = None
    last_modified: datetime | None = None


@dataclass
class SCIMSyncResult:
    """Result of SCIM synchronization operation."""

    success: bool
    resource_type: SCIMResourceType
    operation: SCIMOperationType
    resource_id: str | None = None
    error_message: str | None = None
    changes_applied: list[str] = None


class SCIMUserSynchronizer:
    """Handles SCIM user synchronization with LangBuilder users."""

    def __init__(self, session: AsyncSession):
        """Initialize user synchronizer.

        Args:
            session: Database session for operations
        """
        self.session = session

    async def sync_user(
        self,
        scim_user: SCIMUserResource,
        provider_id: UUIDstr,
        dry_run: bool = False,
    ) -> SCIMSyncResult:
        """Synchronize SCIM user with LangBuilder user.

        Args:
            scim_user: SCIM user resource
            provider_id: SSO provider ID
            dry_run: If True, only validate without making changes

        Returns:
            Synchronization result
        """
        try:

            # Find existing user by external ID or email
            existing_user = await self._find_existing_user(scim_user)

            if existing_user:
                # Update existing user
                return await self._update_user(
                    existing_user, scim_user, provider_id, dry_run
                )
            # Create new user
            return await self._create_user(scim_user, provider_id, dry_run)

        except Exception as e:
            logger.error(f"SCIM user sync failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.USER,
                operation=SCIMOperationType.UPDATE,
                error_message=str(e)
            )

    async def deactivate_user(
        self,
        user_identifier: str,
        provider_id: UUIDstr,
        dry_run: bool = False,
    ) -> SCIMSyncResult:
        """Deactivate user from SCIM provider.

        Args:
            user_identifier: User external ID or email
            provider_id: SSO provider ID
            dry_run: If True, only validate without making changes

        Returns:
            Synchronization result
        """
        try:
            from langflow.services.database.models.user.model import User

            # Find user
            user_query = select(User).where(
                (User.external_id == user_identifier) |
                (User.email == user_identifier)
            )
            result = await self.session.exec(user_query)
            user = result.first()

            if not user:
                return SCIMSyncResult(
                    success=False,
                    resource_type=SCIMResourceType.USER,
                    operation=SCIMOperationType.DEACTIVATE,
                    error_message=f"User {user_identifier} not found"
                )

            if dry_run:
                return SCIMSyncResult(
                    success=True,
                    resource_type=SCIMResourceType.USER,
                    operation=SCIMOperationType.DEACTIVATE,
                    resource_id=str(user.id),
                    changes_applied=["User would be deactivated"]
                )

            # Deactivate user
            user.is_active = False
            user.updated_at = datetime.now(timezone.utc)

            await self.session.commit()

            logger.info(f"SCIM: Deactivated user {user.email}")

            return SCIMSyncResult(
                success=True,
                resource_type=SCIMResourceType.USER,
                operation=SCIMOperationType.DEACTIVATE,
                resource_id=str(user.id),
                changes_applied=["User deactivated"]
            )

        except Exception as e:
            logger.error(f"SCIM user deactivation failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.USER,
                operation=SCIMOperationType.DEACTIVATE,
                error_message=str(e)
            )

    async def _find_existing_user(self, scim_user: SCIMUserResource) -> Optional["User"]:
        """Find existing user by external ID or email."""
        from langflow.services.database.models.user.model import User

        # Try by external ID first
        if scim_user.external_id:
            user_query = select(User).where(User.external_id == scim_user.external_id)
            result = await self.session.exec(user_query)
            user = result.first()
            if user:
                return user

        # Try by primary email
        primary_email = None
        for email in scim_user.emails:
            if email.primary:
                primary_email = email.value
                break

        if not primary_email and scim_user.emails:
            primary_email = scim_user.emails[0].value

        if primary_email:
            user_query = select(User).where(User.email == primary_email)
            result = await self.session.exec(user_query)
            return result.first()

        return None

    async def _create_user(
        self,
        scim_user: SCIMUserResource,
        provider_id: UUIDstr,
        dry_run: bool,
    ) -> SCIMSyncResult:
        """Create new user from SCIM data."""
        import secrets

        from langflow.services.database.models.user.model import User

        try:
            # Get primary email
            primary_email = None
            for email in scim_user.emails:
                if email.primary:
                    primary_email = email.value
                    break

            if not primary_email and scim_user.emails:
                primary_email = scim_user.emails[0].value

            if not primary_email:
                return SCIMSyncResult(
                    success=False,
                    resource_type=SCIMResourceType.USER,
                    operation=SCIMOperationType.CREATE,
                    error_message="No email address provided in SCIM user"
                )

            # Extract name information
            first_name = None
            last_name = None
            if scim_user.name:
                first_name = scim_user.name.given_name
                last_name = scim_user.name.family_name

            # Generate display name
            display_name = scim_user.display_name
            if not display_name and scim_user.name and scim_user.name.formatted:
                display_name = scim_user.name.formatted
            elif not display_name and first_name and last_name:
                display_name = f"{first_name} {last_name}"
            elif not display_name:
                display_name = scim_user.user_name

            if dry_run:
                return SCIMSyncResult(
                    success=True,
                    resource_type=SCIMResourceType.USER,
                    operation=SCIMOperationType.CREATE,
                    changes_applied=[
                        f"User {primary_email} would be created",
                        f"Username: {scim_user.user_name}",
                        f"Display name: {display_name}",
                        f"Active: {scim_user.active}"
                    ]
                )

            # Create user
            new_user = User(
                username=scim_user.user_name,
                email=primary_email,
                first_name=first_name,
                last_name=last_name,
                external_id=scim_user.external_id,
                is_active=scim_user.active,
                is_superuser=False,
                password=secrets.token_urlsafe(32),  # Random password, SSO will be used
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

            self.session.add(new_user)
            await self.session.commit()
            await self.session.refresh(new_user)

            logger.info(f"SCIM: Created user {new_user.email}")

            return SCIMSyncResult(
                success=True,
                resource_type=SCIMResourceType.USER,
                operation=SCIMOperationType.CREATE,
                resource_id=str(new_user.id),
                changes_applied=[
                    "User created",
                    f"Email: {primary_email}",
                    f"Username: {scim_user.user_name}",
                    f"Active: {scim_user.active}"
                ]
            )

        except Exception as e:
            logger.error(f"SCIM user creation failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.USER,
                operation=SCIMOperationType.CREATE,
                error_message=str(e)
            )

    async def _update_user(
        self,
        existing_user: "User",
        scim_user: SCIMUserResource,
        provider_id: UUIDstr,
        dry_run: bool,
    ) -> SCIMSyncResult:
        """Update existing user with SCIM data."""
        try:
            changes = []

            # Get primary email
            primary_email = None
            for email in scim_user.emails:
                if email.primary:
                    primary_email = email.value
                    break

            if not primary_email and scim_user.emails:
                primary_email = scim_user.emails[0].value

            # Check for changes
            if primary_email and existing_user.email != primary_email:
                changes.append(f"Email: {existing_user.email} -> {primary_email}")
                if not dry_run:
                    existing_user.email = primary_email

            if scim_user.user_name != existing_user.username:
                changes.append(f"Username: {existing_user.username} -> {scim_user.user_name}")
                if not dry_run:
                    existing_user.username = scim_user.user_name

            if scim_user.active != existing_user.is_active:
                changes.append(f"Active: {existing_user.is_active} -> {scim_user.active}")
                if not dry_run:
                    existing_user.is_active = scim_user.active

            # Update name fields if provided
            if scim_user.name:
                if scim_user.name.given_name and existing_user.first_name != scim_user.name.given_name:
                    changes.append(f"First name: {existing_user.first_name} -> {scim_user.name.given_name}")
                    if not dry_run:
                        existing_user.first_name = scim_user.name.given_name

                if scim_user.name.family_name and existing_user.last_name != scim_user.name.family_name:
                    changes.append(f"Last name: {existing_user.last_name} -> {scim_user.name.family_name}")
                    if not dry_run:
                        existing_user.last_name = scim_user.name.family_name

            # Update external ID if provided
            if scim_user.external_id and existing_user.external_id != scim_user.external_id:
                changes.append(f"External ID: {existing_user.external_id} -> {scim_user.external_id}")
                if not dry_run:
                    existing_user.external_id = scim_user.external_id

            if changes and not dry_run:
                existing_user.updated_at = datetime.now(timezone.utc)
                await self.session.commit()

            if changes:
                logger.info(f"SCIM: Updated user {existing_user.email} with {len(changes)} changes")

            return SCIMSyncResult(
                success=True,
                resource_type=SCIMResourceType.USER,
                operation=SCIMOperationType.UPDATE,
                resource_id=str(existing_user.id),
                changes_applied=changes if changes else ["No changes needed"]
            )

        except Exception as e:
            logger.error(f"SCIM user update failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.USER,
                operation=SCIMOperationType.UPDATE,
                error_message=str(e)
            )


class SCIMGroupSynchronizer:
    """Handles SCIM group synchronization with LangBuilder user groups."""

    def __init__(self, session: AsyncSession):
        """Initialize group synchronizer.

        Args:
            session: Database session for operations
        """
        self.session = session

    async def sync_group(
        self,
        scim_group: SCIMGroupResource,
        provider_id: UUIDstr,
        dry_run: bool = False,
    ) -> SCIMSyncResult:
        """Synchronize SCIM group with LangBuilder user group.

        Args:
            scim_group: SCIM group resource
            provider_id: SSO provider ID
            dry_run: If True, only validate without making changes

        Returns:
            Synchronization result
        """
        try:

            # Find existing group by external ID or name
            existing_group = await self._find_existing_group(scim_group, provider_id)

            if existing_group:
                # Update existing group
                return await self._update_group(
                    existing_group, scim_group, provider_id, dry_run
                )
            # Create new group
            return await self._create_group(scim_group, provider_id, dry_run)

        except Exception as e:
            logger.error(f"SCIM group sync failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.GROUP,
                operation=SCIMOperationType.UPDATE,
                error_message=str(e)
            )

    async def sync_group_membership(
        self,
        group_id: str,
        member_ids: list[str],
        provider_id: UUIDstr,
        dry_run: bool = False,
    ) -> list[SCIMSyncResult]:
        """Synchronize group membership.

        Args:
            group_id: Group external ID
            member_ids: List of user external IDs
            provider_id: SSO provider ID
            dry_run: If True, only validate without making changes

        Returns:
            List of synchronization results
        """
        results = []

        try:
            from langflow.services.database.models.rbac.user_group import UserGroup, UserGroupMembership
            from langflow.services.database.models.user.model import User

            # Find the group
            group_query = select(UserGroup).where(
                UserGroup.external_id == group_id,
                UserGroup.sso_provider_id == UUID(provider_id)
            )
            result = await self.session.exec(group_query)
            group = result.first()

            if not group:
                results.append(SCIMSyncResult(
                    success=False,
                    resource_type=SCIMResourceType.GROUP,
                    operation=SCIMOperationType.UPDATE,
                    error_message=f"Group {group_id} not found"
                ))
                return results

            # Get current group members
            current_members_query = select(UserGroupMembership).where(
                UserGroupMembership.group_id == group.id,
                UserGroupMembership.is_active is True
            )
            current_members_result = await self.session.exec(current_members_query)
            current_memberships = current_members_result.all()

            current_user_ids = {str(membership.user_id) for membership in current_memberships}

            # Get target users
            target_users = []
            for member_id in member_ids:
                user_query = select(User).where(
                    (User.external_id == member_id) | (User.email == member_id)
                )
                user_result = await self.session.exec(user_query)
                user = user_result.first()
                if user:
                    target_users.append(user)

            target_user_ids = {str(user.id) for user in target_users}

            # Users to add
            users_to_add = [user for user in target_users if str(user.id) not in current_user_ids]

            # Users to remove (current members not in target list)
            users_to_remove_ids = current_user_ids - target_user_ids

            # Add new members
            for user in users_to_add:
                if dry_run:
                    results.append(SCIMSyncResult(
                        success=True,
                        resource_type=SCIMResourceType.GROUP,
                        operation=SCIMOperationType.UPDATE,
                        resource_id=str(group.id),
                        changes_applied=[f"User {user.email} would be added to group"]
                    ))
                else:
                    membership = UserGroupMembership(
                        user_id=user.id,
                        group_id=group.id,
                        is_active=True,
                        created_at=datetime.now(timezone.utc)
                    )
                    self.session.add(membership)

                    results.append(SCIMSyncResult(
                        success=True,
                        resource_type=SCIMResourceType.GROUP,
                        operation=SCIMOperationType.UPDATE,
                        resource_id=str(group.id),
                        changes_applied=[f"User {user.email} added to group"]
                    ))

            # Remove members no longer in SCIM group
            for membership in current_memberships:
                if str(membership.user_id) in users_to_remove_ids:
                    if dry_run:
                        results.append(SCIMSyncResult(
                            success=True,
                            resource_type=SCIMResourceType.GROUP,
                            operation=SCIMOperationType.UPDATE,
                            resource_id=str(group.id),
                            changes_applied=["User membership would be removed from group"]
                        ))
                    else:
                        membership.is_active = False
                        membership.updated_at = datetime.now(timezone.utc)

                        results.append(SCIMSyncResult(
                            success=True,
                            resource_type=SCIMResourceType.GROUP,
                            operation=SCIMOperationType.UPDATE,
                            resource_id=str(group.id),
                            changes_applied=["User membership removed from group"]
                        ))

            if not dry_run:
                await self.session.commit()

            logger.info(f"SCIM: Synchronized membership for group {group.name}")

        except Exception as e:
            logger.error(f"SCIM group membership sync failed: {e}")
            results.append(SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.GROUP,
                operation=SCIMOperationType.UPDATE,
                error_message=str(e)
            ))

        return results

    async def _find_existing_group(
        self,
        scim_group: SCIMGroupResource,
        provider_id: UUIDstr,
    ) -> Optional["UserGroup"]:
        """Find existing group by external ID or name."""
        from langflow.services.database.models.rbac.user_group import UserGroup

        # Try by external ID first
        if scim_group.external_id:
            group_query = select(UserGroup).where(
                UserGroup.external_id == scim_group.external_id,
                UserGroup.sso_provider_id == UUID(provider_id)
            )
            result = await self.session.exec(group_query)
            group = result.first()
            if group:
                return group

        # Try by display name
        group_query = select(UserGroup).where(
            UserGroup.name == scim_group.display_name,
            UserGroup.sso_provider_id == UUID(provider_id)
        )
        result = await self.session.exec(group_query)
        return result.first()

    async def _create_group(
        self,
        scim_group: SCIMGroupResource,
        provider_id: UUIDstr,
        dry_run: bool,
    ) -> SCIMSyncResult:
        """Create new group from SCIM data."""
        from langflow.services.database.models.rbac.user_group import UserGroup

        try:
            if dry_run:
                return SCIMSyncResult(
                    success=True,
                    resource_type=SCIMResourceType.GROUP,
                    operation=SCIMOperationType.CREATE,
                    changes_applied=[
                        f"Group {scim_group.display_name} would be created",
                        f"External ID: {scim_group.external_id}",
                        f"Members: {len(scim_group.members)}"
                    ]
                )

            # Create group
            new_group = UserGroup(
                name=scim_group.display_name,
                description=f"SCIM group: {scim_group.display_name}",
                external_id=scim_group.external_id,
                sso_provider_id=UUID(provider_id),
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

            self.session.add(new_group)
            await self.session.commit()
            await self.session.refresh(new_group)

            logger.info(f"SCIM: Created group {new_group.name}")

            return SCIMSyncResult(
                success=True,
                resource_type=SCIMResourceType.GROUP,
                operation=SCIMOperationType.CREATE,
                resource_id=str(new_group.id),
                changes_applied=[
                    "Group created",
                    f"Name: {scim_group.display_name}",
                    f"External ID: {scim_group.external_id}"
                ]
            )

        except Exception as e:
            logger.error(f"SCIM group creation failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.GROUP,
                operation=SCIMOperationType.CREATE,
                error_message=str(e)
            )

    async def _update_group(
        self,
        existing_group: "UserGroup",
        scim_group: SCIMGroupResource,
        provider_id: UUIDstr,
        dry_run: bool,
    ) -> SCIMSyncResult:
        """Update existing group with SCIM data."""
        try:
            changes = []

            # Check for changes
            if scim_group.display_name != existing_group.name:
                changes.append(f"Name: {existing_group.name} -> {scim_group.display_name}")
                if not dry_run:
                    existing_group.name = scim_group.display_name

            if scim_group.external_id and existing_group.external_id != scim_group.external_id:
                changes.append(f"External ID: {existing_group.external_id} -> {scim_group.external_id}")
                if not dry_run:
                    existing_group.external_id = scim_group.external_id

            if changes and not dry_run:
                existing_group.updated_at = datetime.now(timezone.utc)
                await self.session.commit()

            if changes:
                logger.info(f"SCIM: Updated group {existing_group.name} with {len(changes)} changes")

            return SCIMSyncResult(
                success=True,
                resource_type=SCIMResourceType.GROUP,
                operation=SCIMOperationType.UPDATE,
                resource_id=str(existing_group.id),
                changes_applied=changes if changes else ["No changes needed"]
            )

        except Exception as e:
            logger.error(f"SCIM group update failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.GROUP,
                operation=SCIMOperationType.UPDATE,
                error_message=str(e)
            )


class SCIMProvisioningService(Service):
    """SCIM provisioning service for automated user lifecycle management."""

    name = "scim_provisioning_service"

    def __init__(self):
        super().__init__()
        self._sync_stats = {
            "users_created": 0,
            "users_updated": 0,
            "users_deactivated": 0,
            "groups_created": 0,
            "groups_updated": 0,
            "last_sync": None,
        }

    async def initialize_service(self) -> None:
        """Initialize SCIM provisioning service."""
        logger.info("SCIM provisioning service initialized")

    async def process_scim_user(
        self,
        session: AsyncSession,
        scim_user_data: dict[str, Any],
        provider_id: UUIDstr,
        operation: SCIMOperationType = SCIMOperationType.UPDATE,
        dry_run: bool = False,
    ) -> SCIMSyncResult:
        """Process SCIM user operation.

        Args:
            session: Database session
            scim_user_data: Raw SCIM user data
            provider_id: SSO provider ID
            operation: Type of operation to perform
            dry_run: If True, only validate without making changes

        Returns:
            Synchronization result
        """
        try:
            # Parse SCIM user data
            scim_user = self._parse_scim_user(scim_user_data)

            user_sync = SCIMUserSynchronizer(session)

            if operation == SCIMOperationType.DEACTIVATE:
                result = await user_sync.deactivate_user(
                    scim_user.external_id or scim_user.user_name,
                    provider_id,
                    dry_run
                )
            else:
                result = await user_sync.sync_user(scim_user, provider_id, dry_run)

            # Update stats
            if result.success and not dry_run:
                if result.operation == SCIMOperationType.CREATE:
                    self._sync_stats["users_created"] += 1
                elif result.operation == SCIMOperationType.UPDATE:
                    self._sync_stats["users_updated"] += 1
                elif result.operation == SCIMOperationType.DEACTIVATE:
                    self._sync_stats["users_deactivated"] += 1

            return result

        except Exception as e:
            logger.error(f"SCIM user processing failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.USER,
                operation=operation,
                error_message=str(e)
            )

    async def process_scim_group(
        self,
        session: AsyncSession,
        scim_group_data: dict[str, Any],
        provider_id: UUIDstr,
        dry_run: bool = False,
    ) -> SCIMSyncResult:
        """Process SCIM group operation.

        Args:
            session: Database session
            scim_group_data: Raw SCIM group data
            provider_id: SSO provider ID
            dry_run: If True, only validate without making changes

        Returns:
            Synchronization result
        """
        try:
            # Parse SCIM group data
            scim_group = self._parse_scim_group(scim_group_data)

            group_sync = SCIMGroupSynchronizer(session)
            result = await group_sync.sync_group(scim_group, provider_id, dry_run)

            # Update stats
            if result.success and not dry_run:
                if result.operation == SCIMOperationType.CREATE:
                    self._sync_stats["groups_created"] += 1
                elif result.operation == SCIMOperationType.UPDATE:
                    self._sync_stats["groups_updated"] += 1

            # Sync group membership if group data contains members
            if result.success and scim_group.members:
                member_ids = [member.get("value", "") for member in scim_group.members]
                await group_sync.sync_group_membership(
                    scim_group.external_id or scim_group.id,
                    member_ids,
                    provider_id,
                    dry_run
                )

            return result

        except Exception as e:
            logger.error(f"SCIM group processing failed: {e}")
            return SCIMSyncResult(
                success=False,
                resource_type=SCIMResourceType.GROUP,
                operation=SCIMOperationType.UPDATE,
                error_message=str(e)
            )

    def _parse_scim_user(self, scim_data: dict[str, Any]) -> SCIMUserResource:
        """Parse raw SCIM user data into structured format."""
        # Extract name information
        name = None
        if "name" in scim_data:
            name_data = scim_data["name"]
            name = SCIMName(
                formatted=name_data.get("formatted"),
                family_name=name_data.get("familyName"),
                given_name=name_data.get("givenName"),
                middle_name=name_data.get("middleName"),
                honorific_prefix=name_data.get("honorificPrefix"),
                honorific_suffix=name_data.get("honorificSuffix"),
            )

        # Extract emails
        emails = []
        if "emails" in scim_data:
            for email_data in scim_data["emails"]:
                emails.append(SCIMEmail(
                    value=email_data["value"],
                    type=email_data.get("type", "work"),
                    primary=email_data.get("primary", False)
                ))

        # Extract groups
        groups = []
        if "groups" in scim_data:
            for group_data in scim_data["groups"]:
                groups.append(SCIMGroup(
                    value=group_data["value"],
                    display=group_data.get("display", ""),
                    type=group_data.get("type", "direct")
                ))

        return SCIMUserResource(
            id=scim_data.get("id"),
            external_id=scim_data.get("externalId"),
            user_name=scim_data["userName"],
            name=name,
            display_name=scim_data.get("displayName"),
            emails=emails,
            active=scim_data.get("active", True),
            groups=groups,
            title=scim_data.get("title"),
            department=scim_data.get("department"),
            organization=scim_data.get("organization"),
        )

    def _parse_scim_group(self, scim_data: dict[str, Any]) -> SCIMGroupResource:
        """Parse raw SCIM group data into structured format."""
        members = scim_data.get("members", [])

        return SCIMGroupResource(
            id=scim_data.get("id"),
            external_id=scim_data.get("externalId"),
            display_name=scim_data["displayName"],
            members=members,
        )

    def get_sync_statistics(self) -> dict[str, Any]:
        """Get synchronization statistics.

        Returns:
            Dictionary with sync statistics
        """
        return {
            **self._sync_stats,
            "last_sync": self._sync_stats["last_sync"].isoformat() if self._sync_stats["last_sync"] else None
        }

    async def bulk_sync_users(
        self,
        session: AsyncSession,
        scim_users: list[dict[str, Any]],
        provider_id: UUIDstr,
        dry_run: bool = False,
    ) -> list[SCIMSyncResult]:
        """Bulk synchronize multiple users.

        Args:
            session: Database session
            scim_users: List of SCIM user data
            provider_id: SSO provider ID
            dry_run: If True, only validate without making changes

        Returns:
            List of synchronization results
        """
        results = []

        for user_data in scim_users:
            result = await self.process_scim_user(
                session, user_data, provider_id, SCIMOperationType.UPDATE, dry_run
            )
            results.append(result)

        if not dry_run:
            self._sync_stats["last_sync"] = datetime.now(timezone.utc)

        logger.info(f"SCIM: Bulk synced {len(scim_users)} users")
        return results
