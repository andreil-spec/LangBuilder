"""SSO integration with RBAC system for user provisioning and role assignment.

This module provides integration between SSO authentication results and RBAC
user/role management, following LangBuilder service patterns.
"""

# NO future annotations per Phase 1 requirements
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.auth.sso_service import SSOAuthenticationResult, SSOUserClaims
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.user_group import UserGroup
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User


class SSOUserProvisioningResult:
    """Result of SSO user provisioning operation."""

    def __init__(
        self,
        success: bool,
        user: Optional["User"] = None,
        created: bool = False,
        updated: bool = False,
        role_assignments: list[str] | None = None,
        group_memberships: list[str] | None = None,
        error_message: str | None = None,
    ):
        self.success = success
        self.user = user
        self.created = created
        self.updated = updated
        self.role_assignments = role_assignments or []
        self.group_memberships = group_memberships or []
        self.error_message = error_message


class RBACGroupMapping:
    """Mapping configuration for SSO groups to RBAC roles and workspaces."""

    def __init__(
        self,
        sso_group_name: str,
        workspace_id: UUIDstr | None = None,
        role_name: str | None = None,
        auto_create_workspace: bool = False,
        workspace_access_level: str = "member",
    ):
        self.sso_group_name = sso_group_name
        self.workspace_id = workspace_id
        self.role_name = role_name
        self.auto_create_workspace = auto_create_workspace
        self.workspace_access_level = workspace_access_level


class SSOUserProvisioner:
    """Handles user provisioning from SSO authentication into RBAC system."""

    def __init__(self, session: AsyncSession):
        """Initialize SSO user provisioner.

        Args:
            session: Database session for operations
        """
        self.session = session

    async def provision_user_from_sso(
        self,
        sso_result: "SSOAuthenticationResult",
        provider_id: UUIDstr,
        group_mappings: list[RBACGroupMapping] | None = None,
        auto_create_workspace: bool = False,
    ) -> SSOUserProvisioningResult:
        """Provision user from SSO authentication result.

        Args:
            sso_result: SSO authentication result with user claims
            provider_id: SSO provider ID
            group_mappings: Optional group to role mappings
            auto_create_workspace: Whether to auto-create personal workspace

        Returns:
            Provisioning result
        """
        if not sso_result.success or not sso_result.user_claims:
            return SSOUserProvisioningResult(
                success=False,
                error_message="Invalid SSO authentication result"
            )

        try:
            user_claims = sso_result.user_claims

            # Find or create user
            user = await self._find_or_create_user(user_claims, provider_id)
            if not user:
                return SSOUserProvisioningResult(
                    success=False,
                    error_message="Failed to create or find user"
                )

            created = not await self._user_exists(user_claims)
            updated = False

            # Update user attributes if changed
            if not created:
                updated = await self._update_user_attributes(user, user_claims)

            # Process group memberships and role assignments
            role_assignments = []
            group_memberships = []

            if user_claims.groups and group_mappings:
                assignments, memberships = await self._process_group_mappings(
                    user, user_claims.groups, group_mappings
                )
                role_assignments.extend(assignments)
                group_memberships.extend(memberships)

            # Create personal workspace if requested and user is new
            if created and auto_create_workspace:
                workspace = await self._create_personal_workspace(user)
                if workspace:
                    logger.info(f"Created personal workspace for SSO user {user.email}")

            await self.session.commit()

            logger.info(f"SSO user provisioning successful for {user.email}")

            return SSOUserProvisioningResult(
                success=True,
                user=user,
                created=created,
                updated=updated,
                role_assignments=role_assignments,
                group_memberships=group_memberships,
            )

        except Exception as e:
            logger.error(f"SSO user provisioning failed: {e}")
            await self.session.rollback()
            return SSOUserProvisioningResult(
                success=False,
                error_message=str(e)
            )

    async def _find_or_create_user(
        self,
        user_claims: "SSOUserClaims",
        provider_id: UUIDstr,
    ) -> Optional["User"]:
        """Find existing user or create new one."""
        import secrets

        from langflow.services.database.models.user.model import User

        # Try to find existing user by external ID or email
        existing_user = await self._find_existing_user(user_claims)
        if existing_user:
            # Update external ID if not set
            if not existing_user.external_id and user_claims.sub:
                existing_user.external_id = user_claims.sub
                existing_user.updated_at = datetime.now(timezone.utc)
            return existing_user

        # Create new user
        try:
            # Generate username if not provided
            username = user_claims.email.split("@")[0] if user_claims.email else user_claims.sub

            # Ensure username uniqueness
            base_username = username
            counter = 1
            while await self._username_exists(username):
                username = f"{base_username}_{counter}"
                counter += 1

            new_user = User(
                username=username,
                email=user_claims.email,
                first_name=user_claims.given_name,
                last_name=user_claims.family_name,
                external_id=user_claims.sub,
                is_active=True,
                is_superuser=False,
                password=secrets.token_urlsafe(32),  # Random password, SSO will be used
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

            self.session.add(new_user)
            await self.session.flush()  # Get ID without committing

            logger.info(f"Created new SSO user: {new_user.email}")
            return new_user

        except Exception as e:
            logger.error(f"User creation failed: {e}")
            return None

    async def _find_existing_user(self, user_claims: "SSOUserClaims") -> Optional["User"]:
        """Find existing user by external ID or email."""
        from langflow.services.database.models.user.model import User

        # Try by external ID first
        if user_claims.sub:
            user_query = select(User).where(User.external_id == user_claims.sub)
            result = await self.session.exec(user_query)
            user = result.first()
            if user:
                return user

        # Try by email
        if user_claims.email:
            user_query = select(User).where(User.email == user_claims.email)
            result = await self.session.exec(user_query)
            return result.first()

        return None

    async def _user_exists(self, user_claims: "SSOUserClaims") -> bool:
        """Check if user already exists."""
        existing = await self._find_existing_user(user_claims)
        return existing is not None

    async def _username_exists(self, username: str) -> bool:
        """Check if username already exists."""
        from langflow.services.database.models.user.model import User

        user_query = select(User).where(User.username == username)
        result = await self.session.exec(user_query)
        return result.first() is not None

    async def _update_user_attributes(
        self,
        user: "User",
        user_claims: "SSOUserClaims",
    ) -> bool:
        """Update user attributes if changed."""
        updated = False

        # Update email if changed
        if user_claims.email and user.email != user_claims.email:
            user.email = user_claims.email
            updated = True

        # Update name fields if provided and different
        if user_claims.given_name and user.first_name != user_claims.given_name:
            user.first_name = user_claims.given_name
            updated = True

        if user_claims.family_name and user.last_name != user_claims.family_name:
            user.last_name = user_claims.family_name
            updated = True

        # Update external ID if not set
        if user_claims.sub and not user.external_id:
            user.external_id = user_claims.sub
            updated = True

        if updated:
            user.updated_at = datetime.now(timezone.utc)
            logger.info(f"Updated SSO user attributes for {user.email}")

        return updated

    async def _process_group_mappings(
        self,
        user: "User",
        sso_groups: list[str],
        group_mappings: list[RBACGroupMapping],
    ) -> tuple[list[str], list[str]]:
        """Process SSO group mappings to RBAC roles and workspaces."""
        role_assignments = []
        group_memberships = []

        for group_name in sso_groups:
            # Find matching mapping
            mapping = None
            for gm in group_mappings:
                if gm.sso_group_name == group_name:
                    mapping = gm
                    break

            if not mapping:
                continue

            try:
                # Create workspace if needed
                workspace = None
                if mapping.workspace_id:
                    workspace = await self._get_or_create_workspace(
                        mapping.workspace_id, mapping.auto_create_workspace
                    )
                elif mapping.auto_create_workspace:
                    workspace = await self._create_group_workspace(group_name)

                # Assign role if specified
                if mapping.role_name and workspace:
                    role_assignment = await self._assign_user_role(
                        user, mapping.role_name, workspace
                    )
                    if role_assignment:
                        role_assignments.append(
                            f"{mapping.role_name} in {workspace.name}"
                        )

                # Add to user group
                user_group = await self._add_user_to_group(user, group_name, workspace)
                if user_group:
                    group_memberships.append(group_name)

            except Exception as e:
                logger.error(f"Failed to process group mapping {group_name}: {e}")

        return role_assignments, group_memberships

    async def _get_or_create_workspace(
        self,
        workspace_id: UUIDstr,
        auto_create: bool,
    ) -> Optional["Workspace"]:
        """Get existing workspace or create if auto_create is True."""
        from langflow.services.database.models.rbac.workspace import Workspace

        workspace = await self.session.get(Workspace, workspace_id)
        if workspace and not workspace.is_deleted:
            return workspace

        if auto_create:
            # In a real implementation, this would need more sophisticated logic
            logger.warning(f"Auto-creation of workspace {workspace_id} not implemented")

        return None

    async def _create_group_workspace(self, group_name: str) -> Optional["Workspace"]:
        """Create workspace for SSO group."""
        from langflow.services.database.models.rbac.workspace import Workspace

        try:
            # Create workspace for the group
            workspace = Workspace(
                name=f"SSO Group: {group_name}",
                description=f"Workspace for SSO group {group_name}",
                organization="SSO",
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

            self.session.add(workspace)
            await self.session.flush()

            logger.info(f"Created workspace for SSO group {group_name}")
            return workspace

        except Exception as e:
            logger.error(f"Failed to create workspace for group {group_name}: {e}")
            return None

    async def _create_personal_workspace(self, user: "User") -> Optional["Workspace"]:
        """Create personal workspace for user."""
        from langflow.services.database.models.rbac.workspace import Workspace

        try:
            workspace = Workspace(
                name=f"{user.first_name or user.username}'s Workspace",
                description=f"Personal workspace for {user.email}",
                owner_id=user.id,
                organization="Personal",
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

            self.session.add(workspace)
            await self.session.flush()

            # Assign workspace admin role
            await self._assign_workspace_admin_role(user, workspace)

            return workspace

        except Exception as e:
            logger.error(f"Failed to create personal workspace for {user.email}: {e}")
            return None

    async def _assign_user_role(
        self,
        user: "User",
        role_name: str,
        workspace: "Workspace",
    ) -> Optional["RoleAssignment"]:
        """Assign role to user in workspace."""
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.role_assignment import (
            AssignmentScope,
            AssignmentType,
            RoleAssignment,
        )

        try:
            # Find role
            role_query = select(Role).where(
                Role.name == role_name,
                Role.workspace_id == workspace.id,
                Role.is_active is True,
            )
            result = await self.session.exec(role_query)
            role = result.first()

            if not role:
                # Try to find system role
                role_query = select(Role).where(
                    Role.name == role_name,
                    Role.is_system is True,
                    Role.is_active is True,
                )
                result = await self.session.exec(role_query)
                role = result.first()

            if not role:
                logger.warning(f"Role {role_name} not found")
                return None

            # Check if assignment already exists
            assignment_query = select(RoleAssignment).where(
                RoleAssignment.user_id == user.id,
                RoleAssignment.role_id == role.id,
                RoleAssignment.workspace_id == workspace.id,
                RoleAssignment.is_active is True,
            )
            result = await self.session.exec(assignment_query)
            if result.first():
                return None  # Already assigned

            # Create role assignment
            assignment = RoleAssignment(
                user_id=user.id,
                role_id=role.id,
                workspace_id=workspace.id,
                assignment_type=AssignmentType.DIRECT,
                scope_type=AssignmentScope.WORKSPACE,
                scope_id=workspace.id,
                assigned_by_id=user.id,  # Self-assigned via SSO
                is_active=True,
                metadata={
                    "source": "sso_provisioning",
                    "auto_assigned": True,
                },
                created_at=datetime.now(timezone.utc),
            )

            self.session.add(assignment)
            await self.session.flush()

            logger.info(f"Assigned role {role_name} to {user.email} in {workspace.name}")
            return assignment

        except Exception as e:
            logger.error(f"Failed to assign role {role_name} to {user.email}: {e}")
            return None

    async def _assign_workspace_admin_role(
        self,
        user: "User",
        workspace: "Workspace",
    ) -> None:
        """Assign workspace admin role to user."""
        await self._assign_user_role(user, "Workspace Admin", workspace)

    async def _add_user_to_group(
        self,
        user: "User",
        group_name: str,
        workspace: Optional["Workspace"] = None,
    ) -> Optional["UserGroup"]:
        """Add user to user group."""
        from langflow.services.database.models.rbac.user_group import (
            UserGroup,
            UserGroupMembership,
        )

        try:
            # Find or create user group
            group_query = select(UserGroup).where(
                UserGroup.name == group_name,
                UserGroup.is_active is True,
            )
            if workspace:
                group_query = group_query.where(UserGroup.workspace_id == workspace.id)

            result = await self.session.exec(group_query)
            group = result.first()

            if not group:
                # Create user group
                group = UserGroup(
                    name=group_name,
                    description=f"SSO group: {group_name}",
                    workspace_id=workspace.id if workspace else None,
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
                self.session.add(group)
                await self.session.flush()

            # Check if membership exists
            membership_query = select(UserGroupMembership).where(
                UserGroupMembership.user_id == user.id,
                UserGroupMembership.group_id == group.id,
                UserGroupMembership.is_active is True,
            )
            result = await self.session.exec(membership_query)
            if result.first():
                return group  # Already a member

            # Create membership
            membership = UserGroupMembership(
                user_id=user.id,
                group_id=group.id,
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )

            self.session.add(membership)
            await self.session.flush()

            logger.info(f"Added {user.email} to group {group_name}")
            return group

        except Exception as e:
            logger.error(f"Failed to add {user.email} to group {group_name}: {e}")
            return None


class SSOIntegrationService(Service):
    """Service for integrating SSO with RBAC system."""

    name = "sso_integration_service"

    def __init__(self):
        super().__init__()
        self._provisioning_stats = {
            "users_created": 0,
            "users_updated": 0,
            "role_assignments_created": 0,
            "group_memberships_created": 0,
            "last_provisioning": None,
        }

    async def initialize_service(self) -> None:
        """Initialize SSO integration service."""
        logger.info("SSO integration service initialized")

    async def provision_user_from_sso(
        self,
        session: AsyncSession,
        sso_result: "SSOAuthenticationResult",
        provider_id: UUIDstr,
        group_mappings: list[RBACGroupMapping] | None = None,
        auto_create_workspace: bool = False,
    ) -> SSOUserProvisioningResult:
        """Provision user from SSO authentication.

        Args:
            session: Database session
            sso_result: SSO authentication result
            provider_id: SSO provider ID
            group_mappings: Group to role mappings
            auto_create_workspace: Whether to create personal workspace

        Returns:
            Provisioning result
        """
        provisioner = SSOUserProvisioner(session)
        result = await provisioner.provision_user_from_sso(
            sso_result, provider_id, group_mappings, auto_create_workspace
        )

        # Update stats
        if result.success:
            if result.created:
                self._provisioning_stats["users_created"] += 1
            if result.updated:
                self._provisioning_stats["users_updated"] += 1

            self._provisioning_stats["role_assignments_created"] += len(
                result.role_assignments
            )
            self._provisioning_stats["group_memberships_created"] += len(
                result.group_memberships
            )
            self._provisioning_stats["last_provisioning"] = datetime.now(timezone.utc)

        return result

    async def create_group_mappings_from_config(
        self,
        session: AsyncSession,
        provider_id: UUIDstr,
    ) -> list[RBACGroupMapping]:
        """Create group mappings from SSO provider configuration.

        Args:
            session: Database session
            provider_id: SSO provider ID

        Returns:
            List of group mappings
        """
        try:
            from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

            config = await session.get(SSOConfiguration, provider_id)
            if not config or not config.group_mappings:
                return []

            mappings = []
            for mapping_config in config.group_mappings:
                mapping = RBACGroupMapping(
                    sso_group_name=mapping_config.get("group_name", ""),
                    workspace_id=mapping_config.get("workspace_id"),
                    role_name=mapping_config.get("role_name"),
                    auto_create_workspace=mapping_config.get("auto_create_workspace", False),
                    workspace_access_level=mapping_config.get("access_level", "member"),
                )
                mappings.append(mapping)

            return mappings

        except Exception as e:
            logger.error(f"Failed to create group mappings: {e}")
            return []

    def get_provisioning_statistics(self) -> dict[str, Any]:
        """Get user provisioning statistics."""
        return {
            **self._provisioning_stats,
            "last_provisioning": (
                self._provisioning_stats["last_provisioning"].isoformat()
                if self._provisioning_stats["last_provisioning"]
                else None
            ),
        }

    async def sync_user_groups_from_sso(
        self,
        session: AsyncSession,
        user: "User",
        sso_groups: list[str],
        provider_id: UUIDstr,
    ) -> list[str]:
        """Sync user group memberships from SSO claims.

        Args:
            session: Database session
            user: User to sync groups for
            sso_groups: List of SSO group names
            provider_id: SSO provider ID

        Returns:
            List of synchronized group names
        """
        synchronized_groups = []

        try:
            from langflow.services.database.models.rbac.user_group import (
                UserGroup,
                UserGroupMembership,
            )

            # Get existing SSO-managed group memberships
            existing_query = select(UserGroupMembership).join(UserGroup).where(
                UserGroupMembership.user_id == user.id,
                UserGroupMembership.is_active is True,
                UserGroup.sso_provider_id == UUID(provider_id),
            )
            result = await session.exec(existing_query)
            existing_memberships = result.all()

            existing_group_names = {
                membership.group.name for membership in existing_memberships
                if membership.group
            }

            # Add user to new groups
            for group_name in sso_groups:
                if group_name not in existing_group_names:
                    provisioner = SSOUserProvisioner(session)
                    group = await provisioner._add_user_to_group(user, group_name)
                    if group:
                        synchronized_groups.append(group_name)

            # Remove user from groups no longer in SSO
            for membership in existing_memberships:
                if membership.group and membership.group.name not in sso_groups:
                    membership.is_active = False
                    membership.updated_at = datetime.now(timezone.utc)

            await session.commit()

            logger.info(f"Synchronized {len(synchronized_groups)} groups for {user.email}")

        except Exception as e:
            logger.error(f"Group synchronization failed: {e}")
            await session.rollback()

        return synchronized_groups
