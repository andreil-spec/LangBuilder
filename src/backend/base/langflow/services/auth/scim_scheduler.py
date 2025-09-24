"""SCIM Sync Scheduler Service.

This module provides scheduled SCIM synchronization functionality to automatically
sync users and groups from identity providers based on configured intervals.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from uuid import UUID

from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.auth.scim_service import SCIMProvisioningService
from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration
    from langflow.services.database.service import DatabaseService
    from langflow.services.task.service import TaskService


class SCIMSyncScheduler(Service):
    """Service for managing scheduled SCIM synchronization."""

    name = "scim_sync_scheduler"

    def __init__(
        self,
        task_service: "TaskService",
        database_service: "DatabaseService",
    ):
        self.task_service = task_service
        self.database_service = database_service
        self.scim_service = SCIMProvisioningService()
        self._scheduler_task = None
        self._shutdown_event = asyncio.Event()

    async def start_scheduler(self) -> None:
        """Start the SCIM sync scheduler."""
        if self._scheduler_task is not None:
            logger.warning("SCIM sync scheduler is already running")
            return

        logger.info("Starting SCIM sync scheduler")
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())

    async def stop_scheduler(self) -> None:
        """Stop the SCIM sync scheduler."""
        if self._scheduler_task is None:
            return

        logger.info("Stopping SCIM sync scheduler")
        self._shutdown_event.set()

        if self._scheduler_task:
            try:
                await asyncio.wait_for(self._scheduler_task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("SCIM sync scheduler did not stop gracefully, cancelling")
                self._scheduler_task.cancel()

        self._scheduler_task = None
        self._shutdown_event.clear()

    async def _scheduler_loop(self) -> None:
        """Main scheduler loop that checks for due SCIM sync operations."""
        logger.info("SCIM sync scheduler loop started")

        while not self._shutdown_event.is_set():
            try:
                await self._check_and_run_sync_jobs()
            except Exception as e:
                logger.error(f"Error in SCIM sync scheduler loop: {e}")

            # Check every 5 minutes for due sync jobs
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=300)
                break  # Shutdown event was set
            except asyncio.TimeoutError:
                continue  # Continue the loop

        logger.info("SCIM sync scheduler loop stopped")

    async def _check_and_run_sync_jobs(self) -> None:
        """Check for SSO configurations that need sync and run them."""
        async with self.database_service.with_session() as session:
            # Get all SSO configurations with SCIM enabled
            from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

            query = select(SSOConfiguration).where(
                SSOConfiguration.scim_enabled.is_(True) &
                SSOConfiguration.is_active.is_(True) &
                SSOConfiguration.scim_sync_interval_hours.is_not(None) &
                (SSOConfiguration.scim_sync_interval_hours > 0)
            )

            result = await session.exec(query)
            sso_configs = result.all()

            for config in sso_configs:
                if await self._is_sync_due(config):
                    logger.info(f"Starting scheduled SCIM sync for provider {config.name}")
                    # Launch sync as background task
                    await self.task_service.launch_task(
                        self._run_scim_sync,
                        config.id,
                    )

    async def _is_sync_due(self, config: "SSOConfiguration") -> bool:
        """Check if a SCIM sync is due for the given configuration."""
        if not config.scim_sync_interval_hours:
            return False

        if not config.last_scim_sync:
            # Never synced before, sync now
            return True

        # Check if enough time has passed since last sync
        now = datetime.now(timezone.utc)
        sync_interval = timedelta(hours=config.scim_sync_interval_hours)
        next_sync_time = config.last_scim_sync + sync_interval

        return now >= next_sync_time

    async def _run_scim_sync(self, config_id: UUID) -> None:
        """Run SCIM sync for a specific SSO configuration."""
        async with self.database_service.with_session() as session:
            try:
                # Get the SSO configuration
                from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

                config = await session.get(SSOConfiguration, config_id)
                if not config:
                    logger.error(f"SSO configuration {config_id} not found for SCIM sync")
                    return

                logger.info(f"Running SCIM sync for provider {config.name}")

                # Perform user sync
                await self._sync_users(session, config)

                # Perform group sync
                await self._sync_groups(session, config)

                # Update last sync time
                config.last_scim_sync = datetime.now(timezone.utc)
                session.add(config)
                await session.commit()

                logger.info(f"SCIM sync completed successfully for provider {config.name}")

            except Exception as e:
                logger.error(f"SCIM sync failed for provider {config_id}: {e}")
                await session.rollback()

    async def _sync_users(self, session: AsyncSession, config: "SSOConfiguration") -> None:
        """Sync users from identity provider."""
        try:
            # This would be implemented based on the specific identity provider
            # For now, we'll implement a basic sync that processes existing SCIM data

            # In a real implementation, this would:
            # 1. Fetch users from identity provider API
            # 2. Compare with local users
            # 3. Create/update/deactivate users as needed

            logger.info(f"User sync placeholder for provider {config.name}")

            # Example: Get users that were created/updated via SCIM for this provider
            from langflow.services.database.models.rbac.user_group import UserGroup, UserGroupMembership
            from langflow.services.database.models.user.model import User

            # Find users who are members of groups managed by this SSO provider
            user_query = select(User).join(
                UserGroupMembership, User.id == UserGroupMembership.user_id
            ).join(
                UserGroup, UserGroupMembership.group_id == UserGroup.id
            ).where(
                UserGroup.sso_provider_id == config.id
            ).distinct()

            result = await session.exec(user_query)
            users = result.all()

            logger.info(f"Found {len(users)} users associated with SCIM provider {config.name}")

        except Exception as e:
            logger.error(f"User sync failed for provider {config.name}: {e}")
            raise

    async def _sync_groups(self, session: AsyncSession, config: "SSOConfiguration") -> None:
        """Sync groups from identity provider."""
        try:
            # This would be implemented based on the specific identity provider
            # For now, we'll implement a basic sync that processes existing SCIM data

            logger.info(f"Group sync placeholder for provider {config.name}")

            # Example: Get groups managed by this SSO provider
            from langflow.services.database.models.rbac.user_group import UserGroup

            group_query = select(UserGroup).where(
                UserGroup.sso_provider_id == config.id
            )

            result = await session.exec(group_query)
            groups = result.all()

            logger.info(f"Found {len(groups)} groups managed by SCIM provider {config.name}")

            # In a real implementation, this would:
            # 1. Fetch groups from identity provider API
            # 2. Compare with local groups
            # 3. Create/update/delete groups as needed
            # 4. Sync group memberships

        except Exception as e:
            logger.error(f"Group sync failed for provider {config.name}: {e}")
            raise

    async def trigger_manual_sync(self, config_id: UUID) -> bool:
        """Manually trigger a SCIM sync for a specific configuration."""
        try:
            logger.info(f"Manually triggering SCIM sync for configuration {config_id}")
            await self.task_service.launch_task(self._run_scim_sync, config_id)
            return True
        except Exception as e:
            logger.error(f"Failed to trigger manual SCIM sync: {e}")
            return False

    async def get_sync_status(self, config_id: UUID) -> dict:
        """Get the current sync status for a configuration."""
        async with self.database_service.with_session() as session:
            from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

            config = await session.get(SSOConfiguration, config_id)
            if not config:
                return {"error": "Configuration not found"}

            next_sync = None
            if config.last_scim_sync and config.scim_sync_interval_hours:
                next_sync = config.last_scim_sync + timedelta(hours=config.scim_sync_interval_hours)

            return {
                "provider_name": config.name,
                "scim_enabled": config.scim_enabled,
                "sync_interval_hours": config.scim_sync_interval_hours,
                "last_sync": config.last_scim_sync.isoformat() if config.last_scim_sync else None,
                "next_sync": next_sync.isoformat() if next_sync else None,
                "sync_due": await self._is_sync_due(config),
            }
