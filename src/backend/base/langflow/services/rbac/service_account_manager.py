"""Service account token generation and management system.

This module provides comprehensive service account management including
token generation, rotation, scoping, and security controls.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.service_account import (
        ServiceAccount,
        ServiceAccountToken,
    )


class ServiceAccountTokenGenerator:
    """Secure token generator for service accounts."""

    # Token format: prefix_base32(16_bytes)_checksum(4_bytes)
    TOKEN_LENGTH = 32  # bytes for the main token
    CHECKSUM_LENGTH = 4  # bytes for checksum
    DEFAULT_PREFIX = "sa_"

    @classmethod
    def generate_token(cls, prefix: str = DEFAULT_PREFIX) -> tuple[str, str]:
        """Generate a new service account token.

        Args:
            prefix: Token prefix for identification

        Returns:
            Tuple of (full_token, token_hash)
        """
        # Generate random token bytes
        token_bytes = secrets.token_bytes(cls.TOKEN_LENGTH)

        # Create checksum
        checksum = hashlib.sha256(token_bytes).digest()[:cls.CHECKSUM_LENGTH]

        # Combine token and checksum
        full_token_bytes = token_bytes + checksum

        # Encode as base32 (URL-safe, no padding)
        token_body = secrets.token_urlsafe(len(full_token_bytes))

        # Create full token with prefix
        full_token = f"{prefix}{token_body}"

        # Hash for storage
        token_hash = cls._hash_token(full_token)

        return full_token, token_hash

    @classmethod
    def verify_token(cls, token: str, stored_hash: str) -> bool:
        """Verify a token against its stored hash.

        Args:
            token: Full token to verify
            stored_hash: Stored hash to verify against

        Returns:
            True if token is valid
        """
        try:
            computed_hash = cls._hash_token(token)
            return secrets.compare_digest(computed_hash, stored_hash)
        except Exception:
            return False

    @classmethod
    def extract_prefix(cls, token: str) -> str:
        """Extract prefix from token.

        Args:
            token: Full token

        Returns:
            Token prefix
        """
        # Find the first underscore after the prefix
        parts = token.split("_", 1)
        if len(parts) >= 2:
            return f"{parts[0]}_"
        return cls.DEFAULT_PREFIX

    @classmethod
    def _hash_token(cls, token: str) -> str:
        """Hash a token for secure storage."""
        return hashlib.sha256(token.encode()).hexdigest()


class ServiceAccountManager(Service):
    """Service for managing service accounts and tokens."""

    name = "service_account_manager"

    def __init__(self):
        super().__init__()
        self._token_generator = ServiceAccountTokenGenerator()

    async def create_service_account(
        self,
        session: AsyncSession,
        workspace_id: UUIDstr,
        name: str,
        created_by: UUIDstr,
        *,
        description: str | None = None,
        service_type: str = "api",
        integration_name: str | None = None,
        token_prefix: str = "sa_",
        max_tokens: int = 5,
        token_expiry_days: int | None = 365,
        allowed_ips: list[str] | None = None,
        allowed_origins: list[str] | None = None,
        rate_limit_per_minute: int | None = None,
        default_scope_type: str = "workspace",
        default_scope_id: UUIDstr | None = None,
        allowed_permissions: list[str] | None = None,
        service_metadata: dict | None = None,
        tags: list[str] | None = None,
        expires_at: datetime | None = None
    ) -> dict[str, Any]:
        """Create a new service account.

        Args:
            session: Database session
            workspace_id: Workspace ID
            name: Service account name
            created_by: User creating the service account
            description: Optional description
            service_type: Type of service (api, webhook, integration, bot)
            integration_name: Integration name (e.g., github, slack)
            token_prefix: Prefix for generated tokens
            max_tokens: Maximum number of active tokens
            token_expiry_days: Default token expiry in days
            allowed_ips: Allowed IP addresses
            allowed_origins: Allowed origins for CORS
            rate_limit_per_minute: Rate limit per minute
            default_scope_type: Default scope type
            default_scope_id: Default scope ID
            allowed_permissions: Allowed permissions
            service_metadata: Additional metadata
            tags: Tags for organization
            expires_at: Service account expiry

        Returns:
            Service account creation result
        """
        try:
            from langflow.services.database.models.rbac.service_account import ServiceAccount

            # Validate workspace exists
            from langflow.services.database.models.rbac.workspace import Workspace

            workspace = await session.get(Workspace, workspace_id)
            if not workspace:
                return {"success": False, "error": "Workspace not found"}

            # Check for duplicate name
            existing_query = select(ServiceAccount).where(
                ServiceAccount.workspace_id == workspace_id,
                ServiceAccount.name == name,
                ServiceAccount.is_active == True
            )
            result = await session.exec(existing_query)
            if result.first():
                return {"success": False, "error": "Service account name already exists"}

            # Create service account
            service_account = ServiceAccount(
                workspace_id=workspace_id,
                name=name,
                description=description,
                created_by_id=created_by,
                service_type=service_type,
                integration_name=integration_name,
                token_prefix=token_prefix,
                max_tokens=max_tokens,
                token_expiry_days=token_expiry_days,
                allowed_ips=allowed_ips or [],
                allowed_origins=allowed_origins or [],
                rate_limit_per_minute=rate_limit_per_minute,
                default_scope_type=default_scope_type,
                default_scope_id=default_scope_id,
                allowed_permissions=allowed_permissions or [],
                service_metadata=service_metadata or {},
                tags=tags or [],
                expires_at=expires_at,
                is_active=True
            )

            session.add(service_account)
            await session.commit()
            await session.refresh(service_account)

            # Log creation
            await self._log_service_account_event(
                session, "service_account_created", service_account.id,
                created_by, {"service_account_name": name}
            )

            return {
                "success": True,
                "service_account": {
                    "id": service_account.id,
                    "name": service_account.name,
                    "service_type": service_account.service_type,
                    "created_at": service_account.created_at,
                    "max_tokens": service_account.max_tokens
                }
            }

        except Exception as e:
            logger.error(f"Failed to create service account: {e}")
            await session.rollback()
            return {"success": False, "error": str(e)}

    async def create_service_account_token(
        self,
        session: AsyncSession,
        service_account_id: UUIDstr,
        name: str,
        created_by: UUIDstr,
        *,
        scoped_permissions: list[str] | None = None,
        scope_type: str | None = None,
        scope_id: UUIDstr | None = None,
        allowed_ips: list[str] | None = None,
        expires_at: datetime | None = None
    ) -> dict[str, Any]:
        """Create a new token for service account.

        Args:
            session: Database session
            service_account_id: Service account ID
            name: Token name
            created_by: User creating the token
            scoped_permissions: Specific permissions for this token
            scope_type: Scope type (workspace, project, environment)
            scope_id: Scope ID
            allowed_ips: IP addresses allowed for this token
            expires_at: Token expiry time

        Returns:
            Token creation result with full token (only shown once)
        """
        try:
            from langflow.services.database.models.rbac.service_account import ServiceAccount, ServiceAccountToken

            # Get service account
            service_account = await session.get(ServiceAccount, service_account_id)
            if not service_account or not service_account.is_active:
                return {"success": False, "error": "Service account not found or inactive"}

            # Check token limit
            active_tokens_query = select(ServiceAccountToken).where(
                ServiceAccountToken.service_account_id == service_account_id,
                ServiceAccountToken.is_active == True,
                ServiceAccountToken.revoked_at is None
            )
            result = await session.exec(active_tokens_query)
            active_tokens = result.all()

            if len(active_tokens) >= service_account.max_tokens:
                return {
                    "success": False,
                    "error": f"Maximum token limit ({service_account.max_tokens}) reached"
                }

            # Check for duplicate token name
            name_query = select(ServiceAccountToken).where(
                ServiceAccountToken.service_account_id == service_account_id,
                ServiceAccountToken.name == name,
                ServiceAccountToken.is_active == True
            )
            result = await session.exec(name_query)
            if result.first():
                return {"success": False, "error": "Token name already exists for this service account"}

            # Generate token
            full_token, token_hash = self._token_generator.generate_token(
                service_account.token_prefix
            )
            token_prefix = full_token[:8]  # First 8 characters for display

            # Set expiry if not provided
            if expires_at is None and service_account.token_expiry_days:
                expires_at = datetime.now(timezone.utc) + timedelta(days=service_account.token_expiry_days)

            # Create token record
            token = ServiceAccountToken(
                service_account_id=service_account_id,
                name=name,
                token_hash=token_hash,
                token_prefix=token_prefix,
                scoped_permissions=scoped_permissions or [],
                scope_type=scope_type,
                scope_id=scope_id,
                allowed_ips=allowed_ips or service_account.allowed_ips or [],
                is_active=True,
                created_by_id=created_by,
                expires_at=expires_at
            )

            session.add(token)
            await session.commit()
            await session.refresh(token)

            # Log token creation
            await self._log_service_account_event(
                session, "service_account_token_created", service_account_id,
                created_by, {
                    "token_name": name,
                    "token_id": token.id,
                    "expires_at": expires_at.isoformat() if expires_at else None
                }
            )

            return {
                "success": True,
                "token": {
                    "id": token.id,
                    "name": token.name,
                    "token": full_token,  # Full token only shown once!
                    "token_prefix": token_prefix,
                    "expires_at": token.expires_at,
                    "created_at": token.created_at,
                    "scoped_permissions": token.scoped_permissions,
                    "scope_type": token.scope_type,
                    "scope_id": token.scope_id
                }
            }

        except Exception as e:
            logger.error(f"Failed to create service account token: {e}")
            await session.rollback()
            return {"success": False, "error": str(e)}

    async def verify_service_account_token(
        self,
        session: AsyncSession,
        token: str,
        *,
        client_ip: str | None = None,
        required_permission: str | None = None,
        scope_type: str | None = None,
        scope_id: UUIDstr | None = None
    ) -> dict[str, Any]:
        """Verify and validate a service account token.

        Args:
            session: Database session
            token: Token to verify
            client_ip: Client IP address for validation
            required_permission: Required permission for this operation
            scope_type: Required scope type
            scope_id: Required scope ID

        Returns:
            Verification result with service account and token details
        """
        try:
            from langflow.services.database.models.rbac.service_account import ServiceAccount, ServiceAccountToken

            # Extract token prefix for faster lookup
            token_prefix = token[:8]

            # Find token by prefix
            query = select(ServiceAccountToken, ServiceAccount).join(ServiceAccount).where(
                ServiceAccountToken.token_prefix == token_prefix,
                ServiceAccountToken.is_active == True,
                ServiceAccountToken.revoked_at is None,
                ServiceAccount.is_active == True
            )

            result = await session.exec(query)
            token_with_account = result.first()

            if not token_with_account:
                return {"success": False, "error": "Invalid token"}

            sa_token, service_account = token_with_account

            # Verify token hash
            if not self._token_generator.verify_token(token, sa_token.token_hash):
                return {"success": False, "error": "Invalid token"}

            # Check token expiry
            if sa_token.expires_at and datetime.now(timezone.utc) > sa_token.expires_at:
                return {"success": False, "error": "Token expired"}

            # Check service account expiry
            if service_account.expires_at and datetime.now(timezone.utc) > service_account.expires_at:
                return {"success": False, "error": "Service account expired"}

            # Validate IP restrictions
            if client_ip and sa_token.allowed_ips:
                if not self._is_ip_allowed(client_ip, sa_token.allowed_ips):
                    # Log suspicious activity
                    await self._log_security_event(
                        session, "unauthorized_ip_access", service_account.id,
                        client_ip, {"token_id": sa_token.id}
                    )
                    return {"success": False, "error": "IP address not allowed"}

            # Check permission requirements
            if required_permission:
                if not self._has_permission(sa_token, service_account, required_permission):
                    return {"success": False, "error": "Insufficient permissions"}

            # Check scope requirements
            if scope_type and scope_id:
                if not self._has_scope_access(sa_token, service_account, scope_type, scope_id):
                    return {"success": False, "error": "Scope access denied"}

            # Update usage tracking
            await self._update_token_usage(session, sa_token)

            return {
                "success": True,
                "service_account": {
                    "id": service_account.id,
                    "name": service_account.name,
                    "workspace_id": service_account.workspace_id,
                    "service_type": service_account.service_type,
                    "integration_name": service_account.integration_name
                },
                "token": {
                    "id": sa_token.id,
                    "name": sa_token.name,
                    "scoped_permissions": sa_token.scoped_permissions,
                    "scope_type": sa_token.scope_type,
                    "scope_id": sa_token.scope_id,
                    "expires_at": sa_token.expires_at
                }
            }

        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return {"success": False, "error": "Token verification error"}

    async def revoke_service_account_token(
        self,
        session: AsyncSession,
        token_id: UUIDstr,
        revoked_by: UUIDstr,
        *,
        reason: str | None = None
    ) -> dict[str, Any]:
        """Revoke a service account token.

        Args:
            session: Database session
            token_id: Token ID to revoke
            revoked_by: User revoking the token
            reason: Reason for revocation

        Returns:
            Revocation result
        """
        try:
            from langflow.services.database.models.rbac.service_account import ServiceAccountToken

            # Get token
            token = await session.get(ServiceAccountToken, token_id)
            if not token:
                return {"success": False, "error": "Token not found"}

            if token.revoked_at:
                return {"success": False, "error": "Token already revoked"}

            # Revoke token
            token.is_active = False
            token.revoked_at = datetime.now(timezone.utc)
            token.revoked_by_id = revoked_by
            token.revoke_reason = reason

            await session.commit()

            # Log revocation
            await self._log_service_account_event(
                session, "service_account_token_revoked", token.service_account_id,
                revoked_by, {
                    "token_name": token.name,
                    "token_id": token_id,
                    "reason": reason
                }
            )

            return {"success": True, "message": "Token revoked successfully"}

        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            await session.rollback()
            return {"success": False, "error": str(e)}

    async def rotate_service_account_token(
        self,
        session: AsyncSession,
        token_id: UUIDstr,
        rotated_by: UUIDstr,
        *,
        new_name: str | None = None,
        new_expiry: datetime | None = None
    ) -> dict[str, Any]:
        """Rotate a service account token (revoke old, create new).

        Args:
            session: Database session
            token_id: Token ID to rotate
            rotated_by: User performing rotation
            new_name: New token name (optional)
            new_expiry: New token expiry (optional)

        Returns:
            Rotation result with new token
        """
        try:
            from langflow.services.database.models.rbac.service_account import ServiceAccountToken

            # Get existing token
            old_token = await session.get(ServiceAccountToken, token_id)
            if not old_token:
                return {"success": False, "error": "Token not found"}

            if old_token.revoked_at:
                return {"success": False, "error": "Token already revoked"}

            # Create new token with same properties
            new_token_name = new_name or f"{old_token.name}_rotated"

            new_token_result = await self.create_service_account_token(
                session=session,
                service_account_id=old_token.service_account_id,
                name=new_token_name,
                created_by=rotated_by,
                scoped_permissions=old_token.scoped_permissions,
                scope_type=old_token.scope_type,
                scope_id=old_token.scope_id,
                allowed_ips=old_token.allowed_ips,
                expires_at=new_expiry
            )

            if not new_token_result["success"]:
                return new_token_result

            # Revoke old token
            revoke_result = await self.revoke_service_account_token(
                session=session,
                token_id=token_id,
                revoked_by=rotated_by,
                reason="Token rotation"
            )

            if not revoke_result["success"]:
                # If revocation fails, we should also revoke the new token
                await self.revoke_service_account_token(
                    session=session,
                    token_id=new_token_result["token"]["id"],
                    revoked_by=rotated_by,
                    reason="Rollback from failed rotation"
                )
                return {"success": False, "error": "Failed to revoke old token during rotation"}

            return {
                "success": True,
                "message": "Token rotated successfully",
                "new_token": new_token_result["token"],
                "old_token_id": token_id
            }

        except Exception as e:
            logger.error(f"Token rotation failed: {e}")
            await session.rollback()
            return {"success": False, "error": str(e)}

    async def list_service_account_tokens(
        self,
        session: AsyncSession,
        service_account_id: UUIDstr,
        *,
        include_revoked: bool = False
    ) -> list[dict[str, Any]]:
        """List all tokens for a service account.

        Args:
            session: Database session
            service_account_id: Service account ID
            include_revoked: Include revoked tokens

        Returns:
            List of tokens (without full token values)
        """
        try:
            from langflow.services.database.models.rbac.service_account import ServiceAccountToken

            query = select(ServiceAccountToken).where(
                ServiceAccountToken.service_account_id == service_account_id
            )

            if not include_revoked:
                query = query.where(ServiceAccountToken.revoked_at is None)

            result = await session.exec(query)
            tokens = result.all()

            token_list = []
            for token in tokens:
                token_info = {
                    "id": token.id,
                    "name": token.name,
                    "token_prefix": token.token_prefix,
                    "is_active": token.is_active,
                    "scoped_permissions": token.scoped_permissions,
                    "scope_type": token.scope_type,
                    "scope_id": token.scope_id,
                    "allowed_ips": token.allowed_ips,
                    "last_used_at": token.last_used_at,
                    "usage_count": token.usage_count,
                    "created_at": token.created_at,
                    "expires_at": token.expires_at,
                    "created_by_id": token.created_by_id
                }

                if token.revoked_at:
                    token_info.update({
                        "revoked_at": token.revoked_at,
                        "revoked_by_id": token.revoked_by_id,
                        "revoke_reason": token.revoke_reason
                    })

                token_list.append(token_info)

            return token_list

        except Exception as e:
            logger.error(f"Failed to list service account tokens: {e}")
            return []

    async def get_service_account_usage_stats(
        self,
        session: AsyncSession,
        service_account_id: UUIDstr,
        *,
        days: int = 30
    ) -> dict[str, Any]:
        """Get usage statistics for a service account.

        Args:
            session: Database session
            service_account_id: Service account ID
            days: Number of days to analyze

        Returns:
            Usage statistics
        """
        try:
            from langflow.services.database.models.rbac.service_account import ServiceAccount, ServiceAccountToken

            # Get service account
            service_account = await session.get(ServiceAccount, service_account_id)
            if not service_account:
                return {"error": "Service account not found"}

            # Get tokens
            tokens_query = select(ServiceAccountToken).where(
                ServiceAccountToken.service_account_id == service_account_id
            )
            result = await session.exec(tokens_query)
            tokens = result.all()

            # Calculate statistics
            total_tokens = len(tokens)
            active_tokens = len([t for t in tokens if t.is_active and not t.revoked_at])
            revoked_tokens = len([t for t in tokens if t.revoked_at])
            expired_tokens = len([
                t for t in tokens
                if t.expires_at and datetime.now(timezone.utc) > t.expires_at
            ])

            total_usage = sum(t.usage_count for t in tokens)
            recent_usage = sum(
                t.usage_count for t in tokens
                if t.last_used_at and
                (datetime.now(timezone.utc) - t.last_used_at).days <= days
            )

            most_recent_use = max(
                (t.last_used_at for t in tokens if t.last_used_at),
                default=None
            )

            return {
                "service_account_id": service_account_id,
                "service_account_name": service_account.name,
                "tokens": {
                    "total": total_tokens,
                    "active": active_tokens,
                    "revoked": revoked_tokens,
                    "expired": expired_tokens,
                    "max_allowed": service_account.max_tokens
                },
                "usage": {
                    "total_requests": total_usage,
                    f"recent_requests_{days}d": recent_usage,
                    "last_used_at": most_recent_use,
                    "service_account_created": service_account.created_at
                }
            }

        except Exception as e:
            logger.error(f"Failed to get service account usage stats: {e}")
            return {"error": str(e)}

    def _is_ip_allowed(self, client_ip: str, allowed_ips: list[str]) -> bool:
        """Check if client IP is in allowed list."""
        if not allowed_ips:
            return True

        import ipaddress

        try:
            client_addr = ipaddress.ip_address(client_ip)
            for allowed_ip in allowed_ips:
                try:
                    # Support both single IPs and CIDR ranges
                    if "/" in allowed_ip:
                        network = ipaddress.ip_network(allowed_ip, strict=False)
                        if client_addr in network:
                            return True
                    elif client_addr == ipaddress.ip_address(allowed_ip):
                        return True
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                    # Invalid IP format, skip
                    continue

            return False

        except ipaddress.AddressValueError:
            # Invalid client IP
            return False

    def _has_permission(
        self,
        token: "ServiceAccountToken",
        service_account: "ServiceAccount",
        required_permission: str
    ) -> bool:
        """Check if token has required permission."""
        # Check token-specific permissions first
        if token.scoped_permissions:
            return required_permission in token.scoped_permissions

        # Fall back to service account permissions
        if service_account.allowed_permissions:
            return required_permission in service_account.allowed_permissions

        # If no specific permissions defined, allow (default behavior)
        return True

    def _has_scope_access(
        self,
        token: "ServiceAccountToken",
        service_account: "ServiceAccount",
        scope_type: str,
        scope_id: UUIDstr
    ) -> bool:
        """Check if token has access to required scope."""
        # Check token-specific scope first
        if token.scope_type and token.scope_id:
            return token.scope_type == scope_type and token.scope_id == scope_id

        # Fall back to service account default scope
        if service_account.default_scope_type and service_account.default_scope_id:
            return (
                service_account.default_scope_type == scope_type and
                service_account.default_scope_id == scope_id
            )

        # If no specific scope defined, allow workspace-level access
        return scope_type == "workspace" and scope_id == service_account.workspace_id

    async def _update_token_usage(
        self,
        session: AsyncSession,
        token: "ServiceAccountToken"
    ) -> None:
        """Update token usage statistics."""
        try:
            token.usage_count += 1
            token.last_used_at = datetime.now(timezone.utc)
            await session.commit()
        except Exception as e:
            logger.warning(f"Failed to update token usage: {e}")
            # Don't fail the request for usage tracking errors
            await session.rollback()

    async def _log_service_account_event(
        self,
        session: AsyncSession,
        event_type: str,
        service_account_id: UUIDstr,
        actor_id: UUIDstr,
        metadata: dict[str, Any]
    ) -> None:
        """Log service account events for audit."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.RESOURCE_CREATED if "created" in event_type else AuditEventType.RESOURCE_UPDATED,
            action=event_type,
            outcome=AuditOutcome.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="service_account",
            resource_id=service_account_id,
            event_metadata=metadata
        )

        session.add(audit_log)
        # Note: Commit handled by caller

    async def _log_security_event(
        self,
        session: AsyncSession,
        event_type: str,
        service_account_id: UUIDstr,
        ip_address: str,
        metadata: dict[str, Any]
    ) -> None:
        """Log security events for monitoring."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.SECURITY_ALERT,
            action=event_type,
            outcome=AuditOutcome.DENIED,
            actor_type=ActorType.SERVICE_ACCOUNT,
            actor_id=service_account_id,
            resource_type="service_account_token",
            ip_address=ip_address,
            event_metadata=metadata
        )

        session.add(audit_log)
        await session.commit()
