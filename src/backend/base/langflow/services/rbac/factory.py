"""RBAC service factory following LangBuilder patterns."""

# NO future annotations per Phase 1 requirements
from typing import TYPE_CHECKING

from langflow.services.factory import ServiceFactory
from langflow.services.rbac.service import RBACService

if TYPE_CHECKING:
    from langflow.services.cache.service import CacheService


class RBACServiceFactory(ServiceFactory):
    """Factory for creating RBAC service instances."""

    def __init__(self):
        super().__init__(RBACService)

    def create(self, cache_service=None):
        """Create RBAC service instance with optional cache integration."""
        return RBACService(cache_service=cache_service)
