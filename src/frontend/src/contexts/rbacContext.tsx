import React, {
  createContext,
  ReactNode,
  useContext,
  useEffect,
  useState,
} from "react";
import { useCheckPermission } from "@/controllers/API/queries/rbac";

interface RBACContextType {
  hasPermission: (
    resource: string,
    action: string,
    resourceId?: string,
  ) => boolean;
  checkPermissionAsync: (
    resource: string,
    action: string,
    resourceId?: string,
  ) => Promise<boolean>;
  isLoading: boolean;
  currentWorkspace: string | null;
  setCurrentWorkspace: (workspaceId: string | null) => void;
  currentProject: string | null;
  setCurrentProject: (projectId: string | null) => void;
  refreshPermissions: () => void;
  isDangerousAction: (resource: string, action: string) => boolean;
  requiresMFA: (resource: string, action: string) => boolean;
}

const RBACContext = createContext<RBACContextType | undefined>(undefined);

interface RBACProviderProps {
  children: ReactNode;
}

export function RBACProvider({ children }: RBACProviderProps) {
  const [currentWorkspace, setCurrentWorkspace] = useState<string | null>(null);
  const [currentProject, setCurrentProject] = useState<string | null>(null);
  const [permissionCache, setPermissionCache] = useState<Map<string, boolean>>(
    new Map(),
  );

  // @ts-ignore - Type definition issue with mutation hook
  const { mutate: checkPermission, isPending: isLoading } = useCheckPermission(
    {},
  );

  const hasPermission = (
    resource: string,
    action: string,
    resourceId?: string,
  ): boolean => {
    // Input validation
    if (!resource || !action) {
      console.warn(
        "Invalid permission check: resource and action are required",
      );
      return false;
    }

    // Create cache key
    const cacheKey = `${resource}:${action}:${resourceId || "any"}:${currentWorkspace || "no-workspace"}:${currentProject || "no-project"}`;

    // Check cache first
    if (permissionCache.has(cacheKey)) {
      return permissionCache.get(cacheKey)!;
    }

    // Trigger async permission check for this specific permission
    // Only if we're not already loading to prevent duplicate requests
    if (!isLoading) {
      checkAndCachePermission(resource, action, resourceId);
    }

    // SECURITY: Default to false for safety - deny by default
    // Permissions must be explicitly granted via backend API
    return false;
  };

  const checkAndCachePermission = (
    resource: string,
    action: string,
    resourceId?: string,
  ) => {
    const cacheKey = `${resource}:${action}:${resourceId || "any"}:${currentWorkspace || "no-workspace"}:${currentProject || "no-project"}`;

    checkPermission(
      {
        resource_type: resource,
        action: action,
        resource_id: resourceId,
        workspace_id: currentWorkspace || undefined,
        project_id: currentProject || undefined,
        // environment_id will be added when needed
      },
      {
        onSuccess: (result) => {
          setPermissionCache(
            (prev) => new Map(prev.set(cacheKey, result.allowed)),
          );
        },
        onError: (error) => {
          // Log error for debugging
          console.error(
            `Permission check failed for ${resource}:${action}:`,
            error,
          );
          // Default to false on error for security
          setPermissionCache((prev) => new Map(prev.set(cacheKey, false)));
        },
      },
    );
  };

  // Async permission check method
  const checkPermissionAsync = async (
    resource: string,
    action: string,
    resourceId?: string,
  ): Promise<boolean> => {
    const cacheKey = `${resource}:${action}:${resourceId || "any"}:${currentWorkspace || "no-workspace"}:${currentProject || "no-project"}`;

    // Check cache first
    if (permissionCache.has(cacheKey)) {
      return permissionCache.get(cacheKey)!;
    }

    try {
      const result = await new Promise<{ allowed: boolean }>(
        (resolve, reject) => {
          checkPermission(
            {
              resource_type: resource,
              action: action,
              resource_id: resourceId,
              workspace_id: currentWorkspace || undefined,
              project_id: currentProject || undefined,
            },
            {
              onSuccess: (result) => {
                setPermissionCache(
                  (prev) => new Map(prev.set(cacheKey, result.allowed)),
                );
                resolve(result);
              },
              onError: (error) => {
                console.error(
                  `Permission check failed for ${resource}:${action}:`,
                  error,
                );
                setPermissionCache(
                  (prev) => new Map(prev.set(cacheKey, false)),
                );
                reject(error);
              },
            },
          );
        },
      );

      return result.allowed;
    } catch (error) {
      console.error(
        `Permission check failed for ${resource}:${action}:`,
        error,
      );
      return false;
    }
  };

  const refreshPermissions = () => {
    setPermissionCache(new Map());
  };

  // Security checks for dangerous operations
  const isDangerousAction = (resource: string, action: string): boolean => {
    // Define dangerous operations that require extra confirmation
    const dangerousOperations = [
      "delete",
      "destroy",
      "purge",
      "reset",
      "revoke",
      "terminate",
      "disable_security",
      "grant_admin",
      "delete_workspace",
      "delete_project",
      "delete_user",
      "assign_admin_role",
    ];

    return (
      dangerousOperations.includes(action.toLowerCase()) ||
      (resource === "workspace" && ["delete", "destroy"].includes(action)) ||
      (resource === "user" && ["delete", "assign_roles"].includes(action)) ||
      (resource === "role" && action === "delete" && resource.includes("admin"))
    );
  };

  const requiresMFA = (resource: string, action: string): boolean => {
    // Define operations that require MFA
    const mfaRequiredOperations = [
      {
        resource: "user",
        actions: ["delete", "assign_roles", "revoke_access"],
      },
      { resource: "workspace", actions: ["delete", "transfer_ownership"] },
      { resource: "role", actions: ["create", "delete", "assign"] },
      { resource: "api_key", actions: ["create", "delete"] },
      { resource: "environment", actions: ["delete", "deploy"] },
    ];

    return (
      mfaRequiredOperations.some(
        (op) => op.resource === resource && op.actions.includes(action),
      ) || isDangerousAction(resource, action)
    );
  };

  // Clear cache when workspace or project changes
  useEffect(() => {
    setPermissionCache(new Map());
  }, [currentWorkspace, currentProject]);

  const value: RBACContextType = {
    hasPermission,
    checkPermissionAsync,
    isLoading,
    currentWorkspace,
    setCurrentWorkspace,
    currentProject,
    setCurrentProject,
    refreshPermissions,
    isDangerousAction,
    requiresMFA,
  };

  return <RBACContext.Provider value={value}>{children}</RBACContext.Provider>;
}

export function useRBAC(): RBACContextType {
  const context = useContext(RBACContext);
  if (context === undefined) {
    throw new Error("useRBAC must be used within an RBACProvider");
  }
  return context;
}

// Helper hook for conditional rendering based on permissions
export function usePermissionGuard(
  resource: string,
  action: string,
  resourceId?: string,
) {
  const { hasPermission, isLoading } = useRBAC();
  return {
    canAccess: hasPermission(resource, action, resourceId),
    isLoading,
  };
}
