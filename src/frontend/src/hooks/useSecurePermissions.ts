import { useCallback, useEffect, useState } from "react";
import { useRBAC } from "@/contexts/rbacContext";

interface PermissionState {
  [key: string]: {
    granted: boolean;
    loading: boolean;
    error: boolean;
    lastChecked: number;
  };
}

interface UseSecurePermissionsOptions {
  /**
   * Time in milliseconds to cache permission results
   * Default: 5 minutes (300000ms)
   */
  cacheTime?: number;
  /**
   * Maximum number of retry attempts for failed permission checks
   * Default: 2
   */
  maxRetries?: number;
  /**
   * Whether to automatically check permissions on mount
   * Default: true
   */
  autoCheck?: boolean;
}

/**
 * Hook for secure permission checking with proper error handling,
 * caching, and retry logic. Always defaults to deny for security.
 */
export function useSecurePermissions(
  permissions: Array<{
    resource: string;
    action: string;
    resourceId?: string;
  }>,
  options: UseSecurePermissionsOptions = {},
) {
  const {
    cacheTime = 300000, // 5 minutes
    maxRetries = 2,
    autoCheck = true,
  } = options;

  const { checkPermissionAsync, isLoading: contextLoading } = useRBAC();
  const [permissionStates, setPermissionStates] = useState<PermissionState>({});
  const [retryAttempts, setRetryAttempts] = useState<Record<string, number>>(
    {},
  );

  const createPermissionKey = useCallback(
    (resource: string, action: string, resourceId?: string) => {
      return `${resource}:${action}:${resourceId || "global"}`;
    },
    [],
  );

  const isPermissionExpired = useCallback(
    (lastChecked: number) => {
      return Date.now() - lastChecked > cacheTime;
    },
    [cacheTime],
  );

  const checkPermission = useCallback(
    async (resource: string, action: string, resourceId?: string) => {
      const key = createPermissionKey(resource, action, resourceId);
      const currentRetries = retryAttempts[key] || 0;

      // Set loading state
      setPermissionStates((prev) => ({
        ...prev,
        [key]: {
          granted: false, // Always default to false for security
          loading: true,
          error: false,
          lastChecked: prev[key]?.lastChecked || 0,
        },
      }));

      try {
        const granted = await checkPermissionAsync(
          resource,
          action,
          resourceId,
        );

        setPermissionStates((prev) => ({
          ...prev,
          [key]: {
            granted,
            loading: false,
            error: false,
            lastChecked: Date.now(),
          },
        }));

        // Reset retry counter on success
        setRetryAttempts((prev) => ({
          ...prev,
          [key]: 0,
        }));

        return granted;
      } catch (error) {
        console.error(
          `Permission check failed for ${resource}:${action}${resourceId ? `:${resourceId}` : ""}`,
          error,
        );

        // Retry logic
        if (currentRetries < maxRetries) {
          setRetryAttempts((prev) => ({
            ...prev,
            [key]: currentRetries + 1,
          }));

          // Exponential backoff: wait 2^retries seconds
          const delay = Math.pow(2, currentRetries) * 1000;
          setTimeout(() => {
            checkPermission(resource, action, resourceId);
          }, delay);

          return false; // Return false while retrying for security
        }

        // Max retries exceeded - mark as error and deny permission
        setPermissionStates((prev) => ({
          ...prev,
          [key]: {
            granted: false, // Always deny on error for security
            loading: false,
            error: true,
            lastChecked: Date.now(),
          },
        }));

        return false;
      }
    },
    [checkPermissionAsync, createPermissionKey, maxRetries, retryAttempts],
  );

  const checkPermissions = useCallback(async () => {
    const promises = permissions.map(({ resource, action, resourceId }) => {
      const key = createPermissionKey(resource, action, resourceId);
      const existing = permissionStates[key];

      // Skip if still loading or recently checked and not expired
      if (
        existing?.loading ||
        (existing?.lastChecked && !isPermissionExpired(existing.lastChecked))
      ) {
        return Promise.resolve(existing.granted);
      }

      return checkPermission(resource, action, resourceId);
    });

    return Promise.all(promises);
  }, [
    permissions,
    permissionStates,
    checkPermission,
    createPermissionKey,
    isPermissionExpired,
  ]);

  const refreshPermissions = useCallback(() => {
    // Clear cache and retry counters
    setPermissionStates({});
    setRetryAttempts({});
    checkPermissions();
  }, [checkPermissions]);

  // Auto-check permissions on mount or when permissions change
  useEffect(() => {
    if (autoCheck && permissions.length > 0) {
      checkPermissions();
    }
  }, [permissions, autoCheck, checkPermissions]);

  // Helper functions
  const hasPermission = useCallback(
    (resource: string, action: string, resourceId?: string) => {
      const key = createPermissionKey(resource, action, resourceId);
      const state = permissionStates[key];

      // Default to false if not checked yet, loading, or error
      if (!state || state.loading || state.error) {
        return false;
      }

      // Check if permission is expired
      if (isPermissionExpired(state.lastChecked)) {
        // Trigger refresh but return false until updated
        checkPermission(resource, action, resourceId);
        return false;
      }

      return state.granted;
    },
    [
      permissionStates,
      createPermissionKey,
      isPermissionExpired,
      checkPermission,
    ],
  );

  const isLoading = useCallback(() => {
    return (
      contextLoading ||
      Object.values(permissionStates).some((state) => state.loading)
    );
  }, [contextLoading, permissionStates]);

  const hasErrors = useCallback(() => {
    return Object.values(permissionStates).some((state) => state.error);
  }, [permissionStates]);

  const getPermissionState = useCallback(
    (resource: string, action: string, resourceId?: string) => {
      const key = createPermissionKey(resource, action, resourceId);
      return (
        permissionStates[key] || {
          granted: false,
          loading: false,
          error: false,
          lastChecked: 0,
        }
      );
    },
    [permissionStates, createPermissionKey],
  );

  return {
    hasPermission,
    checkPermissions,
    refreshPermissions,
    isLoading: isLoading(),
    hasErrors: hasErrors(),
    getPermissionState,
    permissionStates,
  };
}
