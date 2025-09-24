import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface CheckPermissionData {
  resource_type: string;
  action: string;
  resource_id?: string;
  workspace_id?: string;
  project_id?: string;
  environment_id?: string;
}

export interface PermissionResult {
  allowed: boolean;
  reason?: string;
  cached?: boolean;
}

export const useCheckPermission: useMutationFunctionType<
  undefined,
  CheckPermissionData,
  PermissionResult
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function checkPermission(
    data: CheckPermissionData,
  ): Promise<PermissionResult> {
    try {
      const res = await api.post(
        `${getURL("RBAC")}/permissions/check-permission`,
        data,
      );
      if (res.status === 200) {
        return res.data;
      }
      throw new Error(`Failed to check permission: ${res.status}`);
    } catch (error: any) {
      // Log specific error types for debugging
      if (error.response?.status === 401) {
        console.error(
          "Permission check failed: Unauthorized - user may need to re-authenticate",
        );
        throw new Error("Authentication required");
      } else if (error.response?.status === 403) {
        console.error(
          "Permission check failed: Forbidden - insufficient permissions",
        );
        // Return denied result instead of throwing for 403 to avoid breaking UI
        return { allowed: false, reason: "Access denied" };
      } else if (error.response?.status === 422) {
        console.error(
          "Permission check failed: Invalid request data",
          error.response.data,
        );
        throw new Error("Invalid permission check request");
      } else {
        console.error("Permission check failed:", error);
        throw error;
      }
    }
  }

  const mutation: UseMutationResult<
    PermissionResult,
    any,
    CheckPermissionData
  > = mutate(["useCheckPermission"], checkPermission, options || {});

  return mutation;
};
