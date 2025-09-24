import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface BatchCheckPermissionData {
  resource_type: string;
  action: string;
  resource_id?: string;
  workspace_id?: string;
  project_id?: string;
  environment_id?: string;
}

export interface BatchPermissionResult {
  allowed: boolean;
  reason?: string;
  cached?: boolean;
  resource_type: string;
  action: string;
  resource_id?: string;
}

export const useBatchCheckPermissions: useMutationFunctionType<
  undefined,
  BatchCheckPermissionData[],
  BatchPermissionResult[]
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function batchCheckPermissions(
    data: BatchCheckPermissionData[],
  ): Promise<BatchPermissionResult[]> {
    if (data.length === 0) {
      return [];
    }

    const res = await api.post(
      `${getURL("RBAC")}/permissions/batch-check-permission`,
      data,
    );

    if (res.status === 200) {
      return res.data;
    }

    // Fallback: deny all permissions on error
    console.error(`Batch permission check failed: ${res.status}`);
    return data.map((item) => ({
      allowed: false,
      reason: "Permission check failed",
      resource_type: item.resource_type,
      action: item.action,
      resource_id: item.resource_id,
    }));
  }

  const mutation: UseMutationResult<
    BatchPermissionResult[],
    any,
    BatchCheckPermissionData[]
  > = mutate(["useBatchCheckPermissions"], batchCheckPermissions, options);

  return mutation;
};
