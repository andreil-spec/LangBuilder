import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface CreatePermissionData {
  name: string;
  code: string;
  description?: string;
  category?: string;
  resource_type: string;
  action: string;
  scope?: string;
  conditions?: Record<string, any>;
  is_system?: boolean;
  is_dangerous?: boolean;
  requires_mfa?: boolean;
}

export interface CreatePermissionResponse {
  id: string;
  name: string;
  code: string;
  description?: string;
  category?: string;
  resource_type: string;
  action: string;
  scope?: string;
  conditions?: Record<string, any>;
  is_system: boolean;
  is_dangerous: boolean;
  requires_mfa: boolean;
  role_count: number;
}

export const useCreatePermission: useMutationFunctionType<
  undefined,
  CreatePermissionData,
  CreatePermissionResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createPermission(
    permissionData: CreatePermissionData
  ): Promise<CreatePermissionResponse> {
    try {
      console.log("Creating permission with data:", permissionData);

      const res = await api.post(
        `${getURL("RBAC")}/permissions/`,
        permissionData
      );

      console.log("Create permission response:", res);

      if (!res) {
        throw new Error("No response received from server");
      }

      if (res.status === 201) {
        return res.data;
      }
      throw new Error(`Failed to create permission: ${res.status}`);
    } catch (error: any) {
      console.error("Create permission error:", error);

      let errorMessage = "Unknown error";
      if (error?.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error?.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error?.message) {
        errorMessage = error.message;
      }

      throw new Error(errorMessage);
    }
  }

  const mutation: UseMutationResult<
    CreatePermissionResponse,
    any,
    CreatePermissionData
  > = mutate(["useCreatePermission"], createPermission, options);

  return mutation;
};