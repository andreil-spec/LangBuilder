import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface AssignPermissionData {
  role_id: string;
  permission_id: string;
}

export interface RemovePermissionData {
  role_id: string;
  permission_id: string;
}

export interface UpdateRolePermissionsData {
  role_id: string;
  permission_ids: string[];
}

export const useAssignRolePermission: useMutationFunctionType<
  undefined,
  AssignPermissionData,
  { success: boolean }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function assignPermission({
    role_id,
    permission_id,
  }: AssignPermissionData): Promise<{ success: boolean }> {
    try {
      const res = await api.post(
        `${getURL("RBAC")}/roles/${role_id}/permissions`,
        { permission_id },
      );

      if (res.status === 200 || res.status === 201) {
        return { success: true };
      }
      throw new Error(`Failed to assign permission: ${res.status}`);
    } catch (error: any) {
      console.error("Assign permission error:", error);

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
    { success: boolean },
    any,
    AssignPermissionData
  > = mutate(["useAssignRolePermission"], assignPermission, options);

  return mutation;
};

export const useRemoveRolePermission: useMutationFunctionType<
  undefined,
  RemovePermissionData,
  { success: boolean }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function removePermission({
    role_id,
    permission_id,
  }: RemovePermissionData): Promise<{ success: boolean }> {
    try {
      const res = await api.delete(
        `${getURL("RBAC")}/roles/${role_id}/permissions/${permission_id}`,
      );

      if (res.status === 200 || res.status === 204) {
        return { success: true };
      }
      throw new Error(`Failed to remove permission: ${res.status}`);
    } catch (error: any) {
      console.error("Remove permission error:", error);

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
    { success: boolean },
    any,
    RemovePermissionData
  > = mutate(["useRemoveRolePermission"], removePermission, options);

  return mutation;
};

interface UpdateRolePermissionsResponse {
  success: boolean;
  message: string;
  permission_count: number;
  permission_ids: string[];
  storage_method?: string;
}

export const useUpdateRolePermissions: useMutationFunctionType<
  undefined,
  UpdateRolePermissionsData,
  UpdateRolePermissionsResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function updateRolePermissions({
    role_id,
    permission_ids,
  }: UpdateRolePermissionsData): Promise<UpdateRolePermissionsResponse> {
    try {
      // Use the authenticated roles endpoint
      const res = await api.put(
        `${getURL("RBAC")}/roles/${role_id}/permissions`,
        {
          permission_ids: permission_ids,
        },
      );

      if (res.status === 200) {
        console.log("Role permissions updated successfully:", res.data);
        return res.data; // Return the full backend response including permission_count
      }
      throw new Error(`Failed to update role permissions: ${res.status}`);
    } catch (error: any) {
      console.error("Update role permissions error:", error);

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
    UpdateRolePermissionsResponse,
    any,
    UpdateRolePermissionsData
  > = mutate(["useUpdateRolePermissions"], updateRolePermissions, options);

  return mutation;
};
