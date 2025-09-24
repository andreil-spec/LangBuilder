import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { Role } from "./use-get-roles";

export interface UpdateRoleData {
  role_id: string;
  role: {
    name?: string;
    description?: string;
    permissions?: string[];
    is_active?: boolean;
  };
}

export const useUpdateRole: useMutationFunctionType<
  undefined,
  UpdateRoleData,
  Role
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function updateRole({ role_id, role }: UpdateRoleData): Promise<Role> {
    try {
      console.log("Updating role:", role_id, "with data:", role);
      const res = await api.put(`${getURL("RBAC")}/roles/${role_id}`, role);
      console.log("Update role response:", res.status, res.data);

      if (res.status === 200 || res.status === 201 || res.status === 204) {
        return res.data;
      }
      throw new Error(`Failed to update role: ${res.status}`);
    } catch (error: any) {
      console.error("Update role error:", error);

      // Extract meaningful error message from response
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

  const mutation: UseMutationResult<Role, any, UpdateRoleData> = mutate(
    ["useUpdateRole"],
    updateRole,
    options,
  );

  return mutation;
};
