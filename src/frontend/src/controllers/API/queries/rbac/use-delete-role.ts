import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface DeleteRoleData {
  role_id: string;
}

export const useDeleteRole: useMutationFunctionType<
  undefined,
  DeleteRoleData
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function deleteRole({
    role_id,
  }: DeleteRoleData): Promise<{ success: boolean }> {
    try {
      console.log("Deleting role:", role_id);
      const res = await api.delete(`${getURL("RBAC")}/roles/${role_id}`);
      console.log("Delete role response:", res.status);

      if (res.status === 204 || res.status === 200) {
        return { success: true };
      }
      throw new Error(`Failed to delete role: ${res.status}`);
    } catch (error: any) {
      console.error("Delete role error:", error);

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

  const mutation: UseMutationResult<{ success: boolean }, any, DeleteRoleData> =
    mutate(["useDeleteRole"], deleteRole, options);

  return mutation;
};
