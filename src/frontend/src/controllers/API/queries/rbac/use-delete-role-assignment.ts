import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface DeleteRoleAssignmentData {
  assignment_id: string;
}

export const useDeleteRoleAssignment: useMutationFunctionType<
  undefined,
  DeleteRoleAssignmentData,
  { success: boolean }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function deleteRoleAssignment({
    assignment_id,
  }: DeleteRoleAssignmentData): Promise<{ success: boolean }> {
    const res = await api.delete(
      `${getURL("RBAC")}/role-assignments/${assignment_id}`,
    );
    if (res.status === 204) {
      return { success: true };
    }
    throw new Error(`Failed to delete role assignment: ${res.status}`);
  }

  const mutation: UseMutationResult<
    { success: boolean },
    any,
    DeleteRoleAssignmentData
  > = mutate(["useDeleteRoleAssignment"], deleteRoleAssignment, options);

  return mutation;
};
