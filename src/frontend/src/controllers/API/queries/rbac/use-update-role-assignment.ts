import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { RoleAssignment } from "./use-get-role-assignments";

export interface UpdateRoleAssignmentData {
  assignment_id: string;
  expires_at?: string;
  is_active?: boolean;
}

export const useUpdateRoleAssignment: useMutationFunctionType<
  undefined,
  UpdateRoleAssignmentData,
  RoleAssignment
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function updateRoleAssignment(
    data: UpdateRoleAssignmentData,
  ): Promise<RoleAssignment> {
    const { assignment_id, ...updateData } = data;
    const res = await api.put(
      `${getURL("RBAC")}/role-assignments/${assignment_id}`,
      updateData,
    );
    if (res.status === 200) {
      return res.data;
    }
    throw new Error(`Failed to update role assignment: ${res.status}`);
  }

  const mutation: UseMutationResult<
    RoleAssignment,
    any,
    UpdateRoleAssignmentData
  > = mutate(["useUpdateRoleAssignment"], updateRoleAssignment, options);

  return mutation;
};
