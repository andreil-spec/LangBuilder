import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { RoleAssignment } from "./use-get-role-assignments";

export interface CreateRoleAssignmentData {
  role_id: string;
  assignment_type: "user" | "group" | "service_account";
  scope_type: "workspace" | "project" | "environment" | "flow" | "component";

  // Assignee (one of these must be provided)
  user_id?: string;
  group_id?: string;
  service_account_id?: string;

  // Scope (based on scope_type)
  workspace_id?: string;
  project_id?: string;
  environment_id?: string;
  flow_id?: string;
  component_id?: string;

  // Optional fields
  valid_from?: string;
  valid_until?: string;
  conditions?: Record<string, any>;
  ip_restrictions?: string[];
  time_restrictions?: Record<string, any>;
  reason?: string;
}

export const useCreateRoleAssignment: useMutationFunctionType<
  undefined,
  CreateRoleAssignmentData,
  RoleAssignment
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createRoleAssignment(
    data: CreateRoleAssignmentData,
  ): Promise<RoleAssignment> {
    const res = await api.post(`${getURL("RBAC")}/role-assignments/`, data);
    if (res.status === 201) {
      return res.data;
    }
    throw new Error(`Failed to create role assignment: ${res.status}`);
  }

  const mutation: UseMutationResult<
    RoleAssignment,
    any,
    CreateRoleAssignmentData
  > = mutate(["useCreateRoleAssignment"], createRoleAssignment, options || {});

  return mutation;
};
