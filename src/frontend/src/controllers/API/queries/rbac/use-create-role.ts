import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { Role } from "./use-get-roles";

export interface CreateRoleData {
  name: string;
  description?: string;
  workspace_id?: string;
  type?: string;
  parent_role_id?: string;
  priority?: number;
  scope_type?: string;
  scope_id?: string;
  role_metadata?: Record<string, any>;
  tags?: string[];
}

export const useCreateRole: useMutationFunctionType<
  undefined,
  CreateRoleData
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createRole(roleData: CreateRoleData): Promise<Role> {
    const res = await api.post(`${getURL("RBAC")}/roles/`, roleData);
    if (res.status === 201) {
      return res.data;
    }
    throw new Error(`Failed to create role: ${res.status}`);
  }

  const mutation: UseMutationResult<Role, any, CreateRoleData> = mutate(
    ["useCreateRole"],
    createRole,
    options,
  );

  return mutation;
};
