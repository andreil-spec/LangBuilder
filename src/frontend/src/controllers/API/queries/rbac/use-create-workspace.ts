import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { Workspace } from "./use-get-workspaces";

export interface CreateWorkspaceData {
  name: string;
  description?: string;
  is_active?: boolean;
}

export const useCreateWorkspace: useMutationFunctionType<
  undefined,
  CreateWorkspaceData,
  Workspace
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createWorkspace(
    workspaceData: CreateWorkspaceData,
  ): Promise<Workspace> {
    const res = await api.post(`${getURL("RBAC")}/workspaces/`, workspaceData);
    if (res.status === 201) {
      // Authenticated endpoint returns the workspace directly
      return res.data;
    }
    throw new Error(`Failed to create workspace: ${res.status}`);
  }

  const mutation: UseMutationResult<Workspace, any, CreateWorkspaceData> =
    mutate(["useCreateWorkspace"], createWorkspace, options);

  return mutation;
};
