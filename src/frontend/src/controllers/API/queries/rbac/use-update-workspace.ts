import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { Workspace } from "./use-get-workspaces";

export interface UpdateWorkspaceData {
  workspace_id: string;
  workspace: {
    name?: string;
    description?: string;
    is_active?: boolean;
  };
}

export const useUpdateWorkspace: useMutationFunctionType<
  undefined,
  UpdateWorkspaceData,
  Workspace
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function updateWorkspace({
    workspace_id,
    workspace,
  }: UpdateWorkspaceData): Promise<Workspace> {
    const res = await api.put(
      `${getURL("RBAC")}/workspaces/${workspace_id}`,
      workspace,
    );
    if (res.status === 200) {
      // Authenticated endpoint returns the workspace directly
      return res.data;
    }
    throw new Error(`Failed to update workspace: ${res.status}`);
  }

  const mutation: UseMutationResult<Workspace, any, UpdateWorkspaceData> =
    mutate(["useUpdateWorkspace"], updateWorkspace, options);

  return mutation;
};
