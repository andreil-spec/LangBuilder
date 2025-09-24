import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface WorkspaceUser {
  user_id: string;
  username: string;
  email?: string;
  roles: string[];
  joined_at: string;
  is_active: boolean;
  is_owner: boolean;
}

interface GetWorkspaceUsersParams {
  workspace_id: string;
  skip?: number;
  limit?: number;
  search?: string;
}

export const useGetWorkspaceUsers: useMutationFunctionType<
  undefined,
  GetWorkspaceUsersParams,
  { users: WorkspaceUser[]; total_count: number }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getWorkspaceUsers({
    workspace_id,
    skip = 0,
    limit = 50,
    search,
  }: GetWorkspaceUsersParams): Promise<{
    users: WorkspaceUser[];
    total_count: number;
  }> {
    let url = `${getURL("RBAC")}/workspaces/${workspace_id}/users/?skip=${skip}&limit=${limit}`;

    if (search) {
      url += `&search=${encodeURIComponent(search)}`;
    }

    const res = await api.get(url);
    if (res.status === 200) {
      return res.data;
    }
    return { users: [], total_count: 0 };
  }

  const mutation: UseMutationResult<
    { users: WorkspaceUser[]; total_count: number },
    any,
    GetWorkspaceUsersParams
  > = mutate(["useGetWorkspaceUsers"], getWorkspaceUsers, options);

  return mutation;
};
