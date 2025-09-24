import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface Workspace {
  id: string;
  name: string;
  description: string | null;
  owner_id: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  member_count?: number;
  project_count?: number;
}

interface GetWorkspacesQueryParams {
  page?: number;
  page_size?: number;
  search?: string;
  is_active?: boolean;
}

export const useGetWorkspaces: useMutationFunctionType<
  undefined,
  GetWorkspacesQueryParams,
  { workspaces: Workspace[]; total_count: number }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getWorkspaces({
    page = 1,
    page_size = 50,
    search,
    is_active,
  }: GetWorkspacesQueryParams): Promise<{
    workspaces: Workspace[];
    total_count: number;
  }> {
    let url = `${getURL("RBAC")}/workspaces/list?page=${page}&page_size=${page_size}`;

    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (is_active !== undefined) url += `&is_active=${is_active}`;

    const res = await api.get(url);
    if (res.status === 200) {
      // Backend returns direct array, not wrapped object
      const workspaces = Array.isArray(res.data)
        ? res.data
        : res.data.workspaces || [];
      return {
        workspaces: workspaces,
        total_count: Array.isArray(res.data)
          ? res.data.length
          : res.data.total_count || 0,
      };
    }
    return { workspaces: [], total_count: 0 };
  }

  const mutation: UseMutationResult<
    { workspaces: Workspace[]; total_count: number },
    any,
    GetWorkspacesQueryParams
  > = mutate(["useGetWorkspaces"], getWorkspaces, options);

  return mutation;
};
