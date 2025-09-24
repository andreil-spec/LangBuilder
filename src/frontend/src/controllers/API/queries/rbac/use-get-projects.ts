import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface Project {
  id: string;
  name: string;
  description: string | null;
  workspace_id: string;
  owner_id: string;
  is_active: boolean;
  is_archived: boolean;
  created_at: string;
  updated_at: string;
  environment_count?: number;
  flow_count?: number;
  last_deployed_at?: string;
}

interface GetProjectsQueryParams {
  workspace_id?: string;
  page?: number;
  page_size?: number;
  search?: string;
  is_active?: boolean;
  is_archived?: boolean;
}

export const useGetProjects: useMutationFunctionType<
  undefined,
  GetProjectsQueryParams,
  { projects: Project[]; total_count: number }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getProjects({
    workspace_id,
    page = 1,
    page_size = 50,
    search,
    is_active,
    is_archived,
  }: GetProjectsQueryParams): Promise<{
    projects: Project[];
    total_count: number;
  }> {
    let url = `${getURL("RBAC")}/projects/?page=${page}&page_size=${page_size}`;

    if (workspace_id) url += `&workspace_id=${workspace_id}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (is_active !== undefined) url += `&is_active=${is_active}`;
    if (is_archived !== undefined) url += `&is_archived=${is_archived}`;

    const res = await api.get(url);
    if (res.status === 200) {
      return {
        projects: res.data.projects || [],
        total_count: res.data.total_count || 0,
      };
    }
    return { projects: [], total_count: 0 };
  }

  const mutation: UseMutationResult<
    { projects: Project[]; total_count: number },
    any,
    GetProjectsQueryParams
  > = mutate(["useGetProjects"], getProjects, options);

  return mutation;
};
