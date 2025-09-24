import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import { handleRBACError } from "./error-handler";

export interface LegacyProject {
  id: string;
  name: string;
  description?: string;
  user_id: string;
  flow_count: number;
  created_at: string;
  updated_at?: string;
  migration_status: "pending" | "migrating" | "completed" | "error";
  migrated_to_project_id?: string;
  type: "legacy";
}

export interface RBACProject {
  id: string;
  name: string;
  description?: string;
  workspace_id: string;
  owner_id: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  type: "rbac";
  environment_count: number;
  flow_count: number;
}

export interface UnifiedProjectsResponse {
  rbac_projects: RBACProject[];
  legacy_projects: LegacyProject[];
  summary: {
    total_count: number;
    rbac_count: number;
    legacy_count: number;
  };
}

interface GetUnifiedProjectsParams {
  include_legacy?: boolean;
  include_rbac?: boolean;
  search?: string;
  page?: number;
  page_size?: number;
}

export const useGetUnifiedProjects: useMutationFunctionType<
  undefined,
  GetUnifiedProjectsParams,
  UnifiedProjectsResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getUnifiedProjects({
    include_legacy = true,
    include_rbac = true,
    search = "",
    page = 1,
    page_size = 50,
  }: GetUnifiedProjectsParams): Promise<UnifiedProjectsResponse> {
    const params = new URLSearchParams();
    params.append("include_legacy", include_legacy.toString());
    params.append("include_rbac", include_rbac.toString());
    if (search) params.append("search", search);
    params.append("page", page.toString());
    params.append("page_size", page_size.toString());

    const url = `${getURL("RBAC")}/unified-projects/?${params.toString()}`;

    try {
      const res = await api.get(url);

      if (res.status === 200) {
        return res.data;
      }

      return {
        rbac_projects: [],
        legacy_projects: [],
        summary: {
          total_count: 0,
          rbac_count: 0,
          legacy_count: 0,
        },
      };
    } catch (error) {
      handleRBACError(error, "unified projects");
      throw error;
    }
  }

  const mutation: UseMutationResult<
    UnifiedProjectsResponse,
    any,
    GetUnifiedProjectsParams
  > = mutate(["useGetUnifiedProjects"], getUnifiedProjects, options || {});

  return mutation;
};
