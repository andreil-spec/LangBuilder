import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import { handleRBACError, normalizeListResponse } from "./error-handler";

export interface Role {
  id: string;
  name: string;
  description: string | null;
  type: string;
  parent_role_id?: string;
  priority: number;
  is_system: boolean;
  is_default: boolean;
  is_active: boolean;
  workspace_id: string | null;
  scope_type?: string;
  scope_id?: string;
  role_metadata?: Record<string, any>;
  tags?: string[];
  version: number;
  created_at: string;
  updated_at: string;
  created_by_id: string;
  permission_count?: number;
  assignment_count?: number;
  is_inherited?: boolean;
}

interface GetRolesQueryParams {
  workspace_id?: string;
  page?: number;
  page_size?: number;
  search?: string;
  include_system_roles?: boolean;
  is_active?: boolean;
}

interface RoleListResponse {
  roles: Role[];
  total_count: number;
  page: number;
  page_size: number;
  has_next: boolean;
  has_previous: boolean;
}

export const useGetRoles: useMutationFunctionType<
  undefined,
  GetRolesQueryParams,
  RoleListResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getRoles({
    workspace_id,
    page = 1,
    page_size = 50,
    search,
    include_system_roles = false,
    is_active,
  }: GetRolesQueryParams): Promise<RoleListResponse> {
    try {
      const params = new URLSearchParams();
      params.append("page", page.toString());
      params.append("page_size", page_size.toString());

      if (workspace_id) {
        params.append("workspace_id", workspace_id);
      }
      if (search) {
        params.append("search", search);
      }
      if (include_system_roles) {
        params.append("include_system_roles", "true");
      }
      if (is_active !== undefined) {
        params.append("is_active", is_active.toString());
      }

      const url = `${getURL("RBAC")}/roles/?${params.toString()}`;

      const res = await api.get(url);

      if (res.status === 200) {
        // Use normalized response handler
        const normalized = normalizeListResponse<Role>(
          res.data,
          "roles",
          page,
          page_size,
        );

        return {
          roles: normalized.items,
          total_count: normalized.total_count,
          page: normalized.page,
          page_size: normalized.page_size,
          has_next: normalized.has_next,
          has_previous: normalized.has_previous,
        };
      }

      return {
        roles: [],
        total_count: 0,
        page: page,
        page_size: page_size,
        has_next: false,
        has_previous: false,
      };
    } catch (error) {
      console.error("❌ Roles API error:", error);
      handleRBACError(error, "role list");
    }
  }

  const mutation: UseMutationResult<
    RoleListResponse,
    any,
    GetRolesQueryParams
  > = mutate(["useGetRoles"], getRoles, options || {});

  return mutation;
};
