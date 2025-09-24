import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import { handleRBACError, normalizeListResponse } from "./error-handler";

export interface ServiceAccount {
  id: string;
  name: string;
  description: string | null;
  workspace_id: string;
  created_by_id: string;
  scope_type: "global" | "workspace" | "project" | "environment";
  scope_id: string | null;
  permissions: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_used_at?: string;
  token_count?: number;
}

interface GetServiceAccountsQueryParams {
  workspace_id?: string;
  scope_type?: string;
  page?: number;
  page_size?: number;
  search?: string;
  is_active?: boolean;
}

interface ServiceAccountListResponse {
  service_accounts: ServiceAccount[];
  total_count: number;
  page: number;
  page_size: number;
  has_next: boolean;
  has_previous: boolean;
}

export const useGetServiceAccounts: useMutationFunctionType<
  undefined,
  GetServiceAccountsQueryParams,
  ServiceAccountListResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getServiceAccounts({
    workspace_id,
    scope_type,
    page = 1,
    page_size = 50,
    search,
    is_active,
  }: GetServiceAccountsQueryParams): Promise<ServiceAccountListResponse> {
    try {
      const params = new URLSearchParams();
      params.append("page", page.toString());
      params.append("page_size", page_size.toString());

      if (workspace_id) {
        params.append("workspace_id", workspace_id);
      }
      if (scope_type) {
        params.append("scope_type", scope_type);
      }
      if (search) {
        params.append("search", search);
      }
      if (is_active !== undefined) {
        params.append("is_active", is_active.toString());
      }

      const url = `${getURL("RBAC")}/service-accounts/?${params.toString()}`;

      const res = await api.get(url);

      if (res.status === 200) {
        // Use normalized response handler
        const normalized = normalizeListResponse<ServiceAccount>(
          res.data,
          "service_accounts",
          page,
          page_size,
        );

        return {
          service_accounts: normalized.items,
          total_count: normalized.total_count,
          page: normalized.page,
          page_size: normalized.page_size,
          has_next: normalized.has_next,
          has_previous: normalized.has_previous,
        };
      }

      return {
        service_accounts: [],
        total_count: 0,
        page: page,
        page_size: page_size,
        has_next: false,
        has_previous: false,
      };
    } catch (error) {
      handleRBACError(error, "service account list");
    }
  }

  const mutation: UseMutationResult<
    ServiceAccountListResponse,
    any,
    GetServiceAccountsQueryParams
  > = mutate(["useGetServiceAccounts"], getServiceAccounts, options || {});

  return mutation;
};
