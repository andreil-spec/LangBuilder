import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import { handleRBACError } from "./error-handler";

export interface Permission {
  id: string;
  name: string;
  code: string;
  description: string | null;
  resource_type: string;
  action: string;
  scope?: string;
  category?: string;
  is_system: boolean;
  is_dangerous: boolean;
  requires_mfa: boolean;
  created_at: string;
  updated_at: string;
}

interface GetPermissionsQueryParams {
  skip?: number;
  limit?: number;
  search?: string;
  resource_type?: string;
  category?: string;
  is_system?: boolean;
  workspace_id?: string;
}

export const useGetPermissions: useMutationFunctionType<
  undefined,
  GetPermissionsQueryParams,
  Permission[]
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getPermissions({
    skip = 0,
    limit = 100,
    search,
    resource_type,
    category,
    is_system,
    workspace_id,
  }: GetPermissionsQueryParams): Promise<Permission[]> {
    try {
      let url = `${getURL("RBAC")}/permissions/?skip=${skip}&limit=${limit}`;

      // Add workspace_id as query parameter for workspace validation (if provided)
      if (workspace_id) {
        url += `&workspace_id=${workspace_id}`;
      }
      if (search) {
        url += `&search=${encodeURIComponent(search)}`;
      }
      if (resource_type) {
        url += `&resource_type=${resource_type}`;
      }
      if (category) {
        url += `&category=${category}`;
      }
      if (is_system !== undefined) {
        url += `&is_system=${is_system}`;
      }

      const res = await api.get(url);
      if (res.status === 200) {
        return res.data;
      }
      return [];
    } catch (error) {
      console.error("❌ Permissions API error:", error);

      // Handle "no data" cases gracefully instead of showing errors
      if (error?.response?.status === 404) {
        console.log("📝 No permissions found, returning empty result");
        return [];
      }

      handleRBACError(error, "permissions list");
    }
  }

  const mutation: UseMutationResult<
    Permission[],
    any,
    GetPermissionsQueryParams
  > = mutate(["useGetPermissions"], getPermissions, options);

  return mutation;
};
