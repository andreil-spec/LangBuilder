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
  service_type: string | null;
  integration_name: string | null;
  token_prefix: string | null;
  max_tokens: number;
  token_expiry_days: number | null;
  allowed_ips: string[] | null;
  allowed_origins: string[] | null;
  rate_limit_per_minute: number | null;
  default_scope_type: string | null;
  default_scope_id: string | null;
  allowed_permissions: string[] | null;
  is_active: boolean;
  is_locked: boolean;
  locked_reason: string | null;
  locked_at: string | null;
  last_used_at: string | null;
  usage_count: number;
  service_metadata: Record<string, any> | null;
  tags: string[] | null;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
  created_by_id: string;
  active_token_count?: number;
  total_token_count?: number;
  role_count?: number;
}

export interface ServiceAccountToken {
  id: string;
  service_account_id: string;
  name: string;
  token_prefix: string;
  scoped_permissions: string[] | null;
  scope_type: string | null;
  scope_id: string | null;
  allowed_ips: string[] | null;
  is_active: boolean;
  last_used_at: string | null;
  usage_count: number;
  created_at: string;
  expires_at: string | null;
  created_by_id: string;
}

export interface ServiceAccountTokenResponse {
  id: string;
  name: string;
  token: string; // Full token (only shown once)
  token_prefix: string;
  expires_at: string | null;
  created_at: string;
}

interface GetServiceAccountsQueryParams {
  workspace_id: string;
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

interface CreateServiceAccountData {
  name: string;
  description?: string;
  workspace_id: string;
  service_type?: string;
  integration_name?: string;
  token_prefix?: string;
  max_tokens?: number;
  token_expiry_days?: number;
  allowed_ips?: string[];
  allowed_origins?: string[];
  rate_limit_per_minute?: number;
  default_scope_type?: string;
  default_scope_id?: string;
  allowed_permissions?: string[];
  service_metadata?: Record<string, any>;
  tags?: string[];
  expires_at?: string;
}

interface UpdateServiceAccountData {
  name?: string;
  description?: string;
  service_type?: string;
  integration_name?: string;
  max_tokens?: number;
  token_expiry_days?: number;
  allowed_ips?: string[];
  allowed_origins?: string[];
  rate_limit_per_minute?: number;
  default_scope_type?: string;
  default_scope_id?: string;
  allowed_permissions?: string[];
  service_metadata?: Record<string, any>;
  tags?: string[];
  is_active?: boolean;
  expires_at?: string;
}

interface CreateServiceAccountTokenData {
  service_account_id: string;
  name: string;
  scoped_permissions?: string[];
  scope_type?: string;
  scope_id?: string;
  allowed_ips?: string[];
  expires_at?: string;
}

// Get Service Accounts
export const useGetServiceAccounts: useMutationFunctionType<
  undefined,
  GetServiceAccountsQueryParams,
  ServiceAccountListResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getServiceAccounts({
    workspace_id,
    page = 1,
    page_size = 50,
    search,
    is_active,
  }: GetServiceAccountsQueryParams): Promise<ServiceAccountListResponse> {
    try {
      const params = new URLSearchParams();
      params.append("workspace_id", workspace_id);
      params.append("page", page.toString());
      params.append("size", page_size.toString());

      if (search) {
        params.append("search", search);
      }
      if (is_active !== undefined) {
        params.append("is_active", is_active.toString());
      }

      const url = `${getURL("RBAC")}/service-accounts/?${params.toString()}`;
      const res = await api.get(url);

      if (res.status === 200) {
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

// Create Service Account
export const useCreateServiceAccount: useMutationFunctionType<
  undefined,
  CreateServiceAccountData,
  ServiceAccount
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createServiceAccount(
    data: CreateServiceAccountData,
  ): Promise<ServiceAccount> {
    try {
      const url = `${getURL("RBAC")}/service-accounts/`;
      const res = await api.post(url, data);

      if (res.status === 201) {
        return res.data;
      }

      throw new Error("Failed to create service account");
    } catch (error) {
      handleRBACError(error, "service account creation");
    }
  }

  const mutation: UseMutationResult<
    ServiceAccount,
    any,
    CreateServiceAccountData
  > = mutate(["useCreateServiceAccount"], createServiceAccount, options || {});

  return mutation;
};

// Update Service Account
export const useUpdateServiceAccount: useMutationFunctionType<
  undefined,
  { service_account_id: string; data: UpdateServiceAccountData },
  ServiceAccount
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function updateServiceAccount({
    service_account_id,
    data,
  }: {
    service_account_id: string;
    data: UpdateServiceAccountData;
  }): Promise<ServiceAccount> {
    try {
      const url = `${getURL("RBAC")}/service-accounts/${service_account_id}`;
      const res = await api.put(url, data);

      if (res.status === 200) {
        return res.data;
      }

      throw new Error("Failed to update service account");
    } catch (error) {
      handleRBACError(error, "service account update");
    }
  }

  const mutation: UseMutationResult<
    ServiceAccount,
    any,
    { service_account_id: string; data: UpdateServiceAccountData }
  > = mutate(["useUpdateServiceAccount"], updateServiceAccount, options || {});

  return mutation;
};

// Delete Service Account
export const useDeleteServiceAccount: useMutationFunctionType<
  undefined,
  { service_account_id: string },
  void
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function deleteServiceAccount({
    service_account_id,
  }: {
    service_account_id: string;
  }): Promise<void> {
    try {
      const url = `${getURL("RBAC")}/service-accounts/${service_account_id}`;
      const res = await api.delete(url);

      if (res.status === 204) {
        return;
      }

      throw new Error("Failed to delete service account");
    } catch (error) {
      handleRBACError(error, "service account deletion");
    }
  }

  const mutation: UseMutationResult<void, any, { service_account_id: string }> =
    mutate(["useDeleteServiceAccount"], deleteServiceAccount, options || {});

  return mutation;
};

// Create Service Account Token
export const useCreateServiceAccountToken: useMutationFunctionType<
  undefined,
  CreateServiceAccountTokenData,
  ServiceAccountTokenResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createServiceAccountToken(
    data: CreateServiceAccountTokenData,
  ): Promise<ServiceAccountTokenResponse> {
    try {
      const url = `${getURL("RBAC")}/service-accounts/${data.service_account_id}/tokens`;
      const res = await api.post(url, data);

      if (res.status === 201) {
        return res.data;
      }

      throw new Error("Failed to create service account token");
    } catch (error) {
      handleRBACError(error, "service account token creation");
    }
  }

  const mutation: UseMutationResult<
    ServiceAccountTokenResponse,
    any,
    CreateServiceAccountTokenData
  > = mutate(
    ["useCreateServiceAccountToken"],
    createServiceAccountToken,
    options || {},
  );

  return mutation;
};

// Get Service Account Tokens
export const useGetServiceAccountTokens: useMutationFunctionType<
  undefined,
  { service_account_id: string },
  ServiceAccountToken[]
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getServiceAccountTokens({
    service_account_id,
  }: {
    service_account_id: string;
  }): Promise<ServiceAccountToken[]> {
    try {
      const url = `${getURL("RBAC")}/service-accounts/${service_account_id}/tokens`;
      const res = await api.get(url);

      if (res.status === 200) {
        return Array.isArray(res.data) ? res.data : [];
      }

      return [];
    } catch (error) {
      handleRBACError(error, "service account tokens list");
    }
  }

  const mutation: UseMutationResult<
    ServiceAccountToken[],
    any,
    { service_account_id: string }
  > = mutate(
    ["useGetServiceAccountTokens"],
    getServiceAccountTokens,
    options || {},
  );

  return mutation;
};

// Delete Service Account Token
export const useDeleteServiceAccountToken: useMutationFunctionType<
  undefined,
  { service_account_id: string; token_id: string },
  void
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function deleteServiceAccountToken({
    service_account_id,
    token_id,
  }: {
    service_account_id: string;
    token_id: string;
  }): Promise<void> {
    try {
      const url = `${getURL("RBAC")}/service-accounts/${service_account_id}/tokens/${token_id}`;
      const res = await api.delete(url);

      if (res.status === 204) {
        return;
      }

      throw new Error("Failed to delete service account token");
    } catch (error) {
      handleRBACError(error, "service account token deletion");
    }
  }

  const mutation: UseMutationResult<
    void,
    any,
    { service_account_id: string; token_id: string }
  > = mutate(
    ["useDeleteServiceAccountToken"],
    deleteServiceAccountToken,
    options || {},
  );

  return mutation;
};
