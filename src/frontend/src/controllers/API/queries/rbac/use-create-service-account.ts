import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { ServiceAccount } from "./use-get-service-accounts";

export interface CreateServiceAccountData {
  name: string;
  description?: string;
  workspace_id: string;
  scope_type: "global" | "workspace" | "project" | "environment";
  scope_id?: string;
  permissions: string[];
}

export const useCreateServiceAccount: useMutationFunctionType<
  undefined,
  CreateServiceAccountData,
  ServiceAccount
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createServiceAccount(
    data: CreateServiceAccountData,
  ): Promise<ServiceAccount> {
    const res = await api.post(`${getURL("RBAC")}/service-accounts/`, data);
    if (res.status === 201) {
      // Authenticated endpoint returns the service account directly
      return res.data;
    }
    throw new Error(`Failed to create service account: ${res.status}`);
  }

  const mutation: UseMutationResult<
    ServiceAccount,
    any,
    CreateServiceAccountData
  > = mutate(["useCreateServiceAccount"], createServiceAccount, options);

  return mutation;
};
