import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { ServiceAccount } from "./use-get-service-accounts";

export interface UpdateServiceAccountData {
  service_account_id: string;
  service_account: {
    name?: string;
    description?: string;
    scope_type?: "global" | "workspace" | "project" | "environment";
    scope_id?: string;
    permissions?: string[];
    is_active?: boolean;
  };
}

export const useUpdateServiceAccount: useMutationFunctionType<
  undefined,
  UpdateServiceAccountData,
  ServiceAccount
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function updateServiceAccount({
    service_account_id,
    service_account,
  }: UpdateServiceAccountData): Promise<ServiceAccount> {
    const res = await api.patch(
      `${getURL("RBAC")}/service-accounts/${service_account_id}`,
      service_account,
    );
    if (res.status === 200) {
      return res.data;
    }
    throw new Error(`Failed to update service account: ${res.status}`);
  }

  const mutation: UseMutationResult<
    ServiceAccount,
    any,
    UpdateServiceAccountData
  > = mutate(["useUpdateServiceAccount"], updateServiceAccount, options);

  return mutation;
};
