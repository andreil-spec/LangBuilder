import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface DeleteServiceAccountData {
  service_account_id: string;
}

export const useDeleteServiceAccount: useMutationFunctionType<
  undefined,
  DeleteServiceAccountData,
  { success: boolean }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function deleteServiceAccount({
    service_account_id,
  }: DeleteServiceAccountData): Promise<{ success: boolean }> {
    const res = await api.delete(
      `${getURL("RBAC")}/service-accounts/${service_account_id}`,
    );
    if (res.status === 204) {
      return { success: true };
    }
    throw new Error(`Failed to delete service account: ${res.status}`);
  }

  const mutation: UseMutationResult<
    { success: boolean },
    any,
    DeleteServiceAccountData
  > = mutate(["useDeleteServiceAccount"], deleteServiceAccount, options);

  return mutation;
};
