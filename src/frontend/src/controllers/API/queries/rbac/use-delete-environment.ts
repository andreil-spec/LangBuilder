import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface DeleteEnvironmentData {
  environment_id: string;
}

export const useDeleteEnvironment: useMutationFunctionType<
  undefined,
  DeleteEnvironmentData,
  { success: boolean }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function deleteEnvironment({
    environment_id,
  }: DeleteEnvironmentData): Promise<{ success: boolean }> {
    const res = await api.delete(
      `${getURL("RBAC")}/environments/${environment_id}`,
    );
    if (res.status === 204) {
      return { success: true };
    }
    throw new Error(`Failed to delete environment: ${res.status}`);
  }

  const mutation: UseMutationResult<
    { success: boolean },
    any,
    DeleteEnvironmentData
  > = mutate(["useDeleteEnvironment"], deleteEnvironment, options);

  return mutation;
};
