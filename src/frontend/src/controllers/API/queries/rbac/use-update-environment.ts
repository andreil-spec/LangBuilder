import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { Environment } from "./use-get-environments";

export interface UpdateEnvironmentData {
  environment_id: string;
  environment: {
    name?: string;
    description?: string;
    type?: "development" | "staging" | "production" | "testing";
    is_active?: boolean;
    is_default?: boolean;
    variables?: Record<string, any>;
  };
}

export const useUpdateEnvironment: useMutationFunctionType<
  undefined,
  UpdateEnvironmentData,
  Environment
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function updateEnvironment({
    environment_id,
    environment,
  }: UpdateEnvironmentData): Promise<Environment> {
    const res = await api.patch(
      `${getURL("RBAC")}/environments/${environment_id}`,
      environment,
    );
    if (res.status === 200) {
      return res.data;
    }
    throw new Error(`Failed to update environment: ${res.status}`);
  }

  const mutation: UseMutationResult<Environment, any, UpdateEnvironmentData> =
    mutate(["useUpdateEnvironment"], updateEnvironment, options);

  return mutation;
};
