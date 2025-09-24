import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface MigrateProjectData {
  folder_id: string;
  workspace_id: string;
  environment_name?: string;
}

export interface MigrateProjectResponse {
  success: boolean;
  message: string;
  project: {
    id: string;
    name: string;
    description?: string;
    workspace_id: string;
    type: "rbac";
  };
}

export const useMigrateProject: useMutationFunctionType<
  undefined,
  MigrateProjectData,
  MigrateProjectResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function migrateProject({
    folder_id,
    workspace_id,
    environment_name = "production",
  }: MigrateProjectData): Promise<MigrateProjectResponse> {
    const res = await api.post(`${getURL("RBAC")}/unified-projects/migrate`, {
      folder_id,
      workspace_id,
      environment_name,
    });
    if (res.status === 200) {
      return res.data;
    }
    throw new Error(`Failed to migrate project: ${res.status}`);
  }

  const mutation: UseMutationResult<
    MigrateProjectResponse,
    any,
    MigrateProjectData
  > = mutate(["useMigrateProject"], migrateProject, options);

  return mutation;
};
