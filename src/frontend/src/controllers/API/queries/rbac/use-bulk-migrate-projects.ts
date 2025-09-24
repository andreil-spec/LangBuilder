import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface BulkMigrationItem {
  folder_id: string;
  workspace_id: string;
  environment_name?: string;
}

export interface BulkMigrationResult {
  folder_id: string;
  project_id?: string;
  success: boolean;
  project_name?: string;
  error?: string;
}

export interface BulkMigrationResponse {
  success: boolean;
  summary: {
    total_requested: number;
    successful: number;
    failed: number;
  };
  results: BulkMigrationResult[];
}

export const useBulkMigrateProjects: useMutationFunctionType<
  undefined,
  BulkMigrationItem[],
  BulkMigrationResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function bulkMigrateProjects(
    migrations: BulkMigrationItem[],
  ): Promise<BulkMigrationResponse> {
    const res = await api.post(
      `${getURL("RBAC")}/unified-projects/migrate/bulk`,
      migrations,
    );
    if (res.status === 200) {
      return res.data;
    }
    throw new Error(`Failed to bulk migrate projects: ${res.status}`);
  }

  const mutation: UseMutationResult<
    BulkMigrationResponse,
    any,
    BulkMigrationItem[]
  > = mutate(["useBulkMigrateProjects"], bulkMigrateProjects, options);

  return mutation;
};
