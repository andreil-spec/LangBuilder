import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import type { Project } from "./use-get-projects";

export interface CreateProjectData {
  name: string;
  description?: string;
  workspace_id: string;
  repository_url?: string;
  documentation_url?: string;
  tags?: string[];
  auto_deploy_enabled?: boolean;
  retention_days?: number;
}

export const useCreateProject: useMutationFunctionType<
  undefined,
  CreateProjectData,
  Project
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createProject(
    projectData: CreateProjectData,
  ): Promise<Project> {
    const res = await api.post(`${getURL("RBAC")}/projects/`, projectData);
    if (res.status === 201) {
      return res.data;
    }
    throw new Error(`Failed to create project: ${res.status}`);
  }

  const mutation: UseMutationResult<Project, any, CreateProjectData> = mutate(
    ["useCreateProject"],
    createProject,
    options,
  );

  return mutation;
};
