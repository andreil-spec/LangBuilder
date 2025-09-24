import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface Environment {
  id: string;
  name: string;
  description: string | null;
  project_id: string;
  type: "development" | "staging" | "production" | "testing";
  is_active: boolean;
  is_default: boolean;
  variables: Record<string, any>;
  created_at: string;
  updated_at: string;
  deployment_count?: number;
  last_deployed_at?: string;
}

interface GetEnvironmentsQueryParams {
  project_id?: string;
  type?: string;
  skip?: number;
  limit?: number;
  search?: string;
  is_active?: boolean;
}

export const useGetEnvironments: useMutationFunctionType<
  undefined,
  GetEnvironmentsQueryParams,
  { environments: Environment[]; total_count: number }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getEnvironments({
    project_id,
    type,
    skip = 0,
    limit = 50,
    search,
    is_active,
  }: GetEnvironmentsQueryParams): Promise<{
    environments: Environment[];
    total_count: number;
  }> {
    try {
      // If a specific project_id is provided, fetch environments for that project
      if (project_id) {
        let url = `${getURL("RBAC")}/environments/?skip=${skip}&limit=${limit}&project_id=${project_id}`;

        if (type) url += `&type=${type}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (is_active !== undefined) url += `&is_active=${is_active}`;

        const res = await api.get(url);
        if (res.status === 200) {
          return res.data;
        }
        return { environments: [], total_count: 0 };
      }

      // If no project_id is provided, fetch all projects first, then get environments for each
      const projectsUrl = `${getURL("RBAC")}/projects/?page=1&page_size=100`;
      const projectsRes = await api.get(projectsUrl);

      if (projectsRes.status !== 200 || !projectsRes.data?.projects) {
        return { environments: [], total_count: 0 };
      }

      const projects = projectsRes.data.projects;
      const allEnvironments: Environment[] = [];

      // Fetch environments for each project
      for (const project of projects) {
        let url = `${getURL("RBAC")}/environments/?project_id=${project.id}`;

        if (type) url += `&type=${type}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (is_active !== undefined) url += `&is_active=${is_active}`;

        try {
          const envRes = await api.get(url);
          if (envRes.status === 200 && envRes.data) {
            allEnvironments.push(...envRes.data);
          }
        } catch (error) {
          console.warn(`Failed to fetch environments for project ${project.id}:`, error);
          // Continue with other projects even if one fails
        }
      }

      // Apply limit and skip to the combined results
      const filteredEnvironments = allEnvironments.slice(skip, skip + limit);

      return {
        environments: filteredEnvironments,
        total_count: allEnvironments.length,
      };
    } catch (error) {
      console.error("Failed to fetch environments:", error);
      return { environments: [], total_count: 0 };
    }
  }

  const mutation: UseMutationResult<
    { environments: Environment[]; total_count: number },
    any,
    GetEnvironmentsQueryParams
  > = mutate(["useGetEnvironments"], getEnvironments, options);

  return mutation;
};
