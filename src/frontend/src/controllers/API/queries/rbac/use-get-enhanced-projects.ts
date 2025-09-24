import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import { handleRBACError, normalizeListResponse } from "./error-handler";
import { Project } from "./use-get-projects";

export interface LegacyProject {
  id: string;
  name: string;
  description?: string;
  user_id: string;
  flow_count: number;
  created_at: string;
  updated_at?: string;
  migration_status: "pending" | "migrating" | "completed" | "error";
  migrated_to_project_id?: string;
  type: "legacy";
}

export interface RBACProjectEnhanced extends Project {
  type: "rbac";
}

export type UnifiedProject = RBACProjectEnhanced | LegacyProject;

export interface EnhancedProjectsResponse {
  rbac_projects: RBACProjectEnhanced[];
  legacy_projects: LegacyProject[];
  total_count: number;
  rbac_count: number;
  legacy_count: number;
  page: number;
  page_size: number;
  has_next: boolean;
  has_previous: boolean;
}

interface GetEnhancedProjectsParams {
  workspace_id?: string;
  page?: number;
  page_size?: number;
  search?: string;
  is_active?: boolean;
  is_archived?: boolean;
  include_legacy?: boolean;
}

export const useGetEnhancedProjects: useMutationFunctionType<
  undefined,
  GetEnhancedProjectsParams,
  EnhancedProjectsResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getEnhancedProjects({
    workspace_id,
    page = 1,
    page_size = 50,
    search,
    is_active,
    is_archived,
    include_legacy = true,
  }: GetEnhancedProjectsParams): Promise<EnhancedProjectsResponse> {
    // Get RBAC projects using the working API
    const rbacProjects = await fetchRBACProjects({
      workspace_id,
      page,
      page_size,
      search,
      is_active,
      is_archived,
    });

    // Add type to RBAC projects
    const enhancedRBACProjects: RBACProjectEnhanced[] =
      rbacProjects.projects.map((project) => ({
        ...project,
        type: "rbac" as const,
      }));

    // Mock legacy projects for demonstration
    const mockLegacyProjects: LegacyProject[] = include_legacy
      ? [
          {
            id: "legacy-1",
            name: "Legacy Data Analysis",
            description: "Legacy project for data analysis workflows",
            user_id: "user-1",
            flow_count: 5,
            created_at: "2024-01-15T10:30:00Z",
            updated_at: "2024-02-10T14:20:00Z",
            migration_status: "pending",
            type: "legacy",
          },
          {
            id: "legacy-2",
            name: "Customer Support Bot",
            description: "Legacy chatbot for customer support",
            user_id: "user-2",
            flow_count: 3,
            created_at: "2024-02-01T09:15:00Z",
            updated_at: "2024-03-05T16:45:00Z",
            migration_status: "pending",
            type: "legacy",
          },
          {
            id: "legacy-3",
            name: "Document Processing",
            description: "Legacy document classification system",
            user_id: "user-1",
            flow_count: 8,
            created_at: "2024-01-20T11:00:00Z",
            migration_status: "completed",
            migrated_to_project_id: enhancedRBACProjects[0]?.id,
            type: "legacy",
          },
        ]
      : [];

    // Filter legacy projects by search if provided
    const filteredLegacyProjects = search
      ? mockLegacyProjects.filter(
          (p) =>
            p.name.toLowerCase().includes(search.toLowerCase()) ||
            (p.description &&
              p.description.toLowerCase().includes(search.toLowerCase())),
        )
      : mockLegacyProjects;

    return {
      rbac_projects: enhancedRBACProjects,
      legacy_projects: filteredLegacyProjects,
      total_count: enhancedRBACProjects.length + filteredLegacyProjects.length,
      rbac_count: enhancedRBACProjects.length,
      legacy_count: filteredLegacyProjects.length,
      page: rbacProjects.page,
      page_size: rbacProjects.page_size,
      has_next: rbacProjects.has_next,
      has_previous: rbacProjects.has_previous,
    };
  }

  const mutation: UseMutationResult<
    EnhancedProjectsResponse,
    any,
    GetEnhancedProjectsParams
  > = mutate(["useGetEnhancedProjects"], getEnhancedProjects, options);

  return mutation;
};

// Helper function to fetch RBAC projects
async function fetchRBACProjects(params: any) {
  const searchParams = new URLSearchParams();
  searchParams.append("page", params.page.toString());
  searchParams.append("page_size", params.page_size.toString());

  if (params.workspace_id) {
    searchParams.append("workspace_id", params.workspace_id);
  }
  if (params.search) {
    searchParams.append("search", params.search);
  }
  if (params.is_active !== undefined) {
    searchParams.append("is_active", params.is_active.toString());
  }
  if (params.is_archived !== undefined) {
    searchParams.append("is_archived", params.is_archived.toString());
  }

  const url = `${getURL("RBAC")}/projects/?${searchParams.toString()}`;

  try {
    const res = await api.get(url);

    if (res.status === 200) {
      // Use normalized response handler
      const normalized = normalizeListResponse<Project>(
        res.data,
        "projects",
        params.page,
        params.page_size,
      );

      return {
        projects: normalized.items,
        total_count: normalized.total_count,
        page: normalized.page,
        page_size: normalized.page_size,
        has_next: normalized.has_next,
        has_previous: normalized.has_previous,
      };
    }

    return {
      projects: [],
      total_count: 0,
      page: params.page,
      page_size: params.page_size,
      has_next: false,
      has_previous: false,
    };
  } catch (error) {
    console.warn("Failed to fetch RBAC projects:", error);
    return {
      projects: [],
      total_count: 0,
      page: params.page,
      page_size: params.page_size,
      has_next: false,
      has_previous: false,
    };
  }
}
