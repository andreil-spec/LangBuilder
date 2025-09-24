import { useMutation } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import { api } from "../../../../../controllers/API/api";
import { getURL } from "../../../../../controllers/API/helpers/constants";

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

interface ImportResult {
  success: boolean;
  message: string;
  created_roles: number;
  updated_roles: number;
  created_permissions: number;
  updated_permissions: number;
  created_assignments: number;
  updated_assignments: number;
  created_groups: number;
  updated_groups: number;
  errors: string[];
  warnings: string[];
}

interface PreviewResult {
  policy: any;
  changes: {
    roles: { create: any[]; update: any[]; delete: any[] };
    permissions: { create: any[]; update: any[]; delete: any[] };
    assignments: { create: any[]; update: any[]; delete: any[] };
    groups: { create: any[]; update: any[]; delete: any[] };
  };
  summary: {
    total_changes: number;
  };
}

interface Template {
  name: string;
  title: string;
  description: string;
  roles: string[];
  use_cases: string[];
}

export const useRBACIaC = () => {
  const [isLoading, setIsLoading] = useState(false);

  // Export workspace configuration
  const exportWorkspaceConfig = useCallback(
    async (
      workspaceId: string,
      format: "yaml" | "json" | "terraform" = "yaml",
      includeSystem: boolean = false,
    ): Promise<Blob> => {
      setIsLoading(true);
      try {
        const params = new URLSearchParams({
          format,
          include_system: includeSystem.toString(),
        });

        const response = await api.get(
          `${getURL("RBAC")}/iac/export/workspace/${workspaceId}?${params.toString()}`,
          {
            responseType: "blob",
          },
        );

        if (response.status === 200) {
          return response.data;
        }
        throw new Error(`Export failed with status ${response.status}`);
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  // Export global configuration
  const exportGlobalConfig = useCallback(
    async (
      format: "yaml" | "json" | "terraform" = "yaml",
      includeSystem: boolean = true,
    ): Promise<Blob> => {
      setIsLoading(true);
      try {
        const params = new URLSearchParams({
          format,
          include_system: includeSystem.toString(),
        });

        const response = await api.get(
          `${getURL("RBAC")}/iac/export/global?${params.toString()}`,
          {
            responseType: "blob",
          },
        );

        if (response.status === 200) {
          return response.data;
        }
        throw new Error(`Export failed with status ${response.status}`);
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  // Validate configuration
  const validateConfig = useCallback(
    async (
      config: string,
      format: string = "yaml",
    ): Promise<ValidationResult> => {
      setIsLoading(true);
      try {
        const formData = new FormData();
        formData.append("config", config);
        formData.append("format", format);

        const response = await api.post(
          `${getURL("RBAC")}/iac/validate`,
          formData,
          {
            headers: {
              "Content-Type": "multipart/form-data",
            },
          },
        );

        if (response.status === 200) {
          return response.data;
        }
        throw new Error(`Validation failed with status ${response.status}`);
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  // Preview import changes
  const previewImport = useCallback(
    async (
      config: string,
      workspaceId?: string,
      format: string = "yaml",
    ): Promise<PreviewResult> => {
      setIsLoading(true);
      try {
        const formData = new FormData();
        formData.append("config", config);
        formData.append("format", format);
        if (workspaceId) {
          formData.append("workspace_id", workspaceId);
        }

        const response = await api.post(
          `${getURL("RBAC")}/iac/import/preview`,
          formData,
          {
            headers: {
              "Content-Type": "multipart/form-data",
            },
          },
        );

        if (response.status === 200) {
          return response.data;
        }
        throw new Error(`Preview failed with status ${response.status}`);
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  // Apply import configuration
  const applyImport = useCallback(
    async (
      config: string,
      workspaceId?: string,
      dryRun: boolean = false,
      format: string = "yaml",
    ): Promise<ImportResult> => {
      setIsLoading(true);
      try {
        const formData = new FormData();
        formData.append("config", config);
        formData.append("format", format);
        formData.append("dry_run", dryRun.toString());
        if (workspaceId) {
          formData.append("workspace_id", workspaceId);
        }

        const response = await api.post(
          `${getURL("RBAC")}/iac/import/apply`,
          formData,
          {
            headers: {
              "Content-Type": "multipart/form-data",
            },
          },
        );

        if (response.status === 200) {
          return response.data;
        }
        throw new Error(`Import failed with status ${response.status}`);
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  // Import from file
  const importFromFile = useCallback(
    async (
      file: File,
      workspaceId?: string,
      dryRun: boolean = false,
    ): Promise<ImportResult> => {
      setIsLoading(true);
      try {
        const formData = new FormData();
        formData.append("file", file);
        formData.append("dry_run", dryRun.toString());
        if (workspaceId) {
          formData.append("workspace_id", workspaceId);
        }

        const response = await api.post(
          `${getURL("RBAC")}/iac/import/file`,
          formData,
          {
            headers: {
              "Content-Type": "multipart/form-data",
            },
          },
        );

        if (response.status === 200) {
          return response.data;
        }
        throw new Error(`File import failed with status ${response.status}`);
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  // List available templates
  const listTemplates = useCallback(async (): Promise<Template[]> => {
    setIsLoading(true);
    try {
      const response = await api.get(`${getURL("RBAC")}/iac/templates`);

      if (response.status === 200) {
        return response.data;
      }
      throw new Error(`Template listing failed with status ${response.status}`);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Generate template
  const generateTemplate = useCallback(
    async (
      templateType: string,
      workspaceName: string,
      includeExamples: boolean = true,
    ): Promise<Blob> => {
      setIsLoading(true);
      try {
        const response = await api.post(
          `${getURL("RBAC")}/iac/templates/generate`,
          {
            template_type: templateType,
            workspace_name: workspaceName,
            include_examples: includeExamples,
          },
          {
            responseType: "blob",
          },
        );

        if (response.status === 200) {
          return response.data;
        }
        throw new Error(
          `Template generation failed with status ${response.status}`,
        );
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  // Mutation for reactive operations
  const exportMutation = useMutation({
    mutationFn: async ({
      type,
      workspaceId,
      format,
      includeSystem,
    }: {
      type: "workspace" | "global";
      workspaceId?: string;
      format: "yaml" | "json" | "terraform";
      includeSystem: boolean;
    }) => {
      if (type === "workspace" && workspaceId) {
        return exportWorkspaceConfig(workspaceId, format, includeSystem);
      } else {
        return exportGlobalConfig(format, includeSystem);
      }
    },
  });

  const validateMutation = useMutation({
    mutationFn: ({ config, format }: { config: string; format?: string }) =>
      validateConfig(config, format),
  });

  const previewMutation = useMutation({
    mutationFn: ({
      config,
      workspaceId,
      format,
    }: {
      config: string;
      workspaceId?: string;
      format?: string;
    }) => previewImport(config, workspaceId, format),
  });

  const importMutation = useMutation({
    mutationFn: ({
      config,
      workspaceId,
      dryRun,
      format,
    }: {
      config: string;
      workspaceId?: string;
      dryRun?: boolean;
      format?: string;
    }) => applyImport(config, workspaceId, dryRun, format),
  });

  const fileImportMutation = useMutation({
    mutationFn: ({
      file,
      workspaceId,
      dryRun,
    }: {
      file: File;
      workspaceId?: string;
      dryRun?: boolean;
    }) => importFromFile(file, workspaceId, dryRun),
  });

  const templateMutation = useMutation({
    mutationFn: ({
      templateType,
      workspaceName,
      includeExamples,
    }: {
      templateType: string;
      workspaceName: string;
      includeExamples?: boolean;
    }) => generateTemplate(templateType, workspaceName, includeExamples),
  });

  return {
    // Direct functions
    exportWorkspaceConfig,
    exportGlobalConfig,
    validateConfig,
    previewImport,
    applyImport,
    importFromFile,
    listTemplates,
    generateTemplate,

    // Mutations for reactive operations
    exportMutation,
    validateMutation,
    previewMutation,
    importMutation,
    fileImportMutation,
    templateMutation,

    // Loading state
    isLoading:
      isLoading ||
      exportMutation.isPending ||
      validateMutation.isPending ||
      previewMutation.isPending ||
      importMutation.isPending ||
      fileImportMutation.isPending ||
      templateMutation.isPending,
  };
};
