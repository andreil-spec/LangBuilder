import { useRBAC } from "@/contexts/rbacContext";

// Define permission actions for different resources
export const PERMISSIONS = {
  FLOWS: {
    CREATE: "create",
    READ: "read",
    UPDATE: "update",
    DELETE: "delete",
    EXECUTE: "execute",
    SHARE: "share",
    EXPORT: "export",
  },
  PROJECTS: {
    CREATE: "create",
    READ: "read",
    UPDATE: "update",
    DELETE: "delete",
    MANAGE: "manage",
  },
  API_KEYS: {
    CREATE: "create",
    READ: "read",
    UPDATE: "update",
    DELETE: "delete",
    MANAGE: "manage",
  },
  WORKSPACES: {
    CREATE: "create",
    READ: "read",
    UPDATE: "update",
    DELETE: "delete",
    MANAGE: "manage",
    INVITE_USERS: "invite_users",
  },
  USERS: {
    READ: "read",
    UPDATE: "update",
    DELETE: "delete",
    MANAGE: "manage",
    ASSIGN_ROLES: "assign_roles",
  },
  ROLES: {
    CREATE: "create",
    READ: "read",
    UPDATE: "update",
    DELETE: "delete",
    ASSIGN: "assign",
  },
  ENVIRONMENTS: {
    CREATE: "create",
    READ: "read",
    UPDATE: "update",
    DELETE: "delete",
    MANAGE: "manage",
    DEPLOY: "deploy",
  },
} as const;

export const RESOURCES = {
  FLOW: "flow",
  PROJECT: "project",
  API_KEY: "api_key",
  WORKSPACE: "workspace",
  USER: "user",
  ROLE: "role",
  ENVIRONMENT: "environment",
} as const;

export function useRBACPermissions() {
  const {
    hasPermission,
    isLoading,
    currentWorkspace,
    currentProject,
    isDangerousAction,
    requiresMFA,
  } = useRBAC();

  return {
    // Flow permissions
    canCreateFlow: (projectId?: string) =>
      hasPermission(RESOURCES.FLOW, PERMISSIONS.FLOWS.CREATE, projectId),
    canEditFlow: (flowId: string) =>
      hasPermission(RESOURCES.FLOW, PERMISSIONS.FLOWS.UPDATE, flowId),
    canDeleteFlow: (flowId: string) =>
      hasPermission(RESOURCES.FLOW, PERMISSIONS.FLOWS.DELETE, flowId),
    canExecuteFlow: (flowId: string) =>
      hasPermission(RESOURCES.FLOW, PERMISSIONS.FLOWS.EXECUTE, flowId),
    canShareFlow: (flowId: string) =>
      hasPermission(RESOURCES.FLOW, PERMISSIONS.FLOWS.SHARE, flowId),
    canExportFlow: (flowId: string) =>
      hasPermission(RESOURCES.FLOW, PERMISSIONS.FLOWS.EXPORT, flowId),

    // Project permissions
    canCreateProject: (workspaceId?: string) =>
      hasPermission(
        RESOURCES.PROJECT,
        PERMISSIONS.PROJECTS.CREATE,
        workspaceId,
      ),
    canEditProject: (projectId: string) =>
      hasPermission(RESOURCES.PROJECT, PERMISSIONS.PROJECTS.UPDATE, projectId),
    canDeleteProject: (projectId: string) =>
      hasPermission(RESOURCES.PROJECT, PERMISSIONS.PROJECTS.DELETE, projectId),
    canManageProject: (projectId: string) =>
      hasPermission(RESOURCES.PROJECT, PERMISSIONS.PROJECTS.MANAGE, projectId),

    // API Key permissions
    canCreateApiKey: () =>
      hasPermission(RESOURCES.API_KEY, PERMISSIONS.API_KEYS.CREATE),
    canViewApiKeys: () =>
      hasPermission(RESOURCES.API_KEY, PERMISSIONS.API_KEYS.READ),
    canDeleteApiKey: (keyId: string) =>
      hasPermission(RESOURCES.API_KEY, PERMISSIONS.API_KEYS.DELETE, keyId),
    canManageApiKeys: () =>
      hasPermission(RESOURCES.API_KEY, PERMISSIONS.API_KEYS.MANAGE),

    // Workspace permissions
    canCreateWorkspace: () =>
      hasPermission(RESOURCES.WORKSPACE, PERMISSIONS.WORKSPACES.CREATE),
    canEditWorkspace: (workspaceId: string) =>
      hasPermission(
        RESOURCES.WORKSPACE,
        PERMISSIONS.WORKSPACES.UPDATE,
        workspaceId,
      ),
    canDeleteWorkspace: (workspaceId: string) =>
      hasPermission(
        RESOURCES.WORKSPACE,
        PERMISSIONS.WORKSPACES.DELETE,
        workspaceId,
      ),
    canManageWorkspace: (workspaceId: string) =>
      hasPermission(
        RESOURCES.WORKSPACE,
        PERMISSIONS.WORKSPACES.MANAGE,
        workspaceId,
      ),
    canInviteUsers: (workspaceId: string) =>
      hasPermission(
        RESOURCES.WORKSPACE,
        PERMISSIONS.WORKSPACES.INVITE_USERS,
        workspaceId,
      ),

    // User management permissions
    canViewUsers: () => hasPermission(RESOURCES.USER, PERMISSIONS.USERS.READ),
    canManageUsers: () =>
      hasPermission(RESOURCES.USER, PERMISSIONS.USERS.MANAGE),
    canAssignRoles: () =>
      hasPermission(RESOURCES.USER, PERMISSIONS.USERS.ASSIGN_ROLES),

    // Role management permissions
    canCreateRole: () =>
      hasPermission(RESOURCES.ROLE, PERMISSIONS.ROLES.CREATE),
    canViewRoles: () => hasPermission(RESOURCES.ROLE, PERMISSIONS.ROLES.READ),
    canEditRole: (roleId: string) =>
      hasPermission(RESOURCES.ROLE, PERMISSIONS.ROLES.UPDATE, roleId),
    canDeleteRole: (roleId: string) =>
      hasPermission(RESOURCES.ROLE, PERMISSIONS.ROLES.DELETE, roleId),
    canAssignRole: (roleId: string) =>
      hasPermission(RESOURCES.ROLE, PERMISSIONS.ROLES.ASSIGN, roleId),

    // Environment permissions
    canCreateEnvironment: (projectId: string) =>
      hasPermission(
        RESOURCES.ENVIRONMENT,
        PERMISSIONS.ENVIRONMENTS.CREATE,
        projectId,
      ),
    canEditEnvironment: (environmentId: string) =>
      hasPermission(
        RESOURCES.ENVIRONMENT,
        PERMISSIONS.ENVIRONMENTS.UPDATE,
        environmentId,
      ),
    canDeleteEnvironment: (environmentId: string) =>
      hasPermission(
        RESOURCES.ENVIRONMENT,
        PERMISSIONS.ENVIRONMENTS.DELETE,
        environmentId,
      ),
    canDeployToEnvironment: (environmentId: string) =>
      hasPermission(
        RESOURCES.ENVIRONMENT,
        PERMISSIONS.ENVIRONMENTS.DEPLOY,
        environmentId,
      ),

    // Utility functions
    hasPermission,
    isLoading,
    currentWorkspace,
    currentProject,

    // Security checks
    isDangerousAction,
    requiresMFA,

    // Helper for dangerous operations
    isDeleteOperation: (resource: string, action: string) =>
      isDangerousAction(resource, action) && action.includes("delete"),
    isMFARequired: (resource: string, action: string) =>
      requiresMFA(resource, action),
  };
}
