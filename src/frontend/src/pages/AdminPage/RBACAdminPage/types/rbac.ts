// RBAC TypeScript types based on PRD requirements
// Hierarchical scope: Workspace > Project > Environment > Flow > Component

export type UUID = string;

// Permission types from PRD Epic 1
export type CRUDAction = "create" | "read" | "update" | "delete";
export type ExtendedAction =
  | "export_flow"
  | "deploy_environment"
  | "invite_users"
  | "modify_component_settings"
  | "manage_tokens";

export type PermissionAction = CRUDAction | ExtendedAction;

// Hierarchical scope types from PRD
export type ScopeType =
  | "workspace"
  | "project"
  | "environment"
  | "flow"
  | "component";

export interface Scope {
  type: ScopeType;
  id: UUID;
  name: string;
}

// Core RBAC entities

export interface Permission {
  id: UUID;
  action: PermissionAction;
  resource_type: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface Role {
  id: UUID;
  name: string;
  description?: string;
  permissions: Permission[];
  is_system_role: boolean;
  version: number;
  created_at: string;
  updated_at: string;
  created_by: UUID;
}

// Hierarchical entities (Epic 2)
export interface Workspace {
  id: UUID;
  name: string;
  description?: string;
  owner_id: UUID;
  settings: Record<string, any>;
  member_count: number;
  project_count: number;
  created_at: string;
  updated_at: string;
}

export interface Project {
  id: UUID;
  name: string;
  description?: string;
  workspace_id: UUID;
  workspace: Workspace;
  owner_id: UUID;
  environment_count: number;
  flow_count: number;
  created_at: string;
  updated_at: string;
}

export interface Environment {
  id: UUID;
  name: string;
  description?: string;
  project_id: UUID;
  project: Project;
  environment_type: "development" | "staging" | "production";
  configuration: Record<string, any>;
  created_at: string;
  updated_at: string;
}

// Identity management (Epic 2)
export interface User {
  id: UUID;
  email: string;
  name: string;
  is_active: boolean;
  last_login?: string;
  created_at: string;
  updated_at: string;
}

export interface UserGroup {
  id: UUID;
  name: string;
  description?: string;
  member_count: number;
  external_id?: string; // For SCIM integration
  created_at: string;
  updated_at: string;
}

export interface ServiceAccount {
  id: UUID;
  name: string;
  description?: string;
  is_active: boolean;
  token_count: number;
  last_used?: string;
  created_at: string;
  updated_at: string;
}

// Role assignments (Epic 2: AC1-AC9)
export interface RoleAssignment {
  id: UUID;
  principal_type: "user" | "group" | "service_account";
  principal_id: UUID;
  principal: User | UserGroup | ServiceAccount;
  role_id: UUID;
  role: Role;
  scope: Scope;
  expires_at?: string;
  created_at: string;
  created_by: UUID;
}

// Audit logging (Epic 5)
export interface AuditLog {
  id: UUID;
  actor_id: UUID;
  actor: User;
  action: string;
  resource_type: string;
  resource_id: UUID;
  details: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  timestamp: string;
}

// API request/response types
export interface CreateWorkspaceRequest {
  name: string;
  description?: string;
}

export interface UpdateWorkspaceRequest {
  name?: string;
  description?: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permission_ids: UUID[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permission_ids?: UUID[];
}

export interface CreateRoleAssignmentRequest {
  principal_type: "user" | "group" | "service_account";
  principal_id: UUID;
  role_id: UUID;
  scope: Scope;
  expires_at?: string;
}

export interface CreateUserGroupRequest {
  name: string;
  description?: string;
  user_ids?: UUID[];
}

export interface CreateServiceAccountRequest {
  name: string;
  description?: string;
  scope: Scope;
  permissions: PermissionAction[];
}

// UI state types
export interface RBACUIState {
  selectedWorkspace?: Workspace;
  selectedProject?: Project;
  selectedEnvironment?: Environment;
  selectedRole?: Role;
  selectedUser?: User;
  loading: boolean;
  error?: string;
}

// Filter and pagination types
export interface PaginationParams {
  page: number;
  page_size: number;
  total?: number;
}

export interface WorkspaceFilters {
  search?: string;
  owner_id?: UUID;
  created_after?: string;
  created_before?: string;
}

export interface RoleFilters {
  search?: string;
  is_system_role?: boolean;
  has_permission?: PermissionAction;
}

export interface AuditLogFilters {
  actor_id?: UUID;
  action?: string;
  resource_type?: string;
  start_date?: string;
  end_date?: string;
}

// Component props types
export interface PermissionSelectorProps {
  selectedPermissions: Permission[];
  onPermissionsChange: (permissions: Permission[]) => void;
  disabled?: boolean;
}

export interface ScopeSelectorProps {
  scope: Scope | null;
  onScopeChange: (scope: Scope | null) => void;
  allowedTypes?: ScopeType[];
  disabled?: boolean;
}

export interface RoleAssignmentTableProps {
  assignments: RoleAssignment[];
  onEdit?: (assignment: RoleAssignment) => void;
  onDelete?: (assignmentId: UUID) => void;
  loading?: boolean;
}
