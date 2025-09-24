import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import { handleRBACError, normalizeListResponse } from "./error-handler";

export enum AuditEventType {
  // Authentication events
  LOGIN = "login",
  LOGOUT = "logout",
  LOGIN_FAILED = "login_failed",
  PASSWORD_CHANGE = "password_change",
  MFA_ENABLED = "mfa_enabled",
  MFA_DISABLED = "mfa_disabled",

  // Authorization events
  PERMISSION_GRANTED = "permission_granted",
  PERMISSION_REVOKED = "permission_revoked",
  ROLE_ASSIGNED = "role_assigned",
  ROLE_REMOVED = "role_removed",
  ACCESS_DENIED = "access_denied",

  // Resource operations
  RESOURCE_CREATED = "resource_created",
  RESOURCE_READ = "resource_read",
  RESOURCE_UPDATED = "resource_updated",
  RESOURCE_DELETED = "resource_deleted",
  RESOURCE_EXPORTED = "resource_exported",
  RESOURCE_IMPORTED = "resource_imported",
  RESOURCE_SHARED = "resource_shared",
  RESOURCE_PUBLISHED = "resource_published",

  // Workspace operations
  WORKSPACE_CREATED = "workspace_created",
  WORKSPACE_UPDATED = "workspace_updated",
  WORKSPACE_DELETED = "workspace_deleted",
  WORKSPACE_USER_ADDED = "workspace_user_added",
  WORKSPACE_USER_REMOVED = "workspace_user_removed",

  // Security events
  SECURITY_ALERT = "security_alert",
  BREAK_GLASS_ACCESS = "break_glass_access",
  IMPERSONATION_START = "impersonation_start",
  IMPERSONATION_END = "impersonation_end",
  SUSPICIOUS_ACTIVITY = "suspicious_activity",

  // System events
  SYSTEM_CONFIG_CHANGE = "system_config_change",
  BACKUP_CREATED = "backup_created",
  RESTORE_PERFORMED = "restore_performed",
  COMPLIANCE_EXPORT = "compliance_export",
}

export enum ActorType {
  USER = "user",
  SERVICE_ACCOUNT = "service_account",
  SYSTEM = "system",
  API_CLIENT = "api_client",
  SCHEDULER = "scheduler",
  ANONYMOUS = "anonymous",
}

export enum AuditOutcome {
  SUCCESS = "success",
  FAILURE = "failure",
  PARTIAL = "partial",
  DENIED = "denied",
  ERROR = "error",
}

export interface AuditLog {
  id: string;
  event_type: AuditEventType;
  action: string;
  outcome: AuditOutcome;
  actor_type: ActorType;
  actor_id: string | null;
  actor_name: string | null;
  actor_email: string | null;
  workspace_id: string;
  workspace_name: string | null;
  resource_type: string | null;
  resource_id: string | null;
  resource_name: string | null;
  ip_address: string | null;
  user_agent: string | null;
  api_endpoint: string | null;
  request_id: string | null;
  session_id: string | null;
  location: string | null;
  metadata: Record<string, any> | null;
  error_message: string | null;
  error_code: string | null;
  timestamp: string;
  compliance_tags: string[] | null;
  retention_policy: string | null;
  risk_score: number | null;
  correlation_id: string | null;
}

interface GetAuditLogsQueryParams {
  workspace_id?: string;
  page?: number;
  page_size?: number;
  event_type?: AuditEventType;
  actor_type?: ActorType;
  outcome?: AuditOutcome;
  actor_id?: string;
  resource_type?: string;
  resource_id?: string;
  start_date?: string;
  end_date?: string;
  search?: string;
}

interface AuditLogListResponse {
  audit_logs: AuditLog[];
  total_count: number;
  page: number;
  page_size: number;
  has_next: boolean;
  has_previous: boolean;
}

interface ExportAuditLogsData {
  workspace_id?: string;
  format: "csv" | "json" | "pdf";
  start_date?: string;
  end_date?: string;
  event_types?: AuditEventType[];
  actor_types?: ActorType[];
  outcomes?: AuditOutcome[];
  include_metadata?: boolean;
  include_sensitive?: boolean;
}

// Get Audit Logs
export const useGetAuditLogs: useMutationFunctionType<
  undefined,
  GetAuditLogsQueryParams,
  AuditLogListResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getAuditLogs({
    workspace_id,
    page = 1,
    page_size = 50,
    event_type,
    actor_type,
    outcome,
    actor_id,
    resource_type,
    resource_id,
    start_date,
    end_date,
    search,
  }: GetAuditLogsQueryParams): Promise<AuditLogListResponse> {
    try {
      const params = new URLSearchParams();
      if (workspace_id) {
        params.append("workspace_id", workspace_id);
      }
      params.append("page", page.toString());
      params.append("size", page_size.toString());

      if (event_type) {
        params.append("event_type", event_type);
      }
      if (actor_type) {
        params.append("actor_type", actor_type);
      }
      if (outcome) {
        params.append("outcome", outcome);
      }
      if (actor_id) {
        params.append("actor_id", actor_id);
      }
      if (resource_type) {
        params.append("resource_type", resource_type);
      }
      if (resource_id) {
        params.append("resource_id", resource_id);
      }
      if (start_date) {
        params.append("start_date", start_date);
      }
      if (end_date) {
        params.append("end_date", end_date);
      }
      if (search) {
        params.append("search", search);
      }

      const url = `${getURL("RBAC")}/audit/logs?${params.toString()}`;
      const res = await api.get(url);

      if (res.status === 200) {
        const normalized = normalizeListResponse<AuditLog>(
          res.data,
          "audit_logs",
          page,
          page_size,
        );

        return {
          audit_logs: normalized.items,
          total_count: normalized.total_count,
          page: normalized.page,
          page_size: normalized.page_size,
          has_next: normalized.has_next,
          has_previous: normalized.has_previous,
        };
      }

      return {
        audit_logs: [],
        total_count: 0,
        page: page,
        page_size: page_size,
        has_next: false,
        has_previous: false,
      };
    } catch (error) {
      handleRBACError(error, "audit logs list");
    }
  }

  const mutation: UseMutationResult<
    AuditLogListResponse,
    any,
    GetAuditLogsQueryParams
  > = mutate(["useGetAuditLogs"], getAuditLogs, options || {});

  return mutation;
};

// Get Single Audit Log
export const useGetAuditLog: useMutationFunctionType<
  undefined,
  { log_id: string },
  AuditLog
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getAuditLog({
    log_id,
  }: {
    log_id: string;
  }): Promise<AuditLog> {
    try {
      const url = `${getURL("RBAC")}/audit/logs/${log_id}`;
      const res = await api.get(url);

      if (res.status === 200) {
        return res.data;
      }

      throw new Error("Failed to get audit log");
    } catch (error) {
      handleRBACError(error, "audit log details");
    }
  }

  const mutation: UseMutationResult<AuditLog, any, { log_id: string }> = mutate(
    ["useGetAuditLog"],
    getAuditLog,
    options || {},
  );

  return mutation;
};

// Export Audit Logs
export const useExportAuditLogs: useMutationFunctionType<
  undefined,
  ExportAuditLogsData,
  { download_url: string; export_id: string }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function exportAuditLogs(
    data: ExportAuditLogsData,
  ): Promise<{ download_url: string; export_id: string }> {
    try {
      const url = `${getURL("RBAC")}/audit/logs/export`;
      const res = await api.post(url, data);

      if (res.status === 200) {
        return res.data;
      }

      throw new Error("Failed to export audit logs");
    } catch (error) {
      handleRBACError(error, "audit logs export");
    }
  }

  const mutation: UseMutationResult<
    { download_url: string; export_id: string },
    any,
    ExportAuditLogsData
  > = mutate(["useExportAuditLogs"], exportAuditLogs, options || {});

  return mutation;
};

// Helper function to get event type color
export function getEventTypeColor(eventType: AuditEventType): string {
  switch (eventType) {
    case AuditEventType.LOGIN:
    case AuditEventType.LOGOUT:
      return "blue";
    case AuditEventType.LOGIN_FAILED:
    case AuditEventType.ACCESS_DENIED:
      return "red";
    case AuditEventType.PERMISSION_GRANTED:
    case AuditEventType.ROLE_ASSIGNED:
      return "green";
    case AuditEventType.PERMISSION_REVOKED:
    case AuditEventType.ROLE_REMOVED:
      return "orange";
    case AuditEventType.RESOURCE_CREATED:
    case AuditEventType.WORKSPACE_CREATED:
      return "emerald";
    case AuditEventType.RESOURCE_DELETED:
    case AuditEventType.WORKSPACE_DELETED:
      return "red";
    case AuditEventType.RESOURCE_UPDATED:
    case AuditEventType.WORKSPACE_UPDATED:
      return "yellow";
    case AuditEventType.SECURITY_ALERT:
    case AuditEventType.SUSPICIOUS_ACTIVITY:
      return "red";
    case AuditEventType.BREAK_GLASS_ACCESS:
      return "purple";
    default:
      return "gray";
  }
}

// Helper function to get outcome color
export function getOutcomeColor(outcome: AuditOutcome): string {
  switch (outcome) {
    case AuditOutcome.SUCCESS:
      return "green";
    case AuditOutcome.FAILURE:
    case AuditOutcome.ERROR:
      return "red";
    case AuditOutcome.DENIED:
      return "orange";
    case AuditOutcome.PARTIAL:
      return "yellow";
    default:
      return "gray";
  }
}

// Helper function to format event type for display
export function formatEventType(eventType: AuditEventType): string {
  return eventType.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase());
}

// Helper function to format actor type for display
export function formatActorType(actorType: ActorType): string {
  return actorType.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase());
}
