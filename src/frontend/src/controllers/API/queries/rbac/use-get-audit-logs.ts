import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface AuditLog {
  id: string;
  event_type: string;
  event_category:
    | "authentication"
    | "authorization"
    | "data_access"
    | "configuration";
  actor_type: "user" | "service_account" | "system";
  actor_id: string;
  actor_name: string;
  resource_type: string;
  resource_id: string | null;
  resource_name: string | null;
  action: string;
  outcome: "success" | "failure" | "pending";
  metadata: Record<string, any>;
  ip_address: string | null;
  user_agent: string | null;
  session_id: string | null;
  timestamp: string;
  severity: "low" | "medium" | "high" | "critical";
}

interface GetAuditLogsQueryParams {
  start_date?: string;
  end_date?: string;
  event_type?: string;
  event_category?: string;
  actor_id?: string;
  resource_type?: string;
  outcome?: string;
  severity?: string;
  skip?: number;
  limit?: number;
}

export const useGetAuditLogs: useMutationFunctionType<
  undefined,
  GetAuditLogsQueryParams,
  { audit_logs: AuditLog[]; total_count: number }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getAuditLogs({
    start_date,
    end_date,
    event_type,
    event_category,
    actor_id,
    resource_type,
    outcome,
    severity,
    skip = 0,
    limit = 50,
  }: GetAuditLogsQueryParams): Promise<{
    audit_logs: AuditLog[];
    total_count: number;
  }> {
    let url = `${getURL("RBAC")}/audit-logs/?skip=${skip}&limit=${limit}`;

    if (start_date) url += `&start_date=${start_date}`;
    if (end_date) url += `&end_date=${end_date}`;
    if (event_type) url += `&event_type=${event_type}`;
    if (event_category) url += `&event_category=${event_category}`;
    if (actor_id) url += `&actor_id=${actor_id}`;
    if (resource_type) url += `&resource_type=${resource_type}`;
    if (outcome) url += `&outcome=${outcome}`;
    if (severity) url += `&severity=${severity}`;

    const res = await api.get(url);
    if (res.status === 200) {
      return res.data;
    }
    return { audit_logs: [], total_count: 0 };
  }

  const mutation: UseMutationResult<
    { audit_logs: AuditLog[]; total_count: number },
    any,
    GetAuditLogsQueryParams
  > = mutate(["useGetAuditLogs"], getAuditLogs, options);

  return mutation;
};
