import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface ComplianceReport {
  id: string;
  report_type: "security" | "access" | "audit" | "full";
  generated_at: string;
  generated_by_id: string;
  generated_by_name: string;
  workspace_id?: string;
  workspace_name?: string;
  scope_type: "global" | "workspace" | "project" | "environment";
  scope_id?: string;
  scope_name?: string;
  status: "generating" | "completed" | "failed";
  summary: {
    total_users: number;
    total_service_accounts: number;
    total_roles: number;
    total_permissions: number;
    security_issues: number;
    compliance_score: number;
  };
  findings: Array<{
    id: string;
    type: "critical" | "high" | "medium" | "low" | "info";
    category: string;
    title: string;
    description: string;
    resource_type: string;
    resource_id: string;
    remediation: string;
  }>;
  download_url?: string;
  expires_at: string;
}

interface GetComplianceReportQueryParams {
  workspace_id?: string;
  report_type?: "security" | "access" | "audit" | "full";
  scope_type?: "global" | "workspace" | "project" | "environment";
  scope_id?: string;
  format?: "json" | "pdf" | "csv";
  include_findings?: boolean;
}

export const useGetComplianceReport: useMutationFunctionType<
  undefined,
  GetComplianceReportQueryParams,
  ComplianceReport
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getComplianceReport({
    workspace_id,
    report_type = "full",
    scope_type = "global",
    scope_id,
    format = "json",
    include_findings = true,
  }: GetComplianceReportQueryParams): Promise<ComplianceReport> {
    let url = `${getURL("RBAC")}/compliance/report?report_type=${report_type}&scope_type=${scope_type}&format=${format}&include_findings=${include_findings}`;

    if (workspace_id) url += `&workspace_id=${workspace_id}`;
    if (scope_id) url += `&scope_id=${scope_id}`;

    const res = await api.get(url);
    if (res.status === 200) {
      return res.data;
    }
    throw new Error(`Failed to generate compliance report: ${res.status}`);
  }

  const mutation: UseMutationResult<
    ComplianceReport,
    any,
    GetComplianceReportQueryParams
  > = mutate(["useGetComplianceReport"], getComplianceReport, options);

  return mutation;
};
