// ComplianceReportGenerator - Advanced audit & export capabilities
import { useEffect, useState } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import useAuthStore from "@/stores/authStore";

interface AuditEntry {
  id: string;
  timestamp: string;
  user_id: string;
  user_name: string;
  action: string;
  resource_type: string;
  resource_id: string;
  result: "success" | "failure" | "denied";
  ip_address: string;
  user_agent: string;
  details: Record<string, any>;
  compliance_tags: string[];
}

interface ComplianceTemplate {
  id: string;
  name: string;
  description: string;
  required_fields: string[];
  filters: Record<string, any>;
  format: "csv" | "json" | "pdf";
}

interface FilterState {
  user_id?: string;
  action?: string;
  resource_type?: string;
  result?: string;
  start_date?: string;
  end_date?: string;
  compliance_tag?: string;
}

export default function ComplianceReportGenerator() {
  const [selectedEntries, setSelectedEntries] = useState<string[]>([]);
  const [filters, setFilters] = useState<FilterState>({});
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");
  const [customFields, setCustomFields] = useState<string[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [auditData, setAuditData] = useState<AuditEntry[]>([]);
  const [searchTerm, setSearchTerm] = useState("");

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // Compliance templates (SOC 2, ISO 27001, etc.)
  const complianceTemplates: ComplianceTemplate[] = [
    {
      id: "soc2",
      name: "SOC 2 Access Report",
      description: "User access and privilege changes for SOC 2 compliance",
      required_fields: [
        "timestamp",
        "user_name",
        "action",
        "resource_type",
        "result",
      ],
      filters: {
        action: [
          "user_login",
          "role_assignment",
          "permission_change",
          "access_denied",
        ],
        compliance_tag: "SOC2",
      },
      format: "csv",
    },
    {
      id: "iso27001",
      name: "ISO 27001 Security Events",
      description: "Security-related events and access controls for ISO 27001",
      required_fields: [
        "timestamp",
        "user_name",
        "action",
        "resource_type",
        "result",
        "ip_address",
      ],
      filters: {
        action: [
          "failed_login",
          "privilege_escalation",
          "system_access",
          "data_export",
        ],
        result: ["failure", "denied"],
      },
      format: "json",
    },
    {
      id: "gdpr",
      name: "GDPR Data Access Log",
      description: "Data access and processing activities for GDPR compliance",
      required_fields: [
        "timestamp",
        "user_name",
        "action",
        "resource_type",
        "details",
      ],
      filters: {
        resource_type: ["user_data", "personal_info", "analytics_data"],
        action: [
          "data_export",
          "data_view",
          "data_modification",
          "data_deletion",
        ],
      },
      format: "csv",
    },
    {
      id: "pci_dss",
      name: "PCI DSS Access Control",
      description: "Payment card data access and security events",
      required_fields: [
        "timestamp",
        "user_name",
        "action",
        "resource_type",
        "result",
        "ip_address",
      ],
      filters: {
        compliance_tag: "PCI_DSS",
        resource_type: ["payment_data", "cardholder_data"],
      },
      format: "pdf",
    },
    {
      id: "custom",
      name: "Custom Report",
      description: "Custom audit report with user-defined fields and filters",
      required_fields: [],
      filters: {},
      format: "json",
    },
  ];

  // Mock audit data (in real implementation, this would come from API)
  useEffect(() => {
    if (isAdmin) {
      loadAuditData();
    }
  }, [isAdmin, filters]);

  const loadAuditData = () => {
    // Mock audit entries for demonstration
    const mockEntries: AuditEntry[] = [
      {
        id: "audit-1",
        timestamp: "2024-01-15T10:30:00Z",
        user_id: "user-123",
        user_name: "john.doe@company.com",
        action: "role_assignment",
        resource_type: "role",
        resource_id: "admin-role",
        result: "success",
        ip_address: "192.168.1.100",
        user_agent: "Mozilla/5.0...",
        details: { assigned_role: "admin", scope: "workspace:main" },
        compliance_tags: ["SOC2", "ISO27001"],
      },
      {
        id: "audit-2",
        timestamp: "2024-01-15T11:15:00Z",
        user_id: "user-456",
        user_name: "jane.smith@company.com",
        action: "data_export",
        resource_type: "user_data",
        resource_id: "export-789",
        result: "success",
        ip_address: "192.168.1.101",
        user_agent: "Mozilla/5.0...",
        details: { export_format: "csv", record_count: 1500 },
        compliance_tags: ["GDPR", "SOC2"],
      },
      {
        id: "audit-3",
        timestamp: "2024-01-15T12:00:00Z",
        user_id: "user-789",
        user_name: "bob.wilson@company.com",
        action: "failed_login",
        resource_type: "auth",
        resource_id: "login-attempt",
        result: "failure",
        ip_address: "203.0.113.15",
        user_agent: "curl/7.68.0",
        details: { reason: "invalid_credentials", attempts: 3 },
        compliance_tags: ["ISO27001", "PCI_DSS"],
      },
      {
        id: "audit-4",
        timestamp: "2024-01-15T14:30:00Z",
        user_id: "user-123",
        user_name: "john.doe@company.com",
        action: "permission_change",
        resource_type: "permission",
        resource_id: "perm-456",
        result: "success",
        ip_address: "192.168.1.100",
        user_agent: "Mozilla/5.0...",
        details: { permission: "data_export", granted: true },
        compliance_tags: ["SOC2"],
      },
      {
        id: "audit-5",
        timestamp: "2024-01-15T15:45:00Z",
        user_id: "user-999",
        user_name: "unauthorized.user@external.com",
        action: "access_denied",
        resource_type: "flow",
        resource_id: "sensitive-flow",
        result: "denied",
        ip_address: "198.51.100.25",
        user_agent: "PostmanRuntime/7.32.2",
        details: { reason: "insufficient_privileges", required_role: "admin" },
        compliance_tags: ["ISO27001", "SOC2"],
      },
    ];

    // Apply filters
    let filteredData = mockEntries;

    if (filters.user_id) {
      filteredData = filteredData.filter((entry) =>
        entry.user_name.toLowerCase().includes(filters.user_id!.toLowerCase()),
      );
    }

    if (filters.action) {
      filteredData = filteredData.filter(
        (entry) => entry.action === filters.action,
      );
    }

    if (filters.resource_type) {
      filteredData = filteredData.filter(
        (entry) => entry.resource_type === filters.resource_type,
      );
    }

    if (filters.result) {
      filteredData = filteredData.filter(
        (entry) => entry.result === filters.result,
      );
    }

    if (filters.compliance_tag) {
      filteredData = filteredData.filter((entry) =>
        entry.compliance_tags.includes(filters.compliance_tag!),
      );
    }

    if (filters.start_date) {
      filteredData = filteredData.filter(
        (entry) => new Date(entry.timestamp) >= new Date(filters.start_date!),
      );
    }

    if (filters.end_date) {
      filteredData = filteredData.filter(
        (entry) => new Date(entry.timestamp) <= new Date(filters.end_date!),
      );
    }

    // Apply search term
    if (searchTerm) {
      filteredData = filteredData.filter(
        (entry) =>
          entry.user_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          entry.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
          entry.resource_type.toLowerCase().includes(searchTerm.toLowerCase()),
      );
    }

    setAuditData(filteredData);
  };

  const handleTemplateChange = (templateId: string) => {
    setSelectedTemplate(templateId);
    const template = complianceTemplates.find((t) => t.id === templateId);

    if (template) {
      // Apply template filters
      setFilters(template.filters);

      // Set required fields for custom selection
      if (template.id === "custom") {
        setCustomFields([]);
      } else {
        setCustomFields(template.required_fields);
      }
    }
  };

  const handleFilterChange = (key: keyof FilterState, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
    }));
  };

  const handleEntrySelection = (entryId: string) => {
    setSelectedEntries((prev) =>
      prev.includes(entryId)
        ? prev.filter((id) => id !== entryId)
        : [...prev, entryId],
    );
  };

  const handleSelectAll = () => {
    setSelectedEntries(auditData.map((entry) => entry.id));
  };

  const handleSelectNone = () => {
    setSelectedEntries([]);
  };

  const generateReport = async (format: "csv" | "json" | "pdf") => {
    setIsGenerating(true);

    try {
      const selectedData =
        selectedEntries.length > 0
          ? auditData.filter((entry) => selectedEntries.includes(entry.id))
          : auditData;

      const template = complianceTemplates.find(
        (t) => t.id === selectedTemplate,
      );
      const reportData = {
        metadata: {
          generated_at: new Date().toISOString(),
          template: template?.name || "Custom Report",
          total_entries: selectedData.length,
          filters_applied: filters,
          fields_included:
            customFields.length > 0
              ? customFields
              : Object.keys(selectedData[0] || {}),
          compliance_framework: template?.id || "custom",
        },
        entries: selectedData.map((entry) => {
          if (customFields.length > 0) {
            // Return only selected fields
            const filteredEntry: any = {};
            customFields.forEach((field) => {
              if (field in entry) {
                filteredEntry[field] = (entry as any)[field];
              }
            });
            return filteredEntry;
          }
          return entry;
        }),
      };

      // Simulate API call
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Generate and download file
      downloadReport(reportData, format);

      console.log("✅ Report generated successfully:", reportData);
    } catch (error) {
      console.error("❌ Failed to generate report:", error);
    } finally {
      setIsGenerating(false);
    }
  };

  const downloadReport = (data: any, format: "csv" | "json" | "pdf") => {
    let content = "";
    let mimeType = "";
    let filename = "";

    const timestamp = new Date().toISOString().split("T")[0];
    const templateName =
      complianceTemplates.find((t) => t.id === selectedTemplate)?.name ||
      "Custom";

    switch (format) {
      case "csv":
        content = convertToCSV(data.entries);
        mimeType = "text/csv";
        filename = `${templateName.replace(/\s+/g, "_")}_${timestamp}.csv`;
        break;
      case "json":
        content = JSON.stringify(data, null, 2);
        mimeType = "application/json";
        filename = `${templateName.replace(/\s+/g, "_")}_${timestamp}.json`;
        break;
      case "pdf":
        // For PDF, we'd typically use a PDF generation library
        content = JSON.stringify(data, null, 2); // Fallback to JSON
        mimeType = "application/json";
        filename = `${templateName.replace(/\s+/g, "_")}_${timestamp}_pdf_placeholder.json`;
        break;
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const convertToCSV = (entries: AuditEntry[]) => {
    if (entries.length === 0) return "";

    const fields =
      customFields.length > 0 ? customFields : Object.keys(entries[0]);
    const headers = fields.join(",");

    const rows = entries.map((entry) => {
      return fields
        .map((field) => {
          const value = (entry as any)[field];
          // Handle complex objects
          if (typeof value === "object") {
            return `"${JSON.stringify(value).replace(/"/g, '""')}"`;
          }
          // Escape CSV values
          return `"${String(value).replace(/"/g, '""')}"`;
        })
        .join(",");
    });

    return [headers, ...rows].join("\n");
  };

  const getComplianceBadgeColor = (tags: string[]) => {
    if (tags.includes("PCI_DSS")) return "bg-red-100 text-red-800";
    if (tags.includes("GDPR")) return "bg-blue-100 text-blue-800";
    if (tags.includes("SOC2")) return "bg-green-100 text-green-800";
    if (tags.includes("ISO27001")) return "bg-purple-100 text-purple-800";
    return "bg-gray-100 text-gray-800";
  };

  const getResultBadgeVariant = (result: string) => {
    switch (result) {
      case "success":
        return "default";
      case "failure":
        return "destructive";
      case "denied":
        return "secondary";
      default:
        return "outline";
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold flex items-center space-x-2">
            <IconComponent name="FileText" className="h-5 w-5" />
            <span>Compliance Report Generator</span>
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Generate audit reports and export compliance data
          </p>
        </div>
      </div>

      {/* Template Selection */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <IconComponent name="Template" className="h-5 w-5" />
            <span>Compliance Templates</span>
          </CardTitle>
          <CardDescription>
            Select a compliance framework template or create a custom report
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {complianceTemplates.map((template) => (
              <Card
                key={template.id}
                className={`cursor-pointer transition-colors ${
                  selectedTemplate === template.id
                    ? "border-blue-500 bg-blue-50"
                    : "hover:bg-gray-50"
                }`}
                onClick={() => handleTemplateChange(template.id)}
              >
                <CardContent className="p-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <Checkbox
                      checked={selectedTemplate === template.id}
                      onChange={() => handleTemplateChange(template.id)}
                    />
                    <h3 className="font-medium">{template.name}</h3>
                  </div>
                  <p className="text-sm text-gray-600 mb-3">
                    {template.description}
                  </p>
                  <div className="flex items-center justify-between text-xs">
                    <Badge variant="outline">
                      {template.format.toUpperCase()}
                    </Badge>
                    <span className="text-gray-500">
                      {template.required_fields.length} fields
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <IconComponent name="Filter" className="h-5 w-5" />
            <span>Report Filters</span>
          </CardTitle>
          <CardDescription>
            Filter audit entries by user, action, timeframe, and compliance
            requirements
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">User</label>
              <Input
                placeholder="Search by user email..."
                value={filters.user_id || ""}
                onChange={(e) => handleFilterChange("user_id", e.target.value)}
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Action</label>
              <select
                value={filters.action || ""}
                onChange={(e) => handleFilterChange("action", e.target.value)}
                className="w-full border rounded px-3 py-2"
              >
                <option value="">All actions</option>
                <option value="role_assignment">Role Assignment</option>
                <option value="permission_change">Permission Change</option>
                <option value="data_export">Data Export</option>
                <option value="failed_login">Failed Login</option>
                <option value="access_denied">Access Denied</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">
                Resource Type
              </label>
              <select
                value={filters.resource_type || ""}
                onChange={(e) =>
                  handleFilterChange("resource_type", e.target.value)
                }
                className="w-full border rounded px-3 py-2"
              >
                <option value="">All resources</option>
                <option value="role">Role</option>
                <option value="permission">Permission</option>
                <option value="user_data">User Data</option>
                <option value="flow">Flow</option>
                <option value="auth">Authentication</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Result</label>
              <select
                value={filters.result || ""}
                onChange={(e) => handleFilterChange("result", e.target.value)}
                className="w-full border rounded px-3 py-2"
              >
                <option value="">All results</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
                <option value="denied">Denied</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">
                Start Date
              </label>
              <Input
                type="date"
                value={filters.start_date || ""}
                onChange={(e) =>
                  handleFilterChange("start_date", e.target.value)
                }
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">End Date</label>
              <Input
                type="date"
                value={filters.end_date || ""}
                onChange={(e) => handleFilterChange("end_date", e.target.value)}
              />
            </div>
          </div>

          <div className="flex space-x-2">
            <Input
              placeholder="Search audit entries..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="flex-1"
            />
            <Button onClick={() => setFilters({})} variant="outline">
              Clear Filters
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Audit Data Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <IconComponent name="List" className="h-5 w-5" />
              <span>Audit Entries</span>
              <Badge variant="outline">{auditData.length} entries</Badge>
            </div>

            <div className="flex space-x-2">
              <Button size="sm" variant="outline" onClick={handleSelectAll}>
                Select All
              </Button>
              <Button size="sm" variant="outline" onClick={handleSelectNone}>
                Clear Selection
              </Button>
            </div>
          </CardTitle>
          <CardDescription>
            Select entries to include in your compliance report
            {selectedEntries.length > 0 &&
              ` (${selectedEntries.length} selected)`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!isAdmin ? (
            <div className="text-center py-8 text-gray-500">
              Please authenticate to view audit data
            </div>
          ) : auditData.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              No audit entries found matching current filters
            </div>
          ) : (
            <div className="border rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-12">
                      <Checkbox
                        checked={
                          selectedEntries.length === auditData.length &&
                          auditData.length > 0
                        }
                        onChange={
                          selectedEntries.length === auditData.length
                            ? handleSelectNone
                            : handleSelectAll
                        }
                      />
                    </TableHead>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Resource</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead>Compliance</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {auditData.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell>
                        <Checkbox
                          checked={selectedEntries.includes(entry.id)}
                          onChange={() => handleEntrySelection(entry.id)}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {new Date(entry.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell className="font-medium">
                        {entry.user_name}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {entry.action.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm">
                          {entry.resource_type}
                          {entry.resource_id && (
                            <span className="text-gray-500 ml-1">
                              ({entry.resource_id})
                            </span>
                          )}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getResultBadgeVariant(entry.result)}>
                          {entry.result}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {entry.compliance_tags.map((tag) => (
                            <Badge
                              key={tag}
                              className={`text-xs ${getComplianceBadgeColor([tag])}`}
                            >
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Export Controls */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <IconComponent name="Download" className="h-5 w-5" />
            <span>Export Report</span>
          </CardTitle>
          <CardDescription>
            Generate and download compliance reports in various formats
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {selectedTemplate && (
            <div className="p-3 border rounded-lg bg-gray-50">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-medium">
                    {
                      complianceTemplates.find((t) => t.id === selectedTemplate)
                        ?.name
                    }
                  </h4>
                  <p className="text-sm text-gray-600">
                    {selectedEntries.length > 0
                      ? selectedEntries.length
                      : auditData.length}{" "}
                    entries selected
                  </p>
                </div>
                <Badge variant="outline">
                  {complianceTemplates
                    .find((t) => t.id === selectedTemplate)
                    ?.format.toUpperCase()}
                </Badge>
              </div>
            </div>
          )}

          <div className="flex space-x-2">
            <Button
              onClick={() => generateReport("csv")}
              disabled={
                !selectedTemplate || auditData.length === 0 || isGenerating
              }
              className="flex-1"
            >
              <IconComponent name="FileSpreadsheet" className="h-4 w-4 mr-2" />
              {isGenerating ? "Generating..." : "Export CSV"}
            </Button>

            <Button
              onClick={() => generateReport("json")}
              disabled={
                !selectedTemplate || auditData.length === 0 || isGenerating
              }
              variant="outline"
              className="flex-1"
            >
              <IconComponent name="FileCode" className="h-4 w-4 mr-2" />
              {isGenerating ? "Generating..." : "Export JSON"}
            </Button>

            <Button
              onClick={() => generateReport("pdf")}
              disabled={
                !selectedTemplate || auditData.length === 0 || isGenerating
              }
              variant="outline"
              className="flex-1"
            >
              <IconComponent name="FileText" className="h-4 w-4 mr-2" />
              {isGenerating ? "Generating..." : "Export PDF"}
            </Button>
          </div>

          {!selectedTemplate && (
            <div className="text-center py-4 text-gray-500 text-sm">
              Please select a compliance template to enable export
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
