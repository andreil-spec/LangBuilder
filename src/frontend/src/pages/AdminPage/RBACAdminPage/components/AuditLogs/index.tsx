// Audit Logs Component - Real API Implementation
// Implements audit logging with real authentication and API calls

import { useEffect, useMemo, useState } from "react";
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
import { DatePickerWithRange } from "@/components/ui/date-range-picker";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ActorType,
  AuditEventType,
  AuditLog,
  AuditOutcome,
  formatActorType,
  formatEventType,
  getEventTypeColor,
  getOutcomeColor,
  useExportAuditLogs,
  useGetAuditLogs,
} from "@/controllers/API/queries/rbac/use-audit-logs";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";

interface ComplianceReportDialogProps {
  isOpen: boolean;
  onClose: () => void;
  isAdmin: boolean;
  onAuthRequired: () => void;
}

function ComplianceReportDialog({
  isOpen,
  onClose,
  isAdmin,
  onAuthRequired,
}: ComplianceReportDialogProps) {
  const [reportType, setReportType] = useState<string>("user_access");
  const [dateRange, setDateRange] = useState<{
    from: Date | undefined;
    to: Date | undefined;
  }>({
    from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
    to: new Date(),
  });
  const [format, setFormat] = useState<"csv" | "json" | "pdf">("csv");

  const { mutate: exportAuditLogs, isPending: isExporting } =
    useExportAuditLogs({
      onSuccess: (data) => {
        console.log("✅ Audit logs export initiated:", data);
        alert(
          `✅ Export initiated successfully! Download URL: ${data.download_url}`,
        );
        onClose();
      },
      onError: (error) => {
        console.error("❌ Failed to export audit logs:", error);
        alert(
          `❌ Failed to export audit logs: ${error.message || "Unknown error"}`,
        );
      },
    });

  const handleGenerateReport = () => {
    if (!isAdmin) {
      onAuthRequired();
      return;
    }

    const exportData = {
      // workspace_id is now optional - removed hardcoded value
      format: format,
      start_date: dateRange.from?.toISOString(),
      end_date: dateRange.to?.toISOString(),
      include_metadata: true,
      include_sensitive: false,
    };

    exportAuditLogs(exportData);
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Generate Compliance Report</DialogTitle>
          <DialogDescription>
            Export audit logs and access reports for compliance review and
            analysis.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          <div>
            <Label>Report Type</Label>
            <Select value={reportType} onValueChange={setReportType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="user_access">User Access Report</SelectItem>
                <SelectItem value="role_changes">
                  Role Changes Report
                </SelectItem>
                <SelectItem value="authentication">
                  Authentication Events
                </SelectItem>
                <SelectItem value="permission_grants">
                  Permission Grants
                </SelectItem>
                <SelectItem value="service_account_activity">
                  Service Account Activity
                </SelectItem>
                <SelectItem value="failed_access_attempts">
                  Failed Access Attempts
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label>Date Range</Label>
            <DatePickerWithRange date={dateRange} onDateChange={setDateRange} />
          </div>

          <div>
            <Label>Export Format</Label>
            <Select value={format} onValueChange={setFormat}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="csv">CSV</SelectItem>
                <SelectItem value="json">JSON</SelectItem>
                <SelectItem value="xlsx">Excel (XLSX)</SelectItem>
                <SelectItem value="pdf">PDF Report</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="bg-blue-50 p-4 rounded-lg">
            <div className="flex items-start space-x-2">
              <IconComponent
                name="Info"
                className="h-4 w-4 text-blue-600 mt-0.5"
              />
              <div className="text-sm">
                <div className="font-medium text-blue-900">
                  Compliance Features
                </div>
                <div className="text-blue-700 mt-1">
                  Reports include all required audit fields for SOC 2 / ISO
                  27001 compliance. Personal identifiers are masked unless
                  accessed by Admins or Auditors.
                </div>
              </div>
            </div>
          </div>

          <div className="flex justify-end space-x-2">
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              onClick={handleGenerateReport}
              disabled={isExporting || !dateRange.from || !dateRange.to}
            >
              <IconComponent name="Download" className="h-4 w-4 mr-2" />
              {isExporting ? "Generating..." : "Generate Report"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function AuditLogTable({
  logs,
  isLoading,
  isAdmin,
  onAuthRequired,
  onRefresh,
}: {
  logs: AuditLog[];
  isLoading: boolean;
  isAdmin: boolean;
  onAuthRequired: () => void;
  onRefresh: () => void;
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterEventType, setFilterEventType] = useState<string>("all");
  const [filterActorType, setFilterActorType] = useState<string>("all");
  const [filterOutcome, setFilterOutcome] = useState<string>("all");
  const [filterResourceType, setFilterResourceType] = useState<string>("all");
  const [filterDateRange, setFilterDateRange] = useState<{
    from: Date | undefined;
    to: Date | undefined;
  }>({ from: undefined, to: undefined });

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchesSearch =
        log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.actor_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        false ||
        log.actor_email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        false ||
        JSON.stringify(log.metadata || {})
          .toLowerCase()
          .includes(searchTerm.toLowerCase());

      const matchesEventType =
        filterEventType === "all" || log.event_type === filterEventType;
      const matchesActorType =
        filterActorType === "all" || log.actor_type === filterActorType;
      const matchesOutcome =
        filterOutcome === "all" || log.outcome === filterOutcome;
      const matchesResourceType =
        filterResourceType === "all" ||
        log.resource_type === filterResourceType;

      const logDate = new Date(log.timestamp);
      const matchesDateRange =
        (!filterDateRange.from || logDate >= filterDateRange.from) &&
        (!filterDateRange.to || logDate <= filterDateRange.to);

      return (
        matchesSearch &&
        matchesEventType &&
        matchesActorType &&
        matchesOutcome &&
        matchesResourceType &&
        matchesDateRange
      );
    });
  }, [
    logs,
    searchTerm,
    filterEventType,
    filterActorType,
    filterOutcome,
    filterResourceType,
    filterDateRange,
  ]);

  const getEventIcon = (eventType: AuditEventType) => {
    switch (eventType) {
      case AuditEventType.ROLE_ASSIGNED:
        return "UserPlus";
      case AuditEventType.ROLE_REMOVED:
        return "UserMinus";
      case AuditEventType.WORKSPACE_CREATED:
        return "Building";
      case AuditEventType.LOGIN:
      case AuditEventType.LOGOUT:
        return "LogIn";
      case AuditEventType.LOGIN_FAILED:
        return "AlertCircle";
      case AuditEventType.PERMISSION_GRANTED:
        return "Shield";
      case AuditEventType.PERMISSION_REVOKED:
        return "ShieldOff";
      case AuditEventType.RESOURCE_CREATED:
        return "Plus";
      case AuditEventType.RESOURCE_DELETED:
        return "Trash2";
      case AuditEventType.SECURITY_ALERT:
        return "AlertTriangle";
      default:
        return "Activity";
    }
  };

  const uniqueEventTypes = [...new Set(logs.map((log) => log.event_type))];
  const uniqueActorTypes = [...new Set(logs.map((log) => log.actor_type))];
  const uniqueOutcomes = [...new Set(logs.map((log) => log.outcome))];
  const uniqueResourceTypes = [
    ...new Set(logs.map((log) => log.resource_type).filter(Boolean)),
  ];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Input
          placeholder="Search logs..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          disabled={!isAdmin}
        />
        <Select value={filterEventType} onValueChange={setFilterEventType}>
          <SelectTrigger>
            <SelectValue placeholder="Event Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Event Types</SelectItem>
            {uniqueEventTypes.map((eventType) => (
              <SelectItem key={eventType} value={eventType}>
                {formatEventType(eventType)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filterActorType} onValueChange={setFilterActorType}>
          <SelectTrigger>
            <SelectValue placeholder="Actor Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Actor Types</SelectItem>
            {uniqueActorTypes.map((actorType) => (
              <SelectItem key={actorType} value={actorType}>
                {formatActorType(actorType)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filterOutcome} onValueChange={setFilterOutcome}>
          <SelectTrigger>
            <SelectValue placeholder="Outcome" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Outcomes</SelectItem>
            {uniqueOutcomes.map((outcome) => (
              <SelectItem key={outcome} value={outcome}>
                {outcome.charAt(0).toUpperCase() + outcome.slice(1)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={filterResourceType}
          onValueChange={setFilterResourceType}
        >
          <SelectTrigger>
            <SelectValue placeholder="Resource" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Resources</SelectItem>
            {uniqueResourceTypes.map((type) => (
              <SelectItem key={type} value={type}>
                {type}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <DatePickerWithRange
          date={filterDateRange}
          onDateChange={setFilterDateRange}
        />
      </div>

      {/* Results count */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {isLoading
            ? "Loading..."
            : `Showing ${filteredLogs.length} of ${logs.length} audit entries`}
        </div>
        <div className="flex items-center space-x-2">
          {(filterDateRange.from ||
            filterDateRange.to ||
            searchTerm ||
            filterEventType !== "all" ||
            filterActorType !== "all" ||
            filterOutcome !== "all" ||
            filterResourceType !== "all") && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setSearchTerm("");
                setFilterEventType("all");
                setFilterActorType("all");
                setFilterOutcome("all");
                setFilterResourceType("all");
                setFilterDateRange({ from: undefined, to: undefined });
              }}
            >
              Clear Filters
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={onRefresh}
            disabled={!isAdmin || isLoading}
          >
            <IconComponent name="RefreshCw" className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Audit Log Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Details</TableHead>
                <TableHead>Source</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <div className="flex items-center justify-center">
                      <IconComponent
                        name="Loader2"
                        className="h-4 w-4 animate-spin mr-2"
                      />
                      Loading audit logs...
                    </div>
                  </TableCell>
                </TableRow>
              ) : !isAdmin ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <div className="text-gray-500">
                      Please authenticate to view audit logs
                      <Button
                        variant="link"
                        onClick={onAuthRequired}
                        className="ml-2"
                      >
                        Sign In
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ) : filteredLogs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <div className="text-gray-500">
                      No audit logs found matching the current filters
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                filteredLogs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>
                      <div className="text-sm">
                        {new Date(log.timestamp).toLocaleDateString()}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div>
                        <div className="font-medium">
                          {log.actor_name || log.actor_id || "Unknown"}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {log.actor_email || formatActorType(log.actor_type)}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <Badge
                          className={`text-${getEventTypeColor(log.event_type)}-700 bg-${getEventTypeColor(log.event_type)}-100 border-0`}
                        >
                          <IconComponent
                            name={getEventIcon(log.event_type)}
                            className="h-3 w-3 mr-1"
                          />
                          {formatEventType(log.event_type)}
                        </Badge>
                        <Badge
                          variant="outline"
                          className={`text-${getOutcomeColor(log.outcome)}-700 border-${getOutcomeColor(log.outcome)}-300`}
                        >
                          {log.outcome.toUpperCase()}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div>
                        <div className="font-medium capitalize">
                          {log.resource_type || "N/A"}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {log.resource_name || log.resource_id || "N/A"}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="max-w-xs">
                        {log.metadata &&
                          Object.keys(log.metadata).length > 0 && (
                            <div className="text-sm">
                              {Object.entries(log.metadata)
                                .slice(0, 2)
                                .map(([key, value]) => (
                                  <div key={key} className="truncate">
                                    <span className="font-medium">{key}:</span>{" "}
                                    {String(value)}
                                  </div>
                                ))}
                              {Object.keys(log.metadata).length > 2 && (
                                <div className="text-xs text-muted-foreground">
                                  +{Object.keys(log.metadata).length - 2} more
                                </div>
                              )}
                            </div>
                          )}
                        {log.error_message && (
                          <div className="text-sm text-red-600">
                            Error: {log.error_message}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-xs text-muted-foreground">
                        <div>{log.ip_address || "N/A"}</div>
                        {log.user_agent && (
                          <div
                            className="truncate max-w-32"
                            title={log.user_agent}
                          >
                            {log.user_agent.split(" ")[0]}
                          </div>
                        )}
                        {log.location && (
                          <div className="text-xs">{log.location}</div>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

export default function AuditLogs() {
  const [isReportDialogOpen, setIsReportDialogOpen] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // API hooks
  const {
    mutate: fetchAuditLogs,
    data: auditLogsData,
    isPending: isLoading,
    error,
  } = useGetAuditLogs({
    onSuccess: (data) => {
      console.log("✅ Audit logs fetched successfully:", data);
    },
    onError: (error) => {
      console.error("❌ Failed to fetch audit logs:", error);
    },
  });

  // Authentication helper
  const requireAuth = (action: string, callback: () => void) => {
    if (!isAdmin) {
      console.log("❌ Not authenticated, showing modal for action:", action);
      setShowAuthModal(true);
    } else {
      console.log("✅ Authenticated, executing action:", action);
      callback();
    }
  };

  const handleAuthSuccess = () => {
    console.log("🎉 Authentication successful, fetching audit logs");
    fetchAuditLogs({
      // workspace_id is now optional - removed hardcoded value
      search: searchTerm,
      page: 1,
      page_size: 100,
    });
  };

  const handleRefresh = () => {
    requireAuth("refresh-audit-logs", () => {
      fetchAuditLogs({
        // workspace_id is now optional - removed hardcoded value
        search: searchTerm,
        page: 1,
        page_size: 100,
      });
    });
  };

  // Fetch data when authenticated
  useEffect(() => {
    if (isAdmin) {
      fetchAuditLogs({
        // workspace_id is now optional - removed hardcoded value
        search: searchTerm,
        page: 1,
        page_size: 100,
      });
    }
  }, [isAdmin]);

  // Debug authentication state changes
  useEffect(() => {
    console.log("🔄 AuditLogs: Auth state changed:", {
      isAdmin,
    });
  }, [isAdmin]);

  // Get logs from API response
  const logs = auditLogsData?.audit_logs || [];

  // Calculate statistics
  const last24Hours = logs.filter(
    (log) =>
      new Date(log.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000),
  ).length;

  const roleChanges = logs.filter(
    (log) =>
      log.event_type === AuditEventType.ROLE_ASSIGNED ||
      log.event_type === AuditEventType.ROLE_REMOVED ||
      log.event_type === AuditEventType.PERMISSION_GRANTED ||
      log.event_type === AuditEventType.PERMISSION_REVOKED,
  ).length;

  const authEvents = logs.filter(
    (log) =>
      log.event_type === AuditEventType.LOGIN ||
      log.event_type === AuditEventType.LOGOUT ||
      log.event_type === AuditEventType.LOGIN_FAILED,
  ).length;

  const uniqueActors = new Set(logs.map((log) => log.actor_id).filter(Boolean))
    .size;

  return (
    <div className="h-full flex flex-col p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Audit Logs</h2>
          <p className="text-muted-foreground">
            Comprehensive audit trail for all RBAC changes and system access
            events
          </p>
        </div>
        <div className="flex items-center space-x-2">

          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={!isAdmin || isLoading}
          >
            <IconComponent name="RefreshCw" className="h-4 w-4 mr-2" />
            {isLoading ? "Loading..." : "Refresh"}
          </Button>
          <Dialog
            open={isReportDialogOpen}
            onOpenChange={setIsReportDialogOpen}
          >
            <DialogTrigger asChild>
              <Button size="sm" disabled={!isAdmin}>
                <IconComponent name="Download" className="h-4 w-4 mr-2" />
                Export Report
              </Button>
            </DialogTrigger>
            <ComplianceReportDialog
              isOpen={isReportDialogOpen}
              onClose={() => setIsReportDialogOpen(false)}
              isAdmin={isAdmin}
              onAuthRequired={() => setShowAuthModal(true)}
            />
          </Dialog>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error loading audit logs: {error.message}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">
              Recent Activity
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "—" : last24Hours}
            </div>
            <p className="text-xs text-muted-foreground">Events in last 24h</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Role Changes</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "—" : roleChanges}
            </div>
            <p className="text-xs text-muted-foreground">
              Permission modifications
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Auth Events</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "—" : authEvents}
            </div>
            <p className="text-xs text-muted-foreground">
              Authentication activities
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Active Actors</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "—" : uniqueActors}
            </div>
            <p className="text-xs text-muted-foreground">Unique actors</p>
          </CardContent>
        </Card>
      </div>

      {/* Compliance Notice */}
      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="p-4">
          <div className="flex items-start space-x-3">
            <IconComponent
              name="Shield"
              className="h-5 w-5 text-blue-600 mt-0.5"
            />
            <div>
              <div className="font-medium text-blue-900">Compliance Ready</div>
              <div className="text-sm text-blue-700 mt-1">
                All audit logs are immutable and include required fields for SOC
                2 / ISO 27001 compliance. Logs are automatically retained
                according to your organization's retention policy.
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="flex-1 overflow-hidden">
        <AuditLogTable
          logs={logs}
          isLoading={isLoading}
          isAdmin={isAdmin}
          onAuthRequired={() => setShowAuthModal(true)}
          onRefresh={handleRefresh}
        />
      </div>

      {/* Authentication Modal */}
      <AuthenticationModal
        open={showAuthModal}
        onOpenChange={setShowAuthModal}
        onSuccess={handleAuthSuccess}
      />
    </div>
  );
}
