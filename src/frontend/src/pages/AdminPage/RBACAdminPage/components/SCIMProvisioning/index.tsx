// SCIM Provisioning Dashboard - Enterprise Integration Phase 2.2
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useGetAutoLogin } from "@/controllers/API/queries/auth";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";

// Types for SCIM Provisioning
interface SCIMEndpoint {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  last_sync: string;
  sync_status: "idle" | "syncing" | "success" | "error";
  sync_progress?: number;
  total_users: number;
  total_groups: number;
  created_at: string;
}

interface SyncOperation {
  id: string;
  type: "full_sync" | "incremental_sync" | "user_sync" | "group_sync";
  status: "pending" | "running" | "completed" | "failed";
  started_at: string;
  completed_at?: string;
  progress: number;
  total_operations: number;
  completed_operations: number;
  errors: string[];
  summary: {
    created: number;
    updated: number;
    deleted: number;
    skipped: number;
  };
}

interface ProvisioningRule {
  id: string;
  name: string;
  condition: string;
  action: "create" | "update" | "delete" | "ignore";
  target_attribute: string;
  value_mapping: Record<string, string>;
  enabled: boolean;
  priority: number;
}

interface ConflictResolution {
  id: string;
  user_id: string;
  conflict_type:
    | "duplicate_email"
    | "attribute_mismatch"
    | "permission_conflict";
  description: string;
  suggested_action: string;
  created_at: string;
  status: "pending" | "resolved" | "ignored";
}

export default function SCIMProvisioning() {
  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // Component state
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [isSyncing, setIsSyncing] = useState(false);

  // Mock data for demonstration
  const [scimEndpoints, setSCIMEndpoints] = useState<SCIMEndpoint[]>([
    {
      id: "1",
      name: "Azure AD SCIM",
      url: "https://graph.microsoft.com/v1.0/",
      enabled: true,
      last_sync: "2024-01-22T10:30:00Z",
      sync_status: "success",
      total_users: 245,
      total_groups: 12,
      created_at: "2024-01-15T08:00:00Z",
    },
    {
      id: "2",
      name: "Okta SCIM",
      url: "https://dev-123456.okta.com/api/v1/",
      enabled: false,
      last_sync: "2024-01-20T15:45:00Z",
      sync_status: "error",
      total_users: 89,
      total_groups: 7,
      created_at: "2024-01-10T12:00:00Z",
    },
  ]);

  const [syncOperations, setSyncOperations] = useState<SyncOperation[]>([
    {
      id: "1",
      type: "full_sync",
      status: "completed",
      started_at: "2024-01-22T10:30:00Z",
      completed_at: "2024-01-22T10:35:00Z",
      progress: 100,
      total_operations: 245,
      completed_operations: 245,
      errors: [],
      summary: {
        created: 12,
        updated: 230,
        deleted: 3,
        skipped: 0,
      },
    },
    {
      id: "2",
      type: "incremental_sync",
      status: "failed",
      started_at: "2024-01-21T14:00:00Z",
      completed_at: "2024-01-21T14:02:00Z",
      progress: 25,
      total_operations: 89,
      completed_operations: 22,
      errors: ["Connection timeout", "Invalid user attribute"],
      summary: {
        created: 0,
        updated: 22,
        deleted: 0,
        skipped: 67,
      },
    },
  ]);

  const [provisioningRules, setProvisioningRules] = useState<
    ProvisioningRule[]
  >([
    {
      id: "1",
      name: "Auto-create Admin Users",
      condition: "user.groups contains 'Langflow-Admins'",
      action: "create",
      target_attribute: "role",
      value_mapping: { "Langflow-Admins": "admin" },
      enabled: true,
      priority: 1,
    },
    {
      id: "2",
      name: "Map Department to Workspace",
      condition: "user.department exists",
      action: "update",
      target_attribute: "workspace",
      value_mapping: {
        Engineering: "engineering-workspace",
        Marketing: "marketing-workspace",
        Sales: "sales-workspace",
      },
      enabled: true,
      priority: 2,
    },
  ]);

  const [conflicts, setConflicts] = useState<ConflictResolution[]>([
    {
      id: "1",
      user_id: "user-123",
      conflict_type: "duplicate_email",
      description: "User with email john.doe@company.com already exists",
      suggested_action: "Merge with existing user or update email",
      created_at: "2024-01-22T09:15:00Z",
      status: "pending",
    },
    {
      id: "2",
      user_id: "user-456",
      conflict_type: "permission_conflict",
      description:
        "User permissions differ between SCIM and current assignments",
      suggested_action: "Update permissions to match SCIM data",
      created_at: "2024-01-21T16:30:00Z",
      status: "pending",
    },
  ]);

  // Auto-login query
  const { data: autoLoginData, isSuccess: autoLoginSuccess } = useGetAutoLogin({
    retry: 3,
    retryDelay: 1000,
  });

  const requireAuth = (action: string, callback: () => void) => {
    if (!isAdmin) {
      setShowAuthModal(true);
    } else {
      callback();
    }
  };

  const handleManualSync = (type: SyncOperation["type"]) => {
    requireAuth("manual-scim-sync", () => {
      setIsSyncing(true);

      // Create new sync operation
      const newOperation: SyncOperation = {
        id: Date.now().toString(),
        type,
        status: "running",
        started_at: new Date().toISOString(),
        progress: 0,
        total_operations: 100,
        completed_operations: 0,
        errors: [],
        summary: {
          created: 0,
          updated: 0,
          deleted: 0,
          skipped: 0,
        },
      };

      setSyncOperations((prev) => [newOperation, ...prev]);

      // Simulate sync progress
      let progress = 0;
      const interval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress >= 100) {
          progress = 100;
          clearInterval(interval);
          setIsSyncing(false);

          // Update operation as completed
          setSyncOperations((prev) =>
            prev.map((op) =>
              op.id === newOperation.id
                ? {
                    ...op,
                    status: "completed",
                    progress: 100,
                    completed_at: new Date().toISOString(),
                    completed_operations: op.total_operations,
                    summary: {
                      created: Math.floor(Math.random() * 10),
                      updated: Math.floor(Math.random() * 80) + 20,
                      deleted: Math.floor(Math.random() * 5),
                      skipped: Math.floor(Math.random() * 10),
                    },
                  }
                : op,
            ),
          );
        } else {
          setSyncOperations((prev) =>
            prev.map((op) =>
              op.id === newOperation.id
                ? {
                    ...op,
                    progress: Math.floor(progress),
                    completed_operations: Math.floor(
                      (progress / 100) * op.total_operations,
                    ),
                  }
                : op,
            ),
          );
        }
      }, 500);
    });
  };

  const handleResolveConflict = (
    conflictId: string,
    action: "resolve" | "ignore",
  ) => {
    requireAuth("resolve-scim-conflict", () => {
      setConflicts((prev) =>
        prev.map((conflict) =>
          conflict.id === conflictId
            ? {
                ...conflict,
                status: action === "resolve" ? "resolved" : "ignored",
              }
            : conflict,
        ),
      );
    });
  };

  const handleToggleRule = (ruleId: string) => {
    requireAuth("toggle-provisioning-rule", () => {
      setProvisioningRules((prev) =>
        prev.map((rule) =>
          rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule,
        ),
      );
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "success":
      case "completed":
        return "text-green-600 bg-green-50";
      case "error":
      case "failed":
        return "text-red-600 bg-red-50";
      case "syncing":
      case "running":
        return "text-blue-600 bg-blue-50";
      default:
        return "text-gray-600 bg-gray-50";
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold flex items-center space-x-2">
            <IconComponent name="RefreshCw" className="h-5 w-5" />
            <span>SCIM Provisioning</span>
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Monitor and manage automated user provisioning from identity
            providers
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <Button
            onClick={() => handleManualSync("full_sync")}
            disabled={!isAdmin || isSyncing}
          >
            {isSyncing ? (
              <>
                <IconComponent
                  name="Loader2"
                  className="h-4 w-4 mr-2 animate-spin"
                />
                Syncing...
              </>
            ) : (
              <>
                <IconComponent name="RefreshCw" className="h-4 w-4 mr-2" />
                Manual Sync
              </>
            )}
          </Button>
        </div>
      </div>

      <Tabs
        value={activeTab}
        onValueChange={setActiveTab}
        className="space-y-4"
      >
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">
            <IconComponent name="BarChart3" className="h-4 w-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="operations">
            <IconComponent name="Activity" className="h-4 w-4 mr-2" />
            Sync Operations
          </TabsTrigger>
          <TabsTrigger value="rules">
            <IconComponent name="Settings" className="h-4 w-4 mr-2" />
            Provisioning Rules
          </TabsTrigger>
          <TabsTrigger value="conflicts">
            <IconComponent name="AlertTriangle" className="h-4 w-4 mr-2" />
            Conflicts ({conflicts.filter((c) => c.status === "pending").length})
          </TabsTrigger>
        </TabsList>

        {/* Overview */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Endpoint Status Cards */}
            {scimEndpoints.map((endpoint) => (
              <Card key={endpoint.id}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">{endpoint.name}</CardTitle>
                    <Badge
                      className={`text-xs ${getStatusColor(endpoint.sync_status)}`}
                    >
                      {endpoint.sync_status}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span>Users</span>
                    <span className="font-medium">{endpoint.total_users}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span>Groups</span>
                    <span className="font-medium">{endpoint.total_groups}</span>
                  </div>
                  <div className="text-xs text-gray-500">
                    Last sync: {new Date(endpoint.last_sync).toLocaleString()}
                  </div>
                  <div className="flex space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      onClick={() => handleManualSync("incremental_sync")}
                      disabled={!isAdmin || !endpoint.enabled}
                    >
                      <IconComponent
                        name="RefreshCw"
                        className="h-3 w-3 mr-1"
                      />
                      Sync
                    </Button>
                    <Button variant="ghost" size="sm">
                      <IconComponent name="Settings" className="h-3 w-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Recent Activity */}
          <Card>
            <CardHeader>
              <CardTitle>Recent Sync Activity</CardTitle>
              <CardDescription>
                Latest provisioning operations and their status
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {syncOperations.slice(0, 3).map((operation) => (
                  <div
                    key={operation.id}
                    className="flex items-center justify-between p-3 border rounded-lg"
                  >
                    <div className="flex items-center space-x-3">
                      <IconComponent
                        name={
                          operation.status === "running"
                            ? "Loader2"
                            : operation.status === "completed"
                              ? "CheckCircle"
                              : operation.status === "failed"
                                ? "XCircle"
                                : "Clock"
                        }
                        className={`h-5 w-5 ${
                          operation.status === "running" ? "animate-spin" : ""
                        } ${getStatusColor(operation.status).split(" ")[0]}`}
                      />
                      <div>
                        <p className="font-medium">
                          {operation.type
                            .replace("_", " ")
                            .replace(/\b\w/g, (l) => l.toUpperCase())}
                        </p>
                        <p className="text-sm text-gray-500">
                          {new Date(operation.started_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge
                        className={`text-xs ${getStatusColor(operation.status)}`}
                      >
                        {operation.status}
                      </Badge>
                      {operation.status === "running" && (
                        <div className="mt-1">
                          <Progress
                            value={operation.progress}
                            className="w-20"
                          />
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Sync Operations */}
        <TabsContent value="operations" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Sync Operations History</CardTitle>
                  <CardDescription>
                    Complete history of SCIM provisioning operations
                  </CardDescription>
                </div>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    onClick={() => handleManualSync("user_sync")}
                    disabled={!isAdmin || isSyncing}
                  >
                    <IconComponent name="Users" className="h-4 w-4 mr-2" />
                    Sync Users
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => handleManualSync("group_sync")}
                    disabled={!isAdmin || isSyncing}
                  >
                    <IconComponent name="UserCheck" className="h-4 w-4 mr-2" />
                    Sync Groups
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Operation</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Progress</TableHead>
                    <TableHead>Summary</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {syncOperations.map((operation) => (
                    <TableRow key={operation.id}>
                      <TableCell>
                        <div className="flex items-center space-x-2">
                          <IconComponent
                            name={
                              operation.type === "full_sync"
                                ? "Database"
                                : operation.type === "user_sync"
                                  ? "Users"
                                  : operation.type === "group_sync"
                                    ? "UserCheck"
                                    : "RefreshCw"
                            }
                            className="h-4 w-4"
                          />
                          <span className="capitalize">
                            {operation.type.replace("_", " ")}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={`text-xs ${getStatusColor(operation.status)}`}
                        >
                          {operation.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {new Date(operation.started_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {operation.completed_at
                          ? `${Math.round(
                              (new Date(operation.completed_at).getTime() -
                                new Date(operation.started_at).getTime()) /
                                1000,
                            )}s`
                          : "—"}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-2">
                          <Progress
                            value={operation.progress}
                            className="w-16"
                          />
                          <span className="text-xs">{operation.progress}%</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-xs text-gray-600">
                          <div>+{operation.summary.created} created</div>
                          <div>~{operation.summary.updated} updated</div>
                          <div>-{operation.summary.deleted} deleted</div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-1">
                          <Button variant="ghost" size="sm">
                            <IconComponent name="Eye" className="h-3 w-3" />
                          </Button>
                          {operation.errors.length > 0 && (
                            <Button variant="ghost" size="sm">
                              <IconComponent
                                name="AlertTriangle"
                                className="h-3 w-3"
                              />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Provisioning Rules */}
        <TabsContent value="rules" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Provisioning Rules</CardTitle>
                  <CardDescription>
                    Configure automatic user and group provisioning rules
                  </CardDescription>
                </div>
                <Button disabled={!isAdmin}>
                  <IconComponent name="Plus" className="h-4 w-4 mr-2" />
                  Add Rule
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {provisioningRules.map((rule) => (
                  <div
                    key={rule.id}
                    className="border rounded-lg p-4 space-y-3"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <h3 className="font-medium">{rule.name}</h3>
                        <Badge
                          variant={rule.enabled ? "default" : "secondary"}
                          className="text-xs"
                        >
                          {rule.enabled ? "Enabled" : "Disabled"}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          Priority {rule.priority}
                        </Badge>
                      </div>
                      <div className="flex space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleToggleRule(rule.id)}
                          disabled={!isAdmin}
                        >
                          {rule.enabled ? "Disable" : "Enable"}
                        </Button>
                        <Button variant="ghost" size="sm">
                          <IconComponent name="Edit" className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <Label className="text-xs text-gray-500">
                          Condition
                        </Label>
                        <code className="block bg-gray-100 p-2 rounded text-xs">
                          {rule.condition}
                        </code>
                      </div>
                      <div>
                        <Label className="text-xs text-gray-500">Action</Label>
                        <div className="flex items-center space-x-2">
                          <Badge
                            variant="outline"
                            className="text-xs capitalize"
                          >
                            {rule.action}
                          </Badge>
                          <span className="text-xs">
                            {rule.target_attribute}
                          </span>
                        </div>
                      </div>
                    </div>

                    {Object.keys(rule.value_mapping).length > 0 && (
                      <div>
                        <Label className="text-xs text-gray-500">
                          Value Mappings
                        </Label>
                        <div className="flex flex-wrap gap-2 mt-1">
                          {Object.entries(rule.value_mapping).map(
                            ([key, value]) => (
                              <span
                                key={key}
                                className="text-xs bg-blue-50 text-blue-700 px-2 py-1 rounded"
                              >
                                {key} → {value}
                              </span>
                            ),
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Conflicts */}
        <TabsContent value="conflicts" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Conflict Resolution</CardTitle>
              <CardDescription>
                Resolve conflicts that occurred during SCIM provisioning
              </CardDescription>
            </CardHeader>
            <CardContent>
              {conflicts.filter((c) => c.status === "pending").length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <IconComponent
                    name="CheckCircle"
                    className="h-8 w-8 mx-auto mb-2 text-green-500"
                  />
                  <p>No pending conflicts</p>
                  <p className="text-sm mt-1">
                    All provisioning operations completed successfully
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {conflicts
                    .filter((conflict) => conflict.status === "pending")
                    .map((conflict) => (
                      <div
                        key={conflict.id}
                        className="border border-orange-200 bg-orange-50 rounded-lg p-4"
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex items-start space-x-3">
                            <IconComponent
                              name="AlertTriangle"
                              className="h-5 w-5 text-orange-600 mt-0.5"
                            />
                            <div>
                              <h3 className="font-medium text-orange-900">
                                {conflict.conflict_type
                                  .replace("_", " ")
                                  .replace(/\b\w/g, (l) => l.toUpperCase())}
                              </h3>
                              <p className="text-sm text-orange-800 mt-1">
                                {conflict.description}
                              </p>
                              <p className="text-xs text-orange-600 mt-2">
                                User ID: {conflict.user_id} • Created:{" "}
                                {new Date(conflict.created_at).toLocaleString()}
                              </p>
                            </div>
                          </div>
                          <div className="flex space-x-2">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() =>
                                handleResolveConflict(conflict.id, "resolve")
                              }
                              disabled={!isAdmin}
                              className="bg-white"
                            >
                              <IconComponent
                                name="Check"
                                className="h-4 w-4 mr-2"
                              />
                              Resolve
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                handleResolveConflict(conflict.id, "ignore")
                              }
                              disabled={!isAdmin}
                            >
                              <IconComponent
                                name="X"
                                className="h-4 w-4 mr-2"
                              />
                              Ignore
                            </Button>
                          </div>
                        </div>

                        <div className="mt-3 p-3 bg-white rounded border">
                          <Label className="text-xs text-gray-500">
                            Suggested Action
                          </Label>
                          <p className="text-sm mt-1">
                            {conflict.suggested_action}
                          </p>
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Authentication Modal */}
      <AuthenticationModal
        open={showAuthModal}
        onOpenChange={setShowAuthModal}
        onSuccess={() => {
          // Refresh any data if needed
        }}
      />
    </div>
  );
}
