// Permission Management Component - Epic 1: Story 1.1 (AC1-AC8)
// Implements permission catalog with CRUD and extended actions

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
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useGetPermissions } from "@/controllers/API/queries/rbac";
import { useCreatePermission } from "@/controllers/API/queries/rbac/use-create-permission";
import useAlertStore from "@/stores/alertStore";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";
import ConfirmDeleteModal from "../../../RBAC/components/ConfirmDeleteModal";
import PermissionEditModal from "../../../RBAC/components/PermissionEditModal";
import {
  CRUDAction,
  ExtendedAction,
  Permission,
  PermissionAction,
} from "../../types/rbac";

// Enhanced permission catalog data (PRD AC1: CRUD + Extended actions with security indicators)
const MOCK_PERMISSIONS: Permission[] = [
  // CRUD actions
  {
    id: "550e8400-e29b-41d4-a716-446655440001",
    action: "create",
    resource_type: "flow",
    description: "Create new flows",
    category: "basic",
    is_dangerous: false,
    requires_mfa: false,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  {
    id: "550e8400-e29b-41d4-a716-446655440002",
    action: "read",
    resource_type: "flow",
    description: "View and read flows",
    category: "basic",
    is_dangerous: false,
    requires_mfa: false,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  {
    id: "550e8400-e29b-41d4-a716-446655440003",
    action: "update",
    resource_type: "flow",
    description: "Modify existing flows",
    category: "basic",
    is_dangerous: false,
    requires_mfa: false,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  {
    id: "550e8400-e29b-41d4-a716-446655440004",
    action: "delete",
    resource_type: "flow",
    description: "Delete flows - irreversible action",
    category: "basic",
    is_dangerous: true,
    requires_mfa: false,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  // Extended actions (PRD AC1) with enhanced security metadata
  {
    id: "550e8400-e29b-41d4-a716-446655440005",
    action: "export_flow",
    resource_type: "flow",
    description: "Export flows to external formats - may expose sensitive data",
    category: "advanced",
    is_dangerous: true,
    requires_mfa: true,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  {
    id: "550e8400-e29b-41d4-a716-446655440006",
    action: "deploy_environment",
    resource_type: "environment",
    description: "Deploy to production environments - high impact operation",
    category: "deployment",
    is_dangerous: true,
    requires_mfa: true,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  {
    id: "550e8400-e29b-41d4-a716-446655440007",
    action: "invite_users",
    resource_type: "workspace",
    description: "Invite users to workspace - affects access control",
    category: "user_management",
    is_dangerous: false,
    requires_mfa: false,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  {
    id: "550e8400-e29b-41d4-a716-446655440008",
    action: "modify_component_settings",
    resource_type: "component",
    description: "Modify component configuration - can break flows",
    category: "configuration",
    is_dangerous: false,
    requires_mfa: false,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  {
    id: "550e8400-e29b-41d4-a716-446655440009",
    action: "manage_tokens",
    resource_type: "project",
    description: "Create and manage API tokens - security critical",
    category: "security",
    is_dangerous: true,
    requires_mfa: true,
    is_system: false,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
  // System-level permissions
  {
    id: "550e8400-e29b-41d4-a716-446655440010",
    action: "system_admin",
    resource_type: "system",
    description: "Full system administration access",
    category: "system",
    is_dangerous: true,
    requires_mfa: true,
    is_system: true,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  },
];

const CRUD_ACTIONS: CRUDAction[] = ["create", "read", "update", "delete"];
const EXTENDED_ACTIONS: ExtendedAction[] = [
  "export_flow",
  "deploy_environment",
  "invite_users",
  "modify_component_settings",
  "manage_tokens",
];

interface PermissionCatalogProps {
  permissions?: Permission[];
  onPermissionSelect?: (permission: Permission) => void;
}

function PermissionCatalog({
  permissions = MOCK_PERMISSIONS,
  onPermissionSelect,
}: PermissionCatalogProps) {
  // Search functionality commented out - not specified in PRD
  // const [searchTerm, setSearchTerm] = useState("");
  const [filterAction, setFilterAction] = useState<PermissionAction | "all">(
    "all",
  );
  const [filterResourceType, setFilterResourceType] = useState<string>("all");

  const filteredPermissions = useMemo(() => {
    return permissions.filter((permission) => {
      // Search functionality commented out - not specified in PRD
      // const matchesSearch =
      //   permission.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      //   permission.resource_type
      //     .toLowerCase()
      //     .includes(searchTerm.toLowerCase()) ||
      //   permission.description.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesAction =
        filterAction === "all" || permission.action === filterAction;

      const matchesResourceType =
        filterResourceType === "all" ||
        permission.resource_type === filterResourceType;

      return matchesAction && matchesResourceType;
    });
  }, [permissions, filterAction, filterResourceType]);

  const resourceTypes = useMemo(() => {
    const types = new Set(permissions.map((p) => p.resource_type));
    return Array.from(types);
  }, [permissions]);

  const getActionBadgeVariant = (action: PermissionAction) => {
    if (CRUD_ACTIONS.includes(action as CRUDAction)) {
      return "default";
    }
    return "secondary";
  };

  const getActionIcon = (action: PermissionAction) => {
    switch (action) {
      case "create":
        return "Plus";
      case "read":
        return "Eye";
      case "update":
        return "Edit";
      case "delete":
        return "Trash2";
      case "export_flow":
        return "Download";
      case "deploy_environment":
        return "Rocket";
      case "invite_users":
        return "UserPlus";
      case "modify_component_settings":
        return "Settings";
      case "manage_tokens":
        return "Key";
      default:
        return "Shield";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Permission Catalog</h3>
          <p className="text-sm text-muted-foreground">
            CRUD and extended actions available for role building
          </p>
        </div>
        <Badge variant="outline" className="text-xs">
          {filteredPermissions.length} permissions
        </Badge>
      </div>

      {/* Filters */}
      <div className="flex gap-4">
        {/* Search functionality commented out - not specified in PRD */}
        {/* <div className="flex-1">
          <Input
            placeholder="Search permissions..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="max-w-sm"
          />
        </div> */}
        <Select
          value={filterAction}
          onValueChange={(value) =>
            setFilterAction(value as PermissionAction | "all")
          }
        >
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Filter by action" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Actions</SelectItem>
            <SelectItem value="create">Create</SelectItem>
            <SelectItem value="read">Read</SelectItem>
            <SelectItem value="update">Update</SelectItem>
            <SelectItem value="delete">Delete</SelectItem>
            <SelectItem value="export_flow">Export Flow</SelectItem>
            <SelectItem value="deploy_environment">
              Deploy Environment
            </SelectItem>
            <SelectItem value="invite_users">Invite Users</SelectItem>
            <SelectItem value="modify_component_settings">
              Modify Component
            </SelectItem>
            <SelectItem value="manage_tokens">Manage Tokens</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={filterResourceType}
          onValueChange={setFilterResourceType}
        >
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Filter by resource" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Resources</SelectItem>
            {resourceTypes.map((type) => (
              <SelectItem key={type} value={type}>
                {type.charAt(0).toUpperCase() + type.slice(1)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Permission Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Action</TableHead>
                <TableHead>Resource Type</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Security</TableHead>
                <TableHead>Type</TableHead>
                <TableHead className="w-12"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredPermissions.map((permission) => (
                <TableRow
                  key={permission.id}
                  className={`cursor-pointer hover:bg-muted/50 ${
                    permission.is_dangerous ? "border-l-4 border-l-red-500" : ""
                  }`}
                  onClick={() => onPermissionSelect?.(permission)}
                >
                  <TableCell>
                    <div className="flex items-center space-x-2">
                      <IconComponent
                        name={getActionIcon(permission.action)}
                        className="h-4 w-4"
                      />
                      <code className="text-sm bg-muted px-2 py-1 rounded">
                        {permission.action}
                      </code>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{permission.resource_type}</Badge>
                  </TableCell>
                  <TableCell>
                    <div>
                      <p className="text-sm">{permission.description}</p>
                      {permission.is_dangerous && (
                        <p className="text-xs text-red-600 mt-1">
                          ⚠️ High-impact operation
                        </p>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize">
                      {permission.category || "general"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {permission.is_dangerous && (
                        <Badge variant="destructive" className="text-xs">
                          <IconComponent
                            name="AlertTriangle"
                            className="h-3 w-3 mr-1"
                          />
                          Dangerous
                        </Badge>
                      )}
                      {permission.requires_mfa && (
                        <Badge variant="secondary" className="text-xs">
                          <IconComponent
                            name="Shield"
                            className="h-3 w-3 mr-1"
                          />
                          MFA
                        </Badge>
                      )}
                      {permission.is_system && (
                        <Badge variant="outline" className="text-xs">
                          <IconComponent
                            name="Settings"
                            className="h-3 w-3 mr-1"
                          />
                          System
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={getActionBadgeVariant(permission.action)}>
                      {CRUD_ACTIONS.includes(permission.action as CRUDAction)
                        ? "CRUD"
                        : "Extended"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <IconComponent
                      name="ChevronRight"
                      className="h-4 w-4 text-muted-foreground"
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Enhanced Summary Cards with Security Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center">
              <IconComponent name="Shield" className="h-4 w-4 mr-1" />
              CRUD Actions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {
                permissions.filter((p) =>
                  CRUD_ACTIONS.includes(p.action as CRUDAction),
                ).length
              }
            </div>
            <p className="text-xs text-muted-foreground">Basic operations</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center">
              <IconComponent name="Zap" className="h-4 w-4 mr-1" />
              Extended Actions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {
                permissions.filter((p) =>
                  EXTENDED_ACTIONS.includes(p.action as ExtendedAction),
                ).length
              }
            </div>
            <p className="text-xs text-muted-foreground">
              Specialized operations
            </p>
          </CardContent>
        </Card>
        <Card className="border-red-200">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center text-red-700">
              <IconComponent name="AlertTriangle" className="h-4 w-4 mr-1" />
              Dangerous
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {permissions.filter((p) => p.is_dangerous).length}
            </div>
            <p className="text-xs text-red-600">High-impact permissions</p>
          </CardContent>
        </Card>
        <Card className="border-yellow-200">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center text-yellow-700">
              <IconComponent name="Lock" className="h-4 w-4 mr-1" />
              MFA Required
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">
              {permissions.filter((p) => p.requires_mfa).length}
            </div>
            <p className="text-xs text-yellow-600">Multi-factor auth needed</p>
          </CardContent>
        </Card>
        <Card className="border-purple-200">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center text-purple-700">
              <IconComponent name="Settings" className="h-4 w-4 mr-1" />
              System Level
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-purple-600">
              {permissions.filter((p) => p.is_system).length}
            </div>
            <p className="text-xs text-purple-600">System permissions</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center">
              <IconComponent name="Database" className="h-4 w-4 mr-1" />
              Total
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{permissions.length}</div>
            <p className="text-xs text-muted-foreground">
              Available permissions
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Security Guidelines */}
      <Card className="border-blue-200 bg-blue-50">
        <CardHeader>
          <CardTitle className="text-sm font-medium flex items-center text-blue-800">
            <IconComponent name="Info" className="h-4 w-4 mr-2" />
            Permission Security Guidelines
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-blue-700">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <p className="font-medium mb-1">🔴 Dangerous Permissions</p>
              <p className="text-xs">
                High-impact operations that can affect system security or data
                integrity. Require careful consideration.
              </p>
            </div>
            <div>
              <p className="font-medium mb-1">🟡 MFA Required</p>
              <p className="text-xs">
                Multi-factor authentication required for these operations to
                prevent unauthorized access.
              </p>
            </div>
            <div>
              <p className="font-medium mb-1">🟣 System Level</p>
              <p className="text-xs">
                Core system permissions that should only be granted to trusted
                administrators.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default function PermissionManagement() {
  const [selectedPermission, setSelectedPermission] =
    useState<Permission | null>(null);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);

  // Modal states
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [editModalMode, setEditModalMode] = useState<"edit" | "create">("edit");

  // API integration for fetching permissions
  const getPermissions = useGetPermissions();
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(true);

  // API integration for creating permissions
  const { mutate: createPermission, isPending: isCreatingPermission } = useCreatePermission({
    onSuccess: (createdPermission) => {
      console.log("✅ Permission created successfully:", createdPermission);

      // Show success notification
      setSuccessData({
        title: "Permission Created Successfully",
      });

      // Add the new permission to the list immediately for UI responsiveness
      setPermissions((prev) => [createdPermission, ...prev]);
      // Refresh permissions using the same logic as handleRefreshPermissions
      setLoading(true);
      getPermissions.mutate(
        { limit: 100 },
        {
          onSuccess: (data) => {
            setPermissions(data || []);
            setLoading(false);
          },
          onError: (error) => {
            console.error("Failed to refresh permissions:", error);
            setLoading(false);
          },
        }
      );
    },
    onError: (error) => {
      console.error("❌ Failed to create permission:", error);

      // Enhanced error handling for better user experience
      let title = "Failed to Create Permission";
      let errorDetails = [error.message || "Unknown error occurred"];

      // Check for specific duplicate error
      if (error.message && error.message.includes("already exists")) {
        title = "Permission Already Exists";
        errorDetails = [
          "A permission with this code already exists.",
          "Please use a different permission code or update the existing permission."
        ];
      } else if (error.message && error.message.includes("validation")) {
        title = "Validation Error";
        errorDetails = [error.message];
      } else if (error.message && error.message.includes("authentication")) {
        title = "Authentication Error";
        errorDetails = [
          "You don't have permission to create permissions.",
          "Please check your authentication status."
        ];
      }

      setErrorData({
        title,
        list: errorDetails,
      });
    },
  });

  // Authentication state management - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // Alert/notification system
  const setSuccessData = useAlertStore((state) => state.setSuccessData);
  const setErrorData = useAlertStore((state) => state.setErrorData);

  // Helper function to handle authentication-protected actions
  const requireAuth = (action: string, callback: () => void) => {
    console.log("🔐 Authentication check:", {
      action,
      isAdmin,
    });

    if (!isAdmin) {
      console.log("❌ Not authenticated, showing modal");
      setPendingAction(action);
      setShowAuthModal(true);
    } else {
      console.log("✅ Authenticated, executing action:", action);
      callback();
    }
  };

  // Handle authentication success
  const handleAuthSuccess = () => {
    console.log(
      "🎉 Authentication successful, executing pending action:",
      pendingAction,
    );

    // Force a small delay to ensure state updates
    setTimeout(() => {
      if (pendingAction === "add-permission") {
        handleAddPermission();
      } else if (pendingAction === "edit-permission") {
        handleEditPermission();
      } else if (pendingAction === "delete-permission") {
        handleDeletePermission();
      } else if (pendingAction === "refresh") {
        handleRefreshPermissions();
      }
      setPendingAction(null);
    }, 100);
  };

  // Action handlers
  const handleAddPermission = () => {
    console.log("🔧 Add Permission clicked - opening modal");
    setEditModalMode("create");
    setSelectedPermission(null);
    setShowEditModal(true);
  };

  const handleEditPermission = () => {
    console.log("🔧 Edit Permission clicked for:", selectedPermission);
    if (selectedPermission) {
      setEditModalMode("edit");
      setShowEditModal(true);
    }
  };

  const handleDeletePermission = () => {
    console.log("🔧 Delete Permission clicked for:", selectedPermission);
    if (selectedPermission) {
      setShowDeleteModal(true);
    }
  };

  // Modal handlers
  const handleSavePermission = (permission: Permission) => {
    console.log("💾 Saving permission:", permission);

    if (editModalMode === "create") {
      // Create new permission via API
      const permissionData = {
        name: permission.description || `${permission.action} ${permission.resource_type}`, // Generate name from description
        code: `${permission.resource_type}.${permission.action}`, // Generate code
        description: permission.description,
        category: permission.category,
        resource_type: permission.resource_type,
        action: permission.action,
        scope: "*",
        conditions: {},
        is_system: permission.is_system || false,
        is_dangerous: permission.is_dangerous || false,
        requires_mfa: permission.requires_mfa || false,
      };

      console.log("📡 Calling API to create permission:", permissionData);
      createPermission(permissionData);
    } else {
      // Update existing permission (TODO: implement update API)
      setPermissions((prev) =>
        prev.map((p) => (p.id === permission.id ? permission : p)),
      );
      setSelectedPermission(permission);
      console.log("✅ Permission updated:", permission);
    }
  };

  const handleConfirmDelete = () => {
    console.log("🗑️ Confirming delete for:", selectedPermission);
    if (selectedPermission) {
      setPermissions((prev) =>
        prev.filter((p) => p.id !== selectedPermission.id),
      );
      setSelectedPermission(null);
      console.log("✅ Permission deleted:", selectedPermission.id);
    }
  };

  const handleRefreshPermissions = () => {
    setLoading(true);
    getPermissions.mutate(
      { limit: 100 },
      {
        onSuccess: (data) => {
          setPermissions(data || []);
          setLoading(false);
        },
        onError: (error) => {
          console.error("Failed to refresh permissions:", error);
          setLoading(false);
        },
      },
    );
  };

  // Fetch permissions on component mount
  useEffect(() => {
    const fetchPermissions = async () => {
      try {
        setLoading(true);
        getPermissions.mutate(
          { limit: 100 },
          {
            onSuccess: (data) => {
              setPermissions(data || []);
              setLoading(false);
            },
            onError: (error) => {
              console.error("Failed to fetch permissions:", error);
              // Fallback to mock data if API fails
              setPermissions(MOCK_PERMISSIONS);
              setLoading(false);
            },
          },
        );
      } catch (error) {
        console.error("Permission fetch error:", error);
        setPermissions(MOCK_PERMISSIONS);
        setLoading(false);
      }
    };

    fetchPermissions();
  }, []);

  return (
    <div className="h-full flex flex-col p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Permission Management</h2>
          <p className="text-muted-foreground">
            Manage the permission catalog with CRUD and extended actions
          </p>
        </div>
        <div className="flex items-center space-x-2">

          <Button
            variant="outline"
            size="sm"
            onClick={() => requireAuth("refresh", handleRefreshPermissions)}
            disabled={loading}
          >
            <IconComponent
              name={loading ? "Loader2" : "RefreshCw"}
              className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Button
            size="sm"
            onClick={() => requireAuth("add-permission", handleAddPermission)}
          >
            <IconComponent name="Plus" className="h-4 w-4 mr-2" />
            Add Permission
          </Button>
        </div>
      </div>

      <div className="flex-1 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <IconComponent
              name="Loader2"
              className="h-6 w-6 animate-spin mr-2"
            />
            Loading permissions...
          </div>
        ) : (
          <PermissionCatalog
            permissions={permissions}
            onPermissionSelect={setSelectedPermission}
          />
        )}
      </div>

      {/* Permission Details Panel */}
      {selectedPermission && (
        <Card className="border-t">
          <CardHeader>
            <CardTitle className="text-lg flex items-center space-x-2">
              <IconComponent
                name={getActionIcon(selectedPermission.action)}
                className="h-5 w-5"
              />
              <span>Permission Details</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium">Action</label>
                <div className="mt-1">
                  <code className="text-sm bg-muted px-2 py-1 rounded">
                    {selectedPermission.action}
                  </code>
                </div>
              </div>
              <div>
                <label className="text-sm font-medium">Resource Type</label>
                <div className="mt-1">
                  <Badge variant="outline">
                    {selectedPermission.resource_type}
                  </Badge>
                </div>
              </div>
              <div>
                <label className="text-sm font-medium">Description</label>
                <p className="mt-1 text-sm text-muted-foreground">
                  {selectedPermission.description}
                </p>
              </div>
              <div className="flex space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    requireAuth("edit-permission", handleEditPermission)
                  }
                >
                  <IconComponent name="Edit" className="h-4 w-4 mr-2" />
                  Edit
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() =>
                    requireAuth("delete-permission", handleDeletePermission)
                  }
                >
                  <IconComponent name="Trash2" className="h-4 w-4 mr-2" />
                  Delete
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Authentication Modal */}
      <AuthenticationModal
        open={showAuthModal}
        onOpenChange={setShowAuthModal}
        onSuccess={handleAuthSuccess}
      />

      {/* Permission Edit/Create Modal */}
      <PermissionEditModal
        open={showEditModal}
        onOpenChange={setShowEditModal}
        permission={selectedPermission}
        onSave={handleSavePermission}
        mode={editModalMode}
      />

      {/* Delete Confirmation Modal */}
      <ConfirmDeleteModal
        open={showDeleteModal}
        onOpenChange={setShowDeleteModal}
        permission={selectedPermission}
        onConfirm={handleConfirmDelete}
      />
    </div>
  );
}

function getActionIcon(action: PermissionAction) {
  switch (action) {
    case "create":
      return "Plus";
    case "read":
      return "Eye";
    case "update":
      return "Edit";
    case "delete":
      return "Trash2";
    case "export_flow":
      return "Download";
    case "deploy_environment":
      return "Rocket";
    case "invite_users":
      return "UserPlus";
    case "modify_component_settings":
      return "Settings";
    case "manage_tokens":
      return "Key";
    default:
      return "Shield";
  }
}
