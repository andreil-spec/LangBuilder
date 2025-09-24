// Service Accounts Component - Real API Implementation
// Implements service account management with real authentication

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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useCreateServiceAccount } from "@/controllers/API/queries/rbac/use-create-service-account";
import { useDeleteServiceAccount } from "@/controllers/API/queries/rbac/use-delete-service-account";
import {
  ServiceAccount,
  useGetServiceAccounts,
} from "@/controllers/API/queries/rbac/use-get-service-accounts";
import {
  useGetWorkspaces,
  Workspace,
} from "@/controllers/API/queries/rbac/use-get-workspaces";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";

interface CreateServiceAccountData {
  name: string;
  description?: string;
  workspace_id: string;
  scope_type: "global" | "workspace" | "project" | "environment";
  scope_id?: string;
  permissions?: string[];
}

interface ServiceAccountBuilderProps {
  workspaces: Workspace[];
  onSave: (data: CreateServiceAccountData) => void;
  onCancel: () => void;
}

function ServiceAccountBuilder({
  workspaces,
  onSave,
  onCancel,
}: ServiceAccountBuilderProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState(
    workspaces[0]?.id || "",
  );
  const [scopeType, setScopeType] = useState<
    "global" | "workspace" | "project" | "environment"
  >("workspace");
  const [nameError, setNameError] = useState("");
  const [workspaceError, setWorkspaceError] = useState("");

  const handleSave = () => {
    let hasError = false;

    if (!name.trim()) {
      setNameError("Service account name is required");
      hasError = true;
    } else {
      setNameError("");
    }

    if (!selectedWorkspaceId) {
      setWorkspaceError("Workspace selection is required");
      hasError = true;
    } else {
      setWorkspaceError("");
    }

    if (!hasError) {
      onSave({
        name: name.trim(),
        description: description.trim() || undefined,
        workspace_id: selectedWorkspaceId,
        scope_type: scopeType,
        scope_id: scopeType === "workspace" ? selectedWorkspaceId : undefined,
      });
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Service Account Name *</Label>
        <Input
          id="name"
          placeholder="Enter service account name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        {nameError && <p className="text-sm text-red-600">{nameError}</p>}
      </div>

      <div className="space-y-2">
        <Label htmlFor="workspace">Workspace *</Label>
        <Select
          value={selectedWorkspaceId}
          onValueChange={setSelectedWorkspaceId}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select workspace" />
          </SelectTrigger>
          <SelectContent>
            {workspaces.map((workspace) => (
              <SelectItem key={workspace.id} value={workspace.id}>
                {workspace.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {workspaceError && (
          <p className="text-sm text-red-600">{workspaceError}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="scope">Scope Type</Label>
        <Select
          value={scopeType}
          onValueChange={(value) => setScopeType(value as any)}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select scope type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="global">Global</SelectItem>
            <SelectItem value="workspace">Workspace</SelectItem>
            <SelectItem value="project">Project</SelectItem>
            <SelectItem value="environment">Environment</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          placeholder="Enter service account description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
        />
      </div>

      <div className="flex space-x-2">
        <Button onClick={handleSave} className="flex-1">
          Create Service Account
        </Button>
        <Button variant="outline" onClick={onCancel} className="flex-1">
          Cancel
        </Button>
      </div>
    </div>
  );
}

export default function ServiceAccounts() {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [showAuthModal, setShowAuthModal] = useState(false);

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // API hooks
  const {
    mutate: fetchServiceAccounts,
    data: serviceAccountsData,
    isPending: isLoadingServiceAccounts,
    error: serviceAccountsError,
  } = useGetServiceAccounts({
    onSuccess: (data) => {
      console.log("✅ Service accounts fetched successfully:", data);
    },
    onError: (error) => {
      console.error("❌ Failed to fetch service accounts:", error);
    },
  });

  const {
    mutate: fetchWorkspaces,
    data: workspacesData,
    isPending: isLoadingWorkspaces,
  } = useGetWorkspaces({
    onSuccess: (data) => {
      console.log("✅ Workspaces fetched successfully:", data);
    },
    onError: (error) => {
      console.error("❌ Failed to fetch workspaces:", error);
    },
  });

  const { mutate: createServiceAccount, isPending: isCreatingServiceAccount } =
    useCreateServiceAccount({
      onSuccess: (newServiceAccount) => {
        console.log(
          "✅ Service account created successfully:",
          newServiceAccount,
        );
        setIsCreateDialogOpen(false);
        // Refresh service accounts list
        fetchServiceAccounts({ search: searchTerm });
        alert(
          `✅ Service account "${newServiceAccount.name}" created successfully!`,
        );
      },
      onError: (error) => {
        console.error("❌ Failed to create service account:", error);
        alert(
          `❌ Failed to create service account: ${error.message || "Unknown error"}`,
        );
      },
    });

  const { mutate: deleteServiceAccount } = useDeleteServiceAccount({
    onSuccess: () => {
      console.log("✅ Service account deleted successfully");
      // Refresh service accounts list
      fetchServiceAccounts({ search: searchTerm });
      alert("✅ Service account deleted successfully!");
    },
    onError: (error) => {
      console.error("❌ Failed to delete service account:", error);
      alert(
        `❌ Failed to delete service account: ${error.message || "Unknown error"}`,
      );
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
    console.log("🎉 Authentication successful, fetching data");
    fetchServiceAccounts({ search: searchTerm });
    fetchWorkspaces({});
  };

  // Fetch data when authenticated
  useEffect(() => {
    if (isAdmin) {
      fetchServiceAccounts({ search: searchTerm });
      fetchWorkspaces({});
    }
  }, [isAdmin]);

  // Debug authentication state changes
  useEffect(() => {
    console.log("🔄 ServiceAccounts: Auth state changed:", {
      isAdmin,
    });
  }, [isAdmin]);

  const handleCreateServiceAccount = (data: CreateServiceAccountData) => {
    requireAuth("create-service-account", () => {
      createServiceAccount(data);
    });
  };

  const handleDeleteServiceAccount = (
    serviceAccountId: string,
    name: string,
  ) => {
    if (confirm(`Are you sure you want to delete service account "${name}"?`)) {
      requireAuth("delete-service-account", () => {
        deleteServiceAccount({ service_account_id: serviceAccountId });
      });
    }
  };

  const handleSearch = () => {
    requireAuth("search-service-accounts", () => {
      fetchServiceAccounts({ search: searchTerm });
    });
  };

  // Get data from API responses
  const serviceAccounts = serviceAccountsData?.service_accounts || [];
  const workspaces = workspacesData?.workspaces || [];

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold flex items-center space-x-2">
            <IconComponent name="Bot" className="h-5 w-5" />
            <span>Service Accounts</span>
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Manage service accounts for API access and automation
          </p>
        </div>
        <div className="flex items-center space-x-2">

          <Dialog
            open={isCreateDialogOpen}
            onOpenChange={setIsCreateDialogOpen}
          >
            <DialogTrigger asChild>
              <Button disabled={!isAdmin}>
                <IconComponent name="Plus" className="h-4 w-4 mr-2" />
                Create Service Account
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Create New Service Account</DialogTitle>
                <DialogDescription>
                  Create a service account for API access and automation.
                </DialogDescription>
              </DialogHeader>
              <ServiceAccountBuilder
                workspaces={workspaces}
                onSave={handleCreateServiceAccount}
                onCancel={() => setIsCreateDialogOpen(false)}
              />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Search */}
      <div className="mb-4 flex space-x-2">
        <Input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onKeyPress={(e) => e.key === "Enter" && handleSearch()}
          placeholder="Search service accounts..."
          className="w-64"
        />
        <Button
          onClick={handleSearch}
          disabled={isLoadingServiceAccounts || !isAdmin}
        >
          {isLoadingServiceAccounts ? "Searching..." : "Search"}
        </Button>
        {searchTerm && (
          <Button
            variant="outline"
            onClick={() => {
              setSearchTerm("");
              requireAuth("clear-search", () => {
                fetchServiceAccounts({ search: "" });
              });
            }}
          >
            Clear
          </Button>
        )}
      </div>

      {/* Error Display */}
      {serviceAccountsError && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error loading service accounts: {serviceAccountsError.message}
        </div>
      )}

      {/* Service Accounts Table */}
      <Card>
        <CardHeader>
          <CardTitle>Service Accounts</CardTitle>
          <CardDescription>
            {isLoadingServiceAccounts
              ? "Loading service accounts..."
              : serviceAccounts.length === 0
                ? "No service accounts found"
                : `Found ${serviceAccounts.length} service account${serviceAccounts.length !== 1 ? "s" : ""}`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border rounded-lg overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Workspace</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Used</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoadingServiceAccounts ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8">
                      <div className="flex items-center justify-center">
                        <IconComponent
                          name="Loader2"
                          className="h-4 w-4 animate-spin mr-2"
                        />
                        Loading service accounts...
                      </div>
                    </TableCell>
                  </TableRow>
                ) : !isAdmin ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8">
                      <div className="text-gray-500">
                        Please authenticate to view service accounts
                        <Button
                          variant="link"
                          onClick={() => setShowAuthModal(true)}
                          className="ml-2"
                        >
                          Sign In
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : serviceAccounts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8">
                      <div className="text-gray-500">
                        No service accounts found. Create your first service
                        account!
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  serviceAccounts.map((serviceAccount) => (
                    <TableRow key={serviceAccount.id}>
                      <TableCell className="font-medium">
                        {serviceAccount.name}
                      </TableCell>
                      <TableCell>
                        {serviceAccount.description || "No description"}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {workspaces.find(
                            (w) => w.id === serviceAccount.workspace_id,
                          )?.name || "Unknown"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {serviceAccount.scope_type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            serviceAccount.is_active ? "default" : "destructive"
                          }
                        >
                          {serviceAccount.is_active ? "Active" : "Inactive"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {serviceAccount.last_used_at
                          ? new Date(
                              serviceAccount.last_used_at,
                            ).toLocaleDateString()
                          : "Never"}
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button variant="ghost" size="sm">
                            <IconComponent
                              name="Settings"
                              className="h-4 w-4"
                            />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              handleDeleteServiceAccount(
                                serviceAccount.id,
                                serviceAccount.name,
                              )
                            }
                          >
                            <IconComponent name="Trash2" className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Authentication Modal */}
      <AuthenticationModal
        open={showAuthModal}
        onOpenChange={setShowAuthModal}
        onSuccess={handleAuthSuccess}
      />
    </div>
  );
}
