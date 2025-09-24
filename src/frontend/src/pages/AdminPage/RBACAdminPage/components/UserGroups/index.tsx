// User Groups Component - Real API Implementation
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
import {
  useGetWorkspaces,
  Workspace,
} from "@/controllers/API/queries/rbac/use-get-workspaces";
import {
  GroupType,
  UserGroup,
  useCreateUserGroup,
  useGetUserGroups,
} from "@/controllers/API/queries/rbac/use-user-groups";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";

export default function UserGroups() {
  const [searchTerm, setSearchTerm] = useState("");
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);

  // Form state for creating user groups
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupDescription, setNewGroupDescription] = useState("");
  const [newGroupType, setNewGroupType] = useState<GroupType>(GroupType.LOCAL);
  const [formErrors, setFormErrors] = useState<{
    name?: string;
    workspace?: string;
  }>({});

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // API hooks
  const {
    mutate: fetchUserGroups,
    data: userGroupsData,
    isPending: isLoading,
    error,
  } = useGetUserGroups({});

  const {
    mutate: fetchWorkspaces,
    data: workspacesData,
    isPending: isLoadingWorkspaces,
  } = useGetWorkspaces({});

  const {
    mutate: createUserGroup,
    isPending: isCreatingUserGroup,
    isSuccess: isCreateSuccess,
    isError: isCreateError,
    error: createError,
    data: createdGroup,
  } = useCreateUserGroup({});

  // Fetch data when authenticated
  useEffect(() => {
    if (isAdmin) {
      // First fetch workspaces to get workspace_id
      fetchWorkspaces({});
    }
  }, [isAdmin]);

  // Fetch user groups when workspaces are available
  useEffect(() => {
    if (isAdmin && workspacesData?.workspaces?.length > 0) {
      const firstWorkspaceId = workspacesData.workspaces[0].id;
      fetchUserGroups({ workspace_id: firstWorkspaceId, search: searchTerm });
    }
  }, [workspacesData, searchTerm]);

  // Handle user group creation success/error
  useEffect(() => {
    if (isCreateSuccess && createdGroup) {
      console.log("✅ User group created successfully:", createdGroup);

      // Reset form and close dialog
      setNewGroupName("");
      setNewGroupDescription("");
      setNewGroupType(GroupType.LOCAL);
      setIsCreateDialogOpen(false);

      // Refresh user groups list
      if (workspacesData?.workspaces?.length > 0) {
        const firstWorkspaceId = workspacesData.workspaces[0].id;
        fetchUserGroups({ workspace_id: firstWorkspaceId, search: searchTerm });
      }
    }
  }, [isCreateSuccess, createdGroup]);

  useEffect(() => {
    if (isCreateError && createError) {
      console.error("❌ Failed to create user group:", createError);
      alert(
        `Failed to create user group: ${createError.message || "Unknown error"}`,
      );
    }
  }, [isCreateError, createError]);

  const requireAuth = (action: string, callback: () => void) => {
    if (!isAdmin) {
      setShowAuthModal(true);
    } else {
      callback();
    }
  };

  const handleSearch = () => {
    requireAuth("search-user-groups", () => {
      if (workspacesData?.workspaces?.length > 0) {
        const firstWorkspaceId = workspacesData.workspaces[0].id;
        fetchUserGroups({ workspace_id: firstWorkspaceId, search: searchTerm });
      }
    });
  };

  const handleCreateUserGroup = () => {
    // Reset form errors
    setFormErrors({});
    let hasError = false;

    // Validate form
    if (!newGroupName.trim()) {
      setFormErrors((prev) => ({
        ...prev,
        name: "User group name is required",
      }));
      hasError = true;
    }

    if (!workspacesData?.workspaces?.length) {
      setFormErrors((prev) => ({
        ...prev,
        workspace: "No workspace available",
      }));
      hasError = true;
    }

    if (hasError) return;

    const firstWorkspaceId = workspacesData.workspaces[0].id;

    requireAuth("create-user-group", () => {
      const groupData = {
        name: newGroupName.trim(),
        description: newGroupDescription.trim() || undefined,
        workspace_id: firstWorkspaceId,
        group_type: newGroupType,
      };

      console.log("Creating user group:", groupData);

      createUserGroup(groupData);
    });
  };

  const userGroups = userGroupsData?.user_groups || [];
  const workspaces = workspacesData?.workspaces || [];
  const isLoadingData = isLoading || isLoadingWorkspaces;
  const hasWorkspaces = workspaces.length > 0;

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold flex items-center space-x-2">
            <IconComponent name="UserCheck" className="h-5 w-5" />
            <span>User Groups</span>
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Manage user groups and memberships
          </p>
        </div>
        <div className="flex items-center space-x-2">

          {/* Create User Group Dialog */}
          <Dialog
            open={isCreateDialogOpen}
            onOpenChange={setIsCreateDialogOpen}
          >
            <DialogTrigger asChild>
              <Button disabled={!isAdmin || !hasWorkspaces}>
                <IconComponent name="Plus" className="h-4 w-4 mr-2" />
                Create User Group
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Create New User Group</DialogTitle>
                <DialogDescription>
                  Create a new user group to organize users and assign
                  permissions.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="groupName">Group Name *</Label>
                  <Input
                    id="groupName"
                    placeholder="Enter group name"
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                  />
                  {formErrors.name && (
                    <p className="text-sm text-red-600">{formErrors.name}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="groupDescription">Description</Label>
                  <Textarea
                    id="groupDescription"
                    placeholder="Enter group description"
                    value={newGroupDescription}
                    onChange={(e) => setNewGroupDescription(e.target.value)}
                    rows={3}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="groupType">Group Type</Label>
                  <Select
                    value={newGroupType}
                    onValueChange={(value) =>
                      setNewGroupType(value as GroupType)
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={GroupType.LOCAL}>Local</SelectItem>
                      <SelectItem value={GroupType.SYNCED}>Synced</SelectItem>
                      <SelectItem value={GroupType.DYNAMIC}>Dynamic</SelectItem>
                      <SelectItem value={GroupType.TEAM}>Team</SelectItem>
                      <SelectItem value={GroupType.PROJECT}>Project</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {formErrors.workspace && (
                  <p className="text-sm text-red-600">{formErrors.workspace}</p>
                )}

                <div className="flex space-x-2">
                  <Button
                    onClick={handleCreateUserGroup}
                    className="flex-1"
                    disabled={isCreatingUserGroup}
                  >
                    {isCreatingUserGroup ? "Creating..." : "Create Group"}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setIsCreateDialogOpen(false)}
                    className="flex-1"
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="mb-4 flex space-x-2">
        <Input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onKeyPress={(e) => e.key === "Enter" && handleSearch()}
          placeholder="Search user groups..."
          className="w-64"
        />
        <Button
          onClick={handleSearch}
          disabled={isLoadingData || !isAdmin || !hasWorkspaces}
        >
          {isLoadingData ? "Loading..." : "Search"}
        </Button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error: {error.message}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>User Groups</CardTitle>
          <CardDescription>
            {isLoadingData
              ? "Loading workspaces and user groups..."
              : !hasWorkspaces
                ? "No workspaces available - user groups require a workspace"
                : `Found ${userGroups.length} user group${userGroups.length !== 1 ? "s" : ""}`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Members</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoadingData ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8">
                    <IconComponent
                      name="Loader2"
                      className="h-4 w-4 animate-spin mr-2"
                    />
                    Loading workspaces and user groups...
                  </TableCell>
                </TableRow>
              ) : !isAdmin ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8">
                    Please authenticate to view user groups
                    <Button
                      variant="link"
                      onClick={() => setShowAuthModal(true)}
                      className="ml-2"
                    >
                      Sign In
                    </Button>
                  </TableCell>
                </TableRow>
              ) : !hasWorkspaces ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8">
                    No workspaces available. Create a workspace first to manage
                    user groups.
                  </TableCell>
                </TableRow>
              ) : userGroups.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8">
                    No user groups found
                  </TableCell>
                </TableRow>
              ) : (
                userGroups.map((group) => (
                  <TableRow key={group.id}>
                    <TableCell className="font-medium">{group.name}</TableCell>
                    <TableCell>
                      {group.description || "No description"}
                    </TableCell>
                    <TableCell>{group.member_count || 0}</TableCell>
                    <TableCell>{group.role_count || 0}</TableCell>
                    <TableCell>
                      {new Date(group.created_at).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <AuthenticationModal
        open={showAuthModal}
        onOpenChange={setShowAuthModal}
        onSuccess={() => {
          // Fetch workspaces first, then user groups will be fetched via useEffect
          fetchWorkspaces({});
        }}
      />
    </div>
  );
}
