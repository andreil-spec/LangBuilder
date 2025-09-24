// Project Management Component - Simple RBAC Projects
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
  CreateProjectData,
  useCreateProject,
} from "@/controllers/API/queries/rbac/use-create-project";
import {
  type EnhancedProjectsResponse,
  type LegacyProject,
  type RBACProjectEnhanced,
  type UnifiedProject,
  useGetEnhancedProjects,
} from "@/controllers/API/queries/rbac/use-get-enhanced-projects";
import {
  Project,
  useGetProjects,
} from "@/controllers/API/queries/rbac/use-get-projects";
import {
  useGetWorkspaces,
  Workspace,
} from "@/controllers/API/queries/rbac/use-get-workspaces";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";

interface ProjectBuilderProps {
  project?: Project;
  workspaces: Workspace[];
  onSave: (projectData: CreateProjectData) => void;
  onCancel: () => void;
  isLoading?: boolean;
}

function ProjectBuilder({
  project,
  workspaces,
  onSave,
  onCancel,
  isLoading = false,
}: ProjectBuilderProps) {
  const [name, setName] = useState(project?.name || "");
  const [description, setDescription] = useState(project?.description || "");
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState(
    project?.workspace_id || workspaces[0]?.id || "",
  );
  const [nameError, setNameError] = useState("");
  const [workspaceError, setWorkspaceError] = useState("");

  const handleSave = () => {
    let hasError = false;

    if (!name.trim()) {
      setNameError("Project name is required");
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
      });
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Project Name *</Label>
        <Input
          id="name"
          placeholder="Enter project name"
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
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          placeholder="Enter project description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
        />
      </div>

      <div className="flex space-x-2">
        <Button onClick={handleSave} className="flex-1" disabled={isLoading}>
          {isLoading ? (
            <>
              <IconComponent
                name="Loader2"
                className="h-4 w-4 animate-spin mr-2"
              />
              {project ? "Updating..." : "Creating..."}
            </>
          ) : project ? (
            "Update Project"
          ) : (
            "Create Project"
          )}
        </Button>
        <Button
          variant="outline"
          onClick={onCancel}
          className="flex-1"
          disabled={isLoading}
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}

export default function ProjectManagement() {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [showAuthModal, setShowAuthModal] = useState(false);

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // API hooks - using enhanced projects that include both RBAC and legacy
  const {
    mutate: fetchProjects,
    data: enhancedProjectsData,
    isPending: isLoadingProjects,
    error: projectsError,
  } = useGetEnhancedProjects({});

  // Keep the old projects hook for creating new projects
  const {
    mutate: fetchRBACProjects,
    data: rbacProjectsData,
    isPending: isLoadingRBACProjects,
    error: rbacProjectsError,
  } = useGetProjects({});

  const {
    mutate: fetchWorkspaces,
    data: workspacesData,
    isPending: isLoadingWorkspaces,
  } = useGetWorkspaces({});

  const { mutate: createProject, isPending: isCreatingProject } =
    useCreateProject({
      onSuccess: (project) => {
        console.log("✅ Project created successfully:", project);
        setIsCreateDialogOpen(false);
        handleFetchProjects({ search: searchTerm });
      },
      onError: (error) => {
        console.error("❌ Failed to create project:", error);
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

  // Helper function to fetch projects
  const handleFetchProjects = (params = {}) => {
    console.log("📊 Fetching projects...");
    fetchProjects(params);
  };

  const handleAuthSuccess = () => {
    console.log("🎉 Authentication successful, fetching data");
    handleFetchProjects({ search: searchTerm });
    fetchWorkspaces({});
  };

  // Fetch data when authenticated
  useEffect(() => {
    if (isAdmin) {
      handleFetchProjects({ search: searchTerm });
      fetchWorkspaces({});
    }
  }, [isAdmin]);

  // Debug authentication state changes
  useEffect(() => {
    console.log("🔄 ProjectManagement: Auth state changed:", {
      isAdmin,
    });
  }, [isAdmin]);

  const handleCreateProject = (projectData: CreateProjectData) => {
    requireAuth("create-project", () => {
      createProject(projectData);
    });
  };

  const handleSearch = () => {
    requireAuth("search-projects", () => {
      handleFetchProjects({ search: searchTerm });
    });
  };

  // Get data from API responses
  const rbacProjects = enhancedProjectsData?.rbac_projects || [];
  const legacyProjects = enhancedProjectsData?.legacy_projects || [];

  // Hide legacy projects for PRD fidelity - show only RBAC projects
  const allProjects: UnifiedProject[] = [...rbacProjects]; // Removed legacyProjects

  const workspaces = workspacesData?.workspaces || [];
  const totalCount = rbacProjects.length; // Show only RBAC count as total
  const rbacCount = enhancedProjectsData?.rbac_count || 0;
  // Legacy count hidden for PRD fidelity
  // const legacyCount = enhancedProjectsData?.legacy_count || 0;

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold flex items-center space-x-2">
            <IconComponent name="Building2" className="h-5 w-5" />
            <span>Project Management</span>
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Manage RBAC projects
          </p>
        </div>
        <div className="flex items-center space-x-2">
          {/* Project Summary */}
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <Badge variant="outline" className="text-xs">
              <IconComponent name="Building2" className="h-3 w-3 mr-1" />
              {totalCount} RBAC Projects
            </Badge>
            {/* Legacy project count hidden for PRD fidelity */}
            {/* {legacyCount > 0 && (
              <Badge variant="secondary" className="text-xs">
                <IconComponent name="FolderOpen" className="h-3 w-3 mr-1" />
                {legacyCount} Legacy
              </Badge>
            )} */}
          </div>

          {/* Authentication Status */}

          {/* Create Project Dialog */}
          <Dialog
            open={isCreateDialogOpen}
            onOpenChange={setIsCreateDialogOpen}
          >
            <DialogTrigger asChild>
              <Button disabled={!isAdmin}>
                <IconComponent name="Plus" className="h-4 w-4 mr-2" />
                Create Project
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Create New Project</DialogTitle>
                <DialogDescription>
                  Add a new RBAC project to organize your flows and
                  environments.
                </DialogDescription>
              </DialogHeader>
              <ProjectBuilder
                workspaces={workspaces}
                onSave={handleCreateProject}
                onCancel={() => setIsCreateDialogOpen(false)}
                isLoading={isCreatingProject}
              />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="mb-4 flex space-x-2 items-center">
        <Input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onKeyPress={(e) => e.key === "Enter" && handleSearch()}
          placeholder="Search projects..."
          className="w-64"
        />
        <Button
          onClick={handleSearch}
          disabled={isLoadingProjects || !isAdmin}
        >
          {isLoadingProjects ? "Searching..." : "Search"}
        </Button>
        {searchTerm && (
          <Button
            variant="outline"
            onClick={() => {
              setSearchTerm("");
              requireAuth("clear-search", () => {
                fetchProjects({ search: "" });
              });
            }}
          >
            Clear
          </Button>
        )}
      </div>

      {/* Error Display */}
      {projectsError && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error loading projects: {projectsError.message}
        </div>
      )}

      {/* Projects Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <IconComponent name="Shield" className="h-5 w-5" />
            <span>Projects</span>
          </CardTitle>
          <CardDescription>
            {isLoadingProjects
              ? "Loading projects..."
              : allProjects.length === 0
                ? "No RBAC projects found"
                : `Found ${allProjects.length} RBAC project${allProjects.length !== 1 ? "s" : ""}`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoadingProjects ? (
            <div className="text-center py-8">
              <div className="flex items-center justify-center">
                <IconComponent
                  name="Loader2"
                  className="h-4 w-4 animate-spin mr-2"
                />
                Loading projects...
              </div>
            </div>
          ) : !isAdmin ? (
            <div className="text-center py-8">
              <div className="text-gray-500">
                Please authenticate to view projects
                <Button
                  variant="link"
                  onClick={() => setShowAuthModal(true)}
                  className="ml-2"
                >
                  Sign In
                </Button>
              </div>
            </div>
          ) : allProjects.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              No RBAC projects found. Create your first RBAC project!
            </div>
          ) : (
            <div className="border rounded-lg overflow-hidden">
              <div className="max-h-96 overflow-y-auto">
                <Table>
                  <TableHeader className="sticky top-0 bg-white z-10">
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Workspace</TableHead>
                      <TableHead>Flows</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {allProjects.map((project) => {
                      const isLegacy = project.type === "legacy";
                      const legacyProject = isLegacy
                        ? (project as LegacyProject)
                        : null;
                      const rbacProject = !isLegacy
                        ? (project as RBACProjectEnhanced)
                        : null;

                      return (
                        <TableRow key={project.id}>
                          <TableCell className="font-medium">
                            <div className="flex items-center space-x-2">
                              <IconComponent
                                name={isLegacy ? "FolderOpen" : "Shield"}
                                className={`h-4 w-4 ${isLegacy ? "text-amber-600" : "text-green-600"}`}
                              />
                              <span>{project.name}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={isLegacy ? "secondary" : "default"}
                              className="text-xs"
                            >
                              {isLegacy ? "Legacy" : "RBAC"}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            {project.description || "No description"}
                          </TableCell>
                          <TableCell>
                            {isLegacy ? (
                              <Badge variant="outline" className="text-xs">
                                Legacy Folder
                              </Badge>
                            ) : (
                              <Badge variant="secondary">
                                {workspaces.find(
                                  (w) => w.id === rbacProject?.workspace_id,
                                )?.name || "Unknown"}
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>{project.flow_count || 0}</TableCell>
                          <TableCell>
                            {new Date(project.created_at).toLocaleDateString()}
                          </TableCell>
                          <TableCell>
                            {isLegacy ? (
                              <Badge
                                variant={
                                  legacyProject?.migration_status ===
                                  "completed"
                                    ? "default"
                                    : legacyProject?.migration_status ===
                                        "pending"
                                      ? "secondary"
                                      : "destructive"
                                }
                              >
                                {legacyProject?.migration_status === "completed"
                                  ? "Migrated"
                                  : legacyProject?.migration_status ===
                                      "pending"
                                    ? "Pending Migration"
                                    : "Migration Error"}
                              </Badge>
                            ) : (
                              <Badge
                                variant={
                                  rbacProject?.is_active
                                    ? "default"
                                    : "secondary"
                                }
                              >
                                {rbacProject?.is_active ? "Active" : "Inactive"}
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex space-x-1">
                              {isLegacy &&
                                legacyProject?.migration_status ===
                                  "pending" && (
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    className="text-xs px-2"
                                  >
                                    <IconComponent
                                      name="ArrowRight"
                                      className="h-3 w-3 mr-1"
                                    />
                                    Migrate
                                  </Button>
                                )}
                              <Button variant="ghost" size="sm">
                                <IconComponent
                                  name="MoreHorizontal"
                                  className="h-4 w-4"
                                />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}
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
