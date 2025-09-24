// Environment Management Component - Real API Implementation
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
import { useCreateEnvironment } from "@/controllers/API/queries/rbac/use-create-environment";
import {
  Environment,
  useGetEnvironments,
} from "@/controllers/API/queries/rbac/use-get-environments";
import {
  Project,
  useGetProjects,
} from "@/controllers/API/queries/rbac/use-get-projects";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";

interface CreateEnvironmentData {
  name: string;
  description?: string;
  project_id: string;
  type: "development" | "staging" | "production" | "testing";
  is_default?: boolean;
  variables?: Record<string, any>;
}

interface EnvironmentBuilderProps {
  projects: Project[];
  onSave: (data: CreateEnvironmentData) => void;
  onCancel: () => void;
  isLoading?: boolean;
}

function EnvironmentBuilder({
  projects,
  onSave,
  onCancel,
  isLoading = false,
}: EnvironmentBuilderProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedProjectId, setSelectedProjectId] = useState(
    projects[0]?.id || "",
  );
  const [type, setType] = useState<
    "development" | "staging" | "production" | "testing"
  >("development");
  const [isDefault, setIsDefault] = useState(false);
  const [nameError, setNameError] = useState("");
  const [projectError, setProjectError] = useState("");

  const handleSave = () => {
    let hasError = false;

    if (!name.trim()) {
      setNameError("Environment name is required");
      hasError = true;
    } else {
      setNameError("");
    }

    if (!selectedProjectId) {
      setProjectError("Project selection is required");
      hasError = true;
    } else {
      setProjectError("");
    }

    if (!hasError) {
      onSave({
        name: name.trim(),
        description: description.trim() || undefined,
        project_id: selectedProjectId,
        type: type,
        is_default: isDefault,
        variables: {},
      });
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Environment Name *</Label>
        <Input
          id="name"
          placeholder="Enter environment name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        {nameError && <p className="text-sm text-red-600">{nameError}</p>}
      </div>

      <div className="space-y-2">
        <Label htmlFor="project">Project *</Label>
        <Select value={selectedProjectId} onValueChange={setSelectedProjectId}>
          <SelectTrigger>
            <SelectValue placeholder="Select project" />
          </SelectTrigger>
          <SelectContent>
            {projects.map((project) => (
              <SelectItem key={project.id} value={project.id}>
                {project.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {projectError && <p className="text-sm text-red-600">{projectError}</p>}
      </div>

      <div className="space-y-2">
        <Label htmlFor="type">Environment Type</Label>
        <Select value={type} onValueChange={(value) => setType(value as any)}>
          <SelectTrigger>
            <SelectValue placeholder="Select environment type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="development">Development</SelectItem>
            <SelectItem value="staging">Staging</SelectItem>
            <SelectItem value="production">Production</SelectItem>
            <SelectItem value="testing">Testing</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          placeholder="Enter environment description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
        />
      </div>

      <div className="flex items-center space-x-2">
        <input
          type="checkbox"
          id="isDefault"
          checked={isDefault}
          onChange={(e) => setIsDefault(e.target.checked)}
          className="rounded border-gray-300"
        />
        <Label htmlFor="isDefault">Set as default environment</Label>
      </div>

      <div className="flex space-x-2">
        <Button onClick={handleSave} className="flex-1" disabled={isLoading}>
          {isLoading ? (
            <>
              <IconComponent name="Loader2" className="h-4 w-4 mr-2 animate-spin" />
              Creating...
            </>
          ) : (
            "Create Environment"
          )}
        </Button>
        <Button variant="outline" onClick={onCancel} className="flex-1" disabled={isLoading}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

export default function EnvironmentManagement() {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // API hooks
  const {
    mutate: fetchEnvironments,
    data: environmentsData,
    isPending: isLoading,
    error,
  } = useGetEnvironments({
    onSuccess: (data) => console.log("✅ Environments fetched:", data),
    onError: (error) =>
      console.error("❌ Failed to fetch environments:", error),
  });

  const {
    mutate: fetchProjects,
    data: projectsData,
    isPending: isLoadingProjects,
  } = useGetProjects({
    onSuccess: (data) => console.log("✅ Projects fetched:", data),
    onError: (error) => console.error("❌ Failed to fetch projects:", error),
  });

  const { mutate: createEnvironment, isPending: isCreatingEnvironment } =
    useCreateEnvironment({
      onSuccess: (newEnvironment) => {
        console.log("✅ Environment created successfully:", newEnvironment);
        setIsCreateDialogOpen(false);
        setCreateError(null); // Clear any previous errors
        // Refresh environments list
        fetchEnvironments({ search: searchTerm });
      },
      onError: (error) => {
        console.error("❌ Failed to create environment:", error);
        // Extract meaningful error message
        let errorMessage = "Unknown error";
        if (error?.response?.data?.detail) {
          errorMessage = error.response.data.detail;
        } else if (error?.message) {
          errorMessage = error.message;
        }
        setCreateError(errorMessage);
      },
    });

  // Fetch data when authenticated
  useEffect(() => {
    if (isAdmin) {
      fetchEnvironments({ search: searchTerm });
      fetchProjects({});
    }
  }, [isAdmin]);

  const requireAuth = (action: string, callback: () => void) => {
    if (!isAdmin) {
      setShowAuthModal(true);
    } else {
      callback();
    }
  };

  const handleCreateEnvironment = (data: CreateEnvironmentData) => {
    requireAuth("create-environment", () => {
      setCreateError(null); // Clear any previous errors
      createEnvironment(data);
    });
  };

  const handleSearch = () => {
    requireAuth("search-environments", () => {
      fetchEnvironments({ search: searchTerm });
    });
  };

  // Get data from API responses
  const environments = environmentsData?.environments || [];
  const projects = projectsData?.projects || [];

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold flex items-center space-x-2">
            <IconComponent name="Settings" className="h-5 w-5" />
            <span>Environment Management</span>
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Manage deployment environments
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
                Create Environment
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Create New Environment</DialogTitle>
                <DialogDescription>
                  Create a new deployment environment for your project.
                </DialogDescription>
              </DialogHeader>
              {createError && (
                <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded-md max-h-32 overflow-y-auto">
                  <div className="flex items-center">
                    <IconComponent name="AlertTriangle" className="h-4 w-4 mr-2 flex-shrink-0" />
                    <span className="font-medium">Error:</span>
                  </div>
                  <p className="mt-1 text-sm break-words">{createError}</p>
                </div>
              )}
              <EnvironmentBuilder
                projects={projects}
                onSave={handleCreateEnvironment}
                onCancel={() => {
                  setIsCreateDialogOpen(false);
                  setCreateError(null); // Clear error when canceling
                }}
                isLoading={isCreatingEnvironment}
              />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="mb-4 flex space-x-2">
        <Input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onKeyPress={(e) => e.key === "Enter" && handleSearch()}
          placeholder="Search environments..."
          className="w-64"
        />
        <Button
          onClick={handleSearch}
          disabled={isLoading || !isAdmin}
        >
          {isLoading ? "Searching..." : "Search"}
        </Button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error: {error.message}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Environments</CardTitle>
          <CardDescription>
            {isLoading
              ? "Loading..."
              : `Found ${environments.length} environment${environments.length !== 1 ? "s" : ""}`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Project</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Deployed</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8">
                    <IconComponent
                      name="Loader2"
                      className="h-4 w-4 animate-spin mr-2"
                    />
                    Loading environments...
                  </TableCell>
                </TableRow>
              ) : !isAdmin ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8">
                    Please authenticate to view environments
                    <Button
                      variant="link"
                      onClick={() => setShowAuthModal(true)}
                      className="ml-2"
                    >
                      Sign In
                    </Button>
                  </TableCell>
                </TableRow>
              ) : environments.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8">
                    No environments found
                  </TableCell>
                </TableRow>
              ) : (
                environments.map((env) => (
                  <TableRow key={env.id}>
                    <TableCell className="font-medium">{env.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{env.type}</Badge>
                    </TableCell>
                    <TableCell>{env.project_id}</TableCell>
                    <TableCell>
                      <Badge
                        variant={env.is_active ? "default" : "destructive"}
                      >
                        {env.is_active ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {env.last_deployed_at
                        ? new Date(env.last_deployed_at).toLocaleDateString()
                        : "Never"}
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
          fetchEnvironments({ search: searchTerm });
          fetchProjects({});
        }}
      />
    </div>
  );
}
