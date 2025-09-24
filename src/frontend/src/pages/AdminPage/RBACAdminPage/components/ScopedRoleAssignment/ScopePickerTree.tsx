// ScopePickerTree - Hierarchical scope selector with PRD-compliant hierarchy
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
import { useGetEnvironments } from "@/controllers/API/queries/rbac/use-get-environments";
import { useGetProjects } from "@/controllers/API/queries/rbac/use-get-projects";
import { useGetWorkspaces } from "@/controllers/API/queries/rbac/use-get-workspaces";
import useAuthStore from "@/stores/authStore";
import type { ScopeHierarchy } from "./index";

interface ScopePickerTreeProps {
  onScopeSelect: (scope: ScopeHierarchy | null) => void;
  selectedScope: ScopeHierarchy | null;
}

interface ScopeNode {
  id: string;
  name: string;
  type: "workspace" | "project" | "environment" | "flow" | "component";
  description?: string;
  parent_id?: string;
  children: ScopeNode[];
  expanded: boolean;
  selected: boolean;
  permissions_inherited?: string[];
}

// PRD-compliant scope hierarchy: Workspace > Project > Environment > Flow > Component
const SCOPE_HIERARCHY = {
  workspace: { rank: 1, icon: "Building", color: "blue" },
  project: { rank: 2, icon: "Folder", color: "green" },
  environment: { rank: 3, icon: "Settings", color: "orange" },
  flow: { rank: 4, icon: "GitBranch", color: "purple" },
  component: { rank: 5, icon: "Box", color: "red" },
};

export default function ScopePickerTree({
  onScopeSelect,
  selectedScope,
}: ScopePickerTreeProps) {
  const [scopeTree, setScopeTree] = useState<ScopeNode[]>([]);
  const [allScopeItems, setAllScopeItems] = useState<ScopeNode[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [loadingChildren, setLoadingChildren] = useState<Set<string>>(
    new Set(),
  );

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // API hooks for lazy loading scope data
  const {
    mutate: fetchWorkspaces,
    data: workspacesData,
    isPending: isLoadingWorkspaces,
    isSuccess: isWorkspacesSuccess,
    isError: isWorkspacesError,
    error: workspacesError,
    // @ts-ignore - Temporary suppress for testing
  } = useGetWorkspaces();

  const {
    mutate: fetchProjects,
    data: projectsData,
    isPending: isLoadingProjects,
    isSuccess: isProjectsSuccess,
    isError: isProjectsError,
    error: projectsError,
    // @ts-ignore - Temporary suppress for testing
  } = useGetProjects();

  const {
    mutate: fetchEnvironments,
    data: environmentsData,
    isPending: isLoadingEnvironments,
    isSuccess: isEnvironmentsSuccess,
    isError: isEnvironmentsError,
    error: environmentsError,
    // @ts-ignore - Temporary suppress for testing
  } = useGetEnvironments();

  // Handle workspaces success
  useEffect(() => {
    if (isWorkspacesSuccess && workspacesData) {
      console.log("✅ Workspaces fetched:", workspacesData);
      addScopeItems(workspacesData.workspaces || [], "workspace");
    }
  }, [isWorkspacesSuccess, workspacesData]);

  // Handle projects success
  useEffect(() => {
    if (isProjectsSuccess && projectsData) {
      console.log("✅ Projects fetched:", projectsData);
      addScopeItems(projectsData.projects || [], "project");
    }
  }, [isProjectsSuccess, projectsData]);

  // Handle environments success
  useEffect(() => {
    if (isEnvironmentsSuccess && environmentsData) {
      console.log("✅ Environments fetched:", environmentsData);
      addScopeItems(environmentsData.environments || [], "environment");
    }
  }, [isEnvironmentsSuccess, environmentsData]);

  // Handle errors
  useEffect(() => {
    if (isWorkspacesError && workspacesError) {
      console.error("❌ Failed to fetch workspaces:", workspacesError);
    }
  }, [isWorkspacesError, workspacesError]);

  useEffect(() => {
    if (isProjectsError && projectsError) {
      console.error("❌ Failed to fetch projects:", projectsError);
    }
  }, [isProjectsError, projectsError]);

  useEffect(() => {
    if (isEnvironmentsError && environmentsError) {
      console.error("❌ Failed to fetch environments:", environmentsError);
    }
  }, [isEnvironmentsError, environmentsError]);

  // Load ALL scope data from multiple sources
  useEffect(() => {
    console.log(
      "🔄 ScopePickerTree: Loading all scope data, isAdmin:",
      isAdmin,
    );

    if (isAdmin) {
      // Fetch all types of scopes concurrently
      console.log("🔄 ScopePickerTree: Fetching real data from all scope APIs");

      // Fetch workspaces (rank 1)
      fetchWorkspaces({});

      // Fetch projects (rank 2)
      fetchProjects({});

      // Fetch environments (rank 3)
      fetchEnvironments({});

      // TODO: Add flows (rank 4) and components (rank 5) when APIs are available
    }
  }, [isAdmin]);

  // Add scope items to the unified list
  const addScopeItems = (
    items: any[],
    type: "workspace" | "project" | "environment" | "flow" | "component",
  ) => {
    const scopeItems: ScopeNode[] = items.map((item) => ({
      id: item.id,
      name: item.name,
      type,
      description: item.description,
      children: [],
      expanded: false,
      selected: false,
      permissions_inherited: [],
      parent_id:
        item.workspace_id ||
        item.project_id ||
        item.environment_id ||
        item.flow_id,
    }));

    setAllScopeItems((prev) => {
      // Remove existing items of this type and add new ones
      const filtered = prev.filter((item) => item.type !== type);
      return [...filtered, ...scopeItems].sort((a, b) => {
        // Sort by rank first, then by name
        const rankA = SCOPE_HIERARCHY[a.type].rank;
        const rankB = SCOPE_HIERARCHY[b.type].rank;
        if (rankA !== rankB) return rankA - rankB;
        return a.name.localeCompare(b.name);
      });
    });
  };

  // Build initial tree structure with workspaces
  const buildInitialTree = (workspaces: any[]) => {
    console.log(
      "🔧 ScopePickerTree: Building initial tree with workspaces:",
      workspaces,
    );
    const tree: ScopeNode[] = workspaces.map((workspace) => ({
      id: workspace.id,
      name: workspace.name,
      type: "workspace",
      description: workspace.description,
      children: [],
      expanded: false,
      selected: false,
      permissions_inherited: [],
    }));
    console.log("🔧 ScopePickerTree: Setting scope tree:", tree);
    setScopeTree(tree);
  };

  // Update tree with projects (lazy loaded)
  const updateTreeWithProjects = (projects: any[]) => {
    setScopeTree((prevTree) => {
      const newTree = [...prevTree];

      projects.forEach((project) => {
        const workspaceNode = newTree.find(
          (w) => w.id === project.workspace_id,
        );
        if (workspaceNode) {
          const projectNode: ScopeNode = {
            id: project.id,
            name: project.name,
            type: "project",
            description: project.description,
            parent_id: project.workspace_id,
            children: [],
            expanded: false,
            selected: false,
            permissions_inherited: [],
          };

          // Add if not already exists
          if (!workspaceNode.children.find((p) => p.id === project.id)) {
            workspaceNode.children.push(projectNode);
          }
        }
      });

      return newTree;
    });
  };

  // Update tree with environments (lazy loaded)
  const updateTreeWithEnvironments = (environments: any[]) => {
    setScopeTree((prevTree) => {
      const newTree = [...prevTree];

      environments.forEach((env) => {
        // Find the project node this environment belongs to
        for (const workspace of newTree) {
          const project = workspace.children.find(
            (p) => p.id === env.project_id,
          );
          if (project) {
            const envNode: ScopeNode = {
              id: env.id,
              name: env.name,
              type: "environment",
              description: `${env.type} environment`,
              parent_id: env.project_id,
              children: [],
              expanded: false,
              selected: false,
              permissions_inherited: [],
            };

            // Add if not already exists
            if (!project.children.find((e) => e.id === env.id)) {
              project.children.push(envNode);
            }
            break;
          }
        }
      });

      return newTree;
    });
  };

  // Handle node expansion and lazy loading
  const handleNodeToggle = async (node: ScopeNode) => {
    const newExpanded = new Set(expandedNodes);

    if (expandedNodes.has(node.id)) {
      // Collapse
      newExpanded.delete(node.id);
    } else {
      // Expand and potentially load children
      newExpanded.add(node.id);

      // Lazy load children if needed
      if (node.children.length === 0) {
        setLoadingChildren((prev) => new Set(prev).add(node.id));

        try {
          if (node.type === "workspace") {
            // Load projects for this workspace
            fetchProjects({
              workspace_id: node.id,
            });
          } else if (node.type === "project") {
            // Load environments for this project
            fetchEnvironments({
              project_id: node.id,
              limit: 100,
            });
          }
          // TODO: Add flow and component loading
        } finally {
          setLoadingChildren((prev) => {
            const newSet = new Set(prev);
            newSet.delete(node.id);
            return newSet;
          });
        }
      }
    }

    setExpandedNodes(newExpanded);
  };

  // Handle scope selection for flat list
  const handleScopeSelect = (item: ScopeNode) => {
    const scope: ScopeHierarchy = {
      type: item.type,
      id: item.id,
      name: item.name,
      parent: item.parent_id ? findParentScopeItem(item.parent_id) : undefined,
      children: [], // No children in flat selection
    };
    onScopeSelect(scope);
  };

  const findParentScopeItem = (
    parentId: string,
  ): ScopeHierarchy | undefined => {
    const parent = allScopeItems.find((item) => item.id === parentId);
    if (!parent) return undefined;

    return {
      type: parent.type,
      id: parent.id,
      name: parent.name,
      parent: parent.parent_id
        ? findParentScopeItem(parent.parent_id)
        : undefined,
      children: [],
    };
  };

  // Render individual scope item in flat list
  const renderScopeItem = (item: ScopeNode): JSX.Element => {
    const isSelected = selectedScope?.id === item.id;
    const hierarchyInfo = SCOPE_HIERARCHY[item.type];

    return (
      <div
        key={item.id}
        className={`p-3 rounded-lg border cursor-pointer transition-all duration-200 ${
          isSelected
            ? "border-blue-500 bg-blue-50"
            : "border-gray-200 hover:border-gray-300 hover:bg-gray-50"
        }`}
        onClick={() => handleScopeSelect(item)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-full bg-${hierarchyInfo.color}-100`}>
              <IconComponent
                name={hierarchyInfo.icon}
                className={`h-4 w-4 text-${hierarchyInfo.color}-600`}
              />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h4 className="font-medium text-gray-900">{item.name}</h4>
                <Badge variant="outline" className="text-xs">
                  Rank {hierarchyInfo.rank}
                </Badge>
              </div>
              {item.description && (
                <p className="text-sm text-gray-500 mt-1">{item.description}</p>
              )}
            </div>
          </div>
          <div className="text-xs text-gray-400 capitalize">{item.type}</div>
        </div>
      </div>
    );
  };

  // Render individual scope node
  const renderScopeNode = (node: ScopeNode, depth: number = 0): JSX.Element => {
    const isExpanded = expandedNodes.has(node.id);
    const isLoading = loadingChildren.has(node.id);
    const isSelected = selectedScope?.id === node.id;
    const hasChildren = node.children.length > 0;
    const hierarchyInfo = SCOPE_HIERARCHY[node.type];

    return (
      <div key={node.id} className="w-full">
        <div
          className={`flex items-center space-x-2 p-2 rounded cursor-pointer transition-colors ${
            isSelected
              ? "bg-blue-100 border border-blue-300"
              : "hover:bg-gray-50"
          }`}
          style={{ paddingLeft: `${depth * 20 + 8}px` }}
          onClick={() => handleScopeSelect(node)}
        >
          {/* Expand/Collapse Button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleNodeToggle(node);
            }}
            className="w-4 h-4 flex items-center justify-center hover:bg-gray-200 rounded"
            disabled={
              !hasChildren &&
              node.type !== "workspace" &&
              node.type !== "project"
            }
          >
            {isLoading ? (
              <IconComponent name="Loader2" className="h-3 w-3 animate-spin" />
            ) : hasChildren ||
              node.type === "workspace" ||
              node.type === "project" ? (
              <IconComponent
                name={isExpanded ? "ChevronDown" : "ChevronRight"}
                className="h-3 w-3"
              />
            ) : (
              <div className="w-3 h-3" />
            )}
          </button>

          {/* Icon */}
          <IconComponent
            name={hierarchyInfo.icon as any}
            className={`h-4 w-4 text-${hierarchyInfo.color}-500`}
          />

          {/* Node Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center space-x-2">
              <span className="font-medium text-sm">{node.name}</span>
              <Badge variant="outline" className="text-xs">
                {node.type}
              </Badge>
            </div>
            {node.description && (
              <p className="text-xs text-gray-500 truncate">
                {node.description}
              </p>
            )}
          </div>

          {/* Hierarchy Rank Indicator */}
          <div className="flex items-center space-x-1">
            <span
              className={`text-xs px-2 py-1 rounded bg-${hierarchyInfo.color}-100 text-${hierarchyInfo.color}-700`}
            >
              Rank {hierarchyInfo.rank}
            </span>
            {isSelected && (
              <IconComponent name="Check" className="h-4 w-4 text-blue-600" />
            )}
          </div>
        </div>

        {/* Children */}
        {isExpanded && hasChildren && (
          <div className="mt-1">
            {node.children.map((child) => renderScopeNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  // Filter tree based on search
  // Filter flat list of scope items
  const filteredScopeItems = allScopeItems.filter((item) => {
    if (!searchTerm) return true;

    return (
      item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.type.toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  // Debug logging
  console.log("🔍 ScopePickerTree: Debug info:", {
    allScopeItemsLength: allScopeItems.length,
    searchTerm,
    filteredScopeItemsLength: filteredScopeItems.length,
    isLoadingWorkspaces,
    isLoadingProjects,
    isLoadingEnvironments,
    isAdmin,
  });

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <IconComponent name="Target" className="h-5 w-5" />
          <span>Available Scopes</span>
        </CardTitle>
        <CardDescription>
          Select any scope (rank 1-5) for role assignment. All available
          components from the system are listed below.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Search */}
        <div className="relative">
          <IconComponent
            name="Search"
            className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400"
          />
          <Input
            placeholder="Search scopes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>

        {/* Hierarchy Legend */}
        <div className="flex flex-wrap gap-2 p-3 bg-gray-50 rounded">
          {Object.entries(SCOPE_HIERARCHY).map(([type, info]) => (
            <div key={type} className="flex items-center space-x-1">
              <IconComponent
                name={info.icon as any}
                className={`h-3 w-3 text-${info.color}-500`}
              />
              <span className="text-xs capitalize">{type}</span>
              <span className="text-xs text-gray-500">(Rank {info.rank})</span>
            </div>
          ))}
        </div>

        {/* Selected Scope Display */}
        {selectedScope && (
          <Card className="border-blue-200 bg-blue-50">
            <CardContent className="p-3">
              <div className="flex items-center space-x-2">
                <IconComponent
                  name="Target"
                  className="h-4 w-4 text-blue-600"
                />
                <span className="font-medium text-sm">Selected Scope:</span>
                <Badge variant="outline" className="bg-white">
                  {selectedScope.type}: {selectedScope.name}
                </Badge>
              </div>
              {selectedScope.parent && (
                <p className="text-xs text-blue-600 mt-1">
                  Parent: {selectedScope.parent.type}:{" "}
                  {selectedScope.parent.name}
                </p>
              )}
            </CardContent>
          </Card>
        )}

        {/* Scope List */}
        <div className="border rounded-lg max-h-[500px] overflow-y-auto">
          {isLoadingWorkspaces || isLoadingProjects || isLoadingEnvironments ? (
            <div className="flex items-center justify-center py-8">
              <IconComponent
                name="Loader2"
                className="h-6 w-6 animate-spin mr-2"
              />
              <span>Loading scopes from all ranks...</span>
            </div>
          ) : filteredScopeItems.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-gray-500">
              <IconComponent name="Search" className="h-6 w-6 mr-2" />
              <span>
                {allScopeItems.length === 0
                  ? "No scopes available"
                  : "No scopes found matching search"}
              </span>
            </div>
          ) : (
            <div className="p-2 space-y-1">
              {filteredScopeItems.map((item) => renderScopeItem(item))}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex justify-between items-center pt-2 border-t">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setExpandedNodes(new Set());
              onScopeSelect(null);
            }}
          >
            <IconComponent name="RotateCcw" className="h-4 w-4 mr-1" />
            Reset
          </Button>

          <div className="text-xs text-gray-500">
            {selectedScope
              ? `Selected: ${selectedScope.type} level (Rank ${SCOPE_HIERARCHY[selectedScope.type].rank})`
              : "Select a scope to continue"}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
