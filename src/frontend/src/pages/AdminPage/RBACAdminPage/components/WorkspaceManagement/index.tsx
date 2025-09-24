import { useEffect, useState } from "react";
import { useCreateWorkspace } from "../../../../../controllers/API/queries/rbac/use-create-workspace";
import { useDeleteWorkspace } from "../../../../../controllers/API/queries/rbac/use-delete-workspace";
import { useGetWorkspaces } from "../../../../../controllers/API/queries/rbac/use-get-workspaces";
import { useUpdateWorkspace } from "../../../../../controllers/API/queries/rbac/use-update-workspace";

export default function WorkspaceManagement() {
  const [searchTerm, setSearchTerm] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [newWorkspaceName, setNewWorkspaceName] = useState("");
  const [newWorkspaceDescription, setNewWorkspaceDescription] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [editingWorkspace, setEditingWorkspace] = useState<string | null>(null);
  const [editWorkspaceName, setEditWorkspaceName] = useState("");
  const [editWorkspaceDescription, setEditWorkspaceDescription] = useState("");

  const {
    mutate: fetchWorkspaces,
    data: workspacesData,
    isPending: isLoading,
    error,
  } = useGetWorkspaces({
    onSuccess: (data) => {
      console.log("Workspaces fetched successfully:", data);
      console.log("Number of workspaces:", data?.workspaces?.length || 0);
    },
    onError: (error) => {
      console.error("Failed to fetch workspaces:", error);
    },
  });

  const { mutate: createWorkspace, isPending: isCreatingWorkspace } =
    useCreateWorkspace({
      onSuccess: (newWorkspace) => {
        console.log("Workspace created successfully:", newWorkspace);
        setIsCreating(false);
        setNewWorkspaceName("");
        setNewWorkspaceDescription("");
        setCreateError(null);
        // Refresh workspaces list - clear search to see all workspaces including new one
        setSearchTerm("");
        // Add a small delay to ensure backend has processed the creation
        setTimeout(() => {
          fetchWorkspaces({ search: "" });
        }, 500);
      },
      onError: (error) => {
        console.error("Failed to create workspace:", error);
        // Don't show error if it's a duplicate but workspace was still created
        const errorMessage = error?.message || "Unknown error occurred";
        if (
          errorMessage.toLowerCase().includes("already exists") ||
          errorMessage.toLowerCase().includes("duplicate")
        ) {
          // Still refresh the list in case it was created despite the error
          setTimeout(() => {
            fetchWorkspaces({ search: searchTerm });
          }, 500);
          // Clear the form since it might have been created
          setIsCreating(false);
          setNewWorkspaceName("");
          setNewWorkspaceDescription("");
          setCreateError(null);
        } else {
          setCreateError(errorMessage);
        }
      },
    });

  const {
    mutate: updateWorkspace,
    isPending: isUpdatingWorkspace,
    error: updateError,
  } = useUpdateWorkspace({
    onSuccess: (data) => {
      console.log("Update workspace successful:", data);
      setEditingWorkspace(null);
      setEditWorkspaceName("");
      setEditWorkspaceDescription("");
      // Refresh workspaces list
      fetchWorkspaces({ search: searchTerm });
    },
    onError: (error) => {
      console.error("Failed to update workspace:", error);
      console.error("Update error details:", error?.response || error);
      // Reset edit state on error to prevent getting stuck
      setEditingWorkspace(null);
      setEditWorkspaceName("");
      setEditWorkspaceDescription("");
    },
  });

  const { mutate: deleteWorkspace } = useDeleteWorkspace({
    onSuccess: () => {
      // Refresh workspaces list
      fetchWorkspaces({ search: searchTerm });
    },
    onError: (error) => {
      console.error("Failed to delete workspace:", error);
    },
  });

  useEffect(() => {
    fetchWorkspaces({ search: searchTerm });
  }, []);

  const handleRefresh = () => {
    fetchWorkspaces({ search: searchTerm });
  };

  const handleClearSearch = () => {
    setSearchTerm("");
    fetchWorkspaces({ search: "" });
  };

  const handleSearch = () => {
    fetchWorkspaces({ search: searchTerm });
  };

  const handleCreateWorkspace = () => {
    if (newWorkspaceName.trim()) {
      // Clear any previous errors
      setCreateError(null);

      const trimmedName = newWorkspaceName.trim();

      // Let the backend handle duplicate validation
      createWorkspace({
        name: trimmedName,
        description: newWorkspaceDescription.trim() || undefined,
        is_active: true,
      });
    }
  };

  const handleEditWorkspace = (workspace: any) => {
    setEditingWorkspace(workspace.id);
    setEditWorkspaceName(workspace.name);
    setEditWorkspaceDescription(workspace.description || "");
  };

  const handleUpdateWorkspace = () => {
    console.log("handleUpdateWorkspace called");
    console.log("editingWorkspace:", editingWorkspace);
    console.log("editWorkspaceName:", editWorkspaceName);
    console.log("editWorkspaceDescription:", editWorkspaceDescription);

    if (editingWorkspace && editWorkspaceName.trim()) {
      console.log("Calling updateWorkspace with data:", {
        workspace_id: editingWorkspace,
        workspace: {
          name: editWorkspaceName.trim(),
          description: editWorkspaceDescription.trim() || undefined,
          is_active: true,
        },
      });

      updateWorkspace({
        workspace_id: editingWorkspace,
        workspace: {
          name: editWorkspaceName.trim(),
          description: editWorkspaceDescription.trim() || undefined,
          is_active: true,
        },
      });
    } else {
      console.log("handleUpdateWorkspace: conditions not met");
      console.log("editingWorkspace exists:", !!editingWorkspace);
      console.log(
        "editWorkspaceName.trim() exists:",
        !!editWorkspaceName.trim(),
      );
    }
  };

  const handleCancelEdit = () => {
    setEditingWorkspace(null);
    setEditWorkspaceName("");
    setEditWorkspaceDescription("");
  };

  const handleDeleteWorkspace = (workspaceId: string) => {
    if (confirm("Are you sure you want to delete this workspace?")) {
      deleteWorkspace({ workspace_id: workspaceId });
    }
  };

  const workspaces = workspacesData?.workspaces || [];

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold">Workspace Management</h2>
        <button
          onClick={() => setIsCreating(true)}
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          disabled={isCreatingWorkspace}
        >
          {isCreatingWorkspace ? "Creating..." : "Create Workspace"}
        </button>
      </div>

      {isCreating && (
        <div className="mb-6 p-4 border rounded-lg bg-gray-50">
          <h3 className="text-lg font-medium mb-4">Create New Workspace</h3>

          {createError && (
            <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
              {createError}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">
                Workspace Name
              </label>
              <input
                type="text"
                value={newWorkspaceName}
                onChange={(e) => {
                  setNewWorkspaceName(e.target.value);
                  if (createError) setCreateError(null); // Clear error when user starts typing
                }}
                className="w-full border rounded px-3 py-2"
                placeholder="Enter workspace name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">
                Description (Optional)
              </label>
              <textarea
                value={newWorkspaceDescription}
                onChange={(e) => setNewWorkspaceDescription(e.target.value)}
                className="w-full border rounded px-3 py-2"
                rows={3}
                placeholder="Enter workspace description"
              />
            </div>
            <div className="flex space-x-2">
              <button
                onClick={handleCreateWorkspace}
                disabled={!newWorkspaceName.trim() || isCreatingWorkspace}
                className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
              >
                {isCreatingWorkspace ? "Creating..." : "Create"}
              </button>
              <button
                onClick={() => {
                  setIsCreating(false);
                  setNewWorkspaceName("");
                  setNewWorkspaceDescription("");
                  setCreateError(null);
                }}
                className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {updateError && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error updating workspace: {updateError?.message || "Unknown error"}
        </div>
      )}

      <div className="mb-4 flex space-x-2">
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onKeyPress={(e) => e.key === "Enter" && handleSearch()}
          placeholder="Search workspaces..."
          className="border rounded px-3 py-2 w-64"
        />
        <button
          onClick={handleSearch}
          disabled={isLoading}
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
        >
          {isLoading ? "Searching..." : "Search"}
        </button>
        {searchTerm && (
          <button
            onClick={handleClearSearch}
            disabled={isLoading}
            className="px-4 py-2 bg-gray-500 text-white rounded hover:bg-gray-600 disabled:opacity-50"
          >
            Clear
          </button>
        )}
        <button
          onClick={handleRefresh}
          disabled={isLoading}
          className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700 disabled:opacity-50"
        >
          {isLoading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error loading workspaces: {error.message}
        </div>
      )}

      <div className="border rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Name
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Members
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Projects
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Status
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  Loading workspaces...
                </td>
              </tr>
            ) : workspaces.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  No workspaces found. Create your first workspace!
                </td>
              </tr>
            ) : (
              workspaces.map((workspace) => (
                <tr key={workspace.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium">
                    {editingWorkspace === workspace.id ? (
                      <input
                        type="text"
                        value={editWorkspaceName}
                        onChange={(e) => setEditWorkspaceName(e.target.value)}
                        className="w-full border rounded px-2 py-1 text-sm"
                      />
                    ) : (
                      workspace.name
                    )}
                  </td>
                  <td className="px-4 py-3">{workspace.member_count || 1}</td>
                  <td className="px-4 py-3">-</td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-1 rounded text-xs ${
                        workspace.is_active
                          ? "bg-green-100 text-green-800"
                          : "bg-gray-100 text-gray-800"
                      }`}
                    >
                      {workspace.is_active ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex space-x-2">
                      {editingWorkspace === workspace.id ? (
                        <>
                          <button
                            onClick={handleUpdateWorkspace}
                            disabled={
                              !editWorkspaceName.trim() || isUpdatingWorkspace
                            }
                            className="text-green-600 hover:text-green-800 text-sm disabled:opacity-50"
                          >
                            {isUpdatingWorkspace ? "Saving..." : "Save"}
                          </button>
                          <button
                            onClick={handleCancelEdit}
                            className="text-gray-600 hover:text-gray-800 text-sm"
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            onClick={() => handleEditWorkspace(workspace)}
                            className="text-blue-600 hover:text-blue-800 text-sm"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => handleDeleteWorkspace(workspace.id)}
                            className="text-red-600 hover:text-red-800 text-sm"
                          >
                            Delete
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
