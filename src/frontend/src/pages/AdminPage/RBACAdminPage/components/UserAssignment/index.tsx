import { useEffect, useState } from "react";
import { useCreateRoleAssignment } from "../../../../../controllers/API/queries/rbac/use-create-role-assignment";
import { useDeleteRoleAssignment } from "../../../../../controllers/API/queries/rbac/use-delete-role-assignment";
import { useGetRoleAssignments } from "../../../../../controllers/API/queries/rbac/use-get-role-assignments";
import { useGetRoles } from "../../../../../controllers/API/queries/rbac/use-get-roles";
import { useGetWorkspaces } from "../../../../../controllers/API/queries/rbac/use-get-workspaces";

export default function UserAssignment() {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedWorkspace, setSelectedWorkspace] = useState("");
  const [isAssigning, setIsAssigning] = useState(false);
  const [newAssignment, setNewAssignment] = useState({
    user_id: "",
    role_id: "",
    workspace_id: "",
  });

  const {
    mutate: fetchAssignments,
    data: assignmentsData,
    isPending: isLoading,
    error,
  } = useGetRoleAssignments({
    onSuccess: (data) => {
      console.log("Role assignments fetched successfully:", data);
    },
    onError: (error) => {
      console.error("Failed to fetch role assignments:", error);
    },
  });

  const { mutate: fetchWorkspaces, data: workspacesData } = useGetWorkspaces();
  const { mutate: fetchRoles, data: rolesData } = useGetRoles();

  const { mutate: createAssignment, isPending: isCreatingAssignment } =
    useCreateRoleAssignment({
      onSuccess: () => {
        setIsAssigning(false);
        setNewAssignment({ user_id: "", role_id: "", workspace_id: "" });
        // Refresh assignments list
        fetchAssignments({ workspace_id: selectedWorkspace });
      },
      onError: (error) => {
        console.error("Failed to create role assignment:", error);
      },
    });

  const { mutate: deleteAssignment } = useDeleteRoleAssignment({
    onSuccess: () => {
      // Refresh assignments list
      fetchAssignments({ workspace_id: selectedWorkspace });
    },
    onError: (error) => {
      console.error("Failed to delete role assignment:", error);
    },
  });

  useEffect(() => {
    fetchWorkspaces({});
    fetchRoles({});
    if (selectedWorkspace) {
      fetchAssignments({ workspace_id: selectedWorkspace });
    }
  }, [selectedWorkspace]);

  const handleCreateAssignment = () => {
    if (
      newAssignment.user_id &&
      newAssignment.role_id &&
      newAssignment.workspace_id
    ) {
      createAssignment({
        user_id: newAssignment.user_id,
        role_id: newAssignment.role_id,
        workspace_id: newAssignment.workspace_id,
        assignment_type: "user",
        scope_type: "workspace",
      });
    }
  };

  const handleDeleteAssignment = (assignmentId: string) => {
    if (confirm("Are you sure you want to remove this role assignment?")) {
      deleteAssignment({ assignment_id: assignmentId });
    }
  };

  // Handle both API response formats
  const assignments = Array.isArray(assignmentsData)
    ? assignmentsData
    : assignmentsData?.assignments || [];
  const workspaces = Array.isArray(workspacesData)
    ? workspacesData
    : workspacesData?.workspaces || [];
  const roles = Array.isArray(rolesData) ? rolesData : rolesData?.roles || [];

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold">User Assignments</h2>
        <button
          onClick={() => setIsAssigning(true)}
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          disabled={isCreatingAssignment}
        >
          {isCreatingAssignment ? "Assigning..." : "Assign Role"}
        </button>
      </div>

      {isAssigning && (
        <div className="mb-6 p-4 border rounded-lg bg-gray-50">
          <h3 className="text-lg font-medium mb-4">Create Role Assignment</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">User ID</label>
              <input
                type="text"
                value={newAssignment.user_id}
                onChange={(e) =>
                  setNewAssignment((prev) => ({
                    ...prev,
                    user_id: e.target.value,
                  }))
                }
                className="w-full border rounded px-3 py-2"
                placeholder="Enter user ID"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">
                Workspace
              </label>
              <select
                value={newAssignment.workspace_id}
                onChange={(e) =>
                  setNewAssignment((prev) => ({
                    ...prev,
                    workspace_id: e.target.value,
                  }))
                }
                className="w-full border rounded px-3 py-2"
              >
                <option value="">Select Workspace</option>
                {workspaces.map((workspace) => (
                  <option key={workspace.id} value={workspace.id}>
                    {workspace.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Role</label>
              <select
                value={newAssignment.role_id}
                onChange={(e) =>
                  setNewAssignment((prev) => ({
                    ...prev,
                    role_id: e.target.value,
                  }))
                }
                className="w-full border rounded px-3 py-2"
              >
                <option value="">Select Role</option>
                {roles.map((role) => (
                  <option key={role.id} value={role.id}>
                    {role.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex space-x-2">
              <button
                onClick={handleCreateAssignment}
                disabled={
                  !newAssignment.user_id ||
                  !newAssignment.role_id ||
                  !newAssignment.workspace_id ||
                  isCreatingAssignment
                }
                className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
              >
                Assign
              </button>
              <button
                onClick={() => {
                  setIsAssigning(false);
                  setNewAssignment({
                    user_id: "",
                    role_id: "",
                    workspace_id: "",
                  });
                }}
                className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="flex space-x-4 mb-4">
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search users..."
          className="border rounded px-3 py-2 w-64"
        />
        <select
          value={selectedWorkspace}
          onChange={(e) => setSelectedWorkspace(e.target.value)}
          className="border rounded px-3 py-2"
        >
          <option value="">All Workspaces</option>
          {workspaces.map((workspace) => (
            <option key={workspace.id} value={workspace.id}>
              {workspace.name}
            </option>
          ))}
        </select>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error loading assignments: {error.message}
        </div>
      )}

      <div className="border rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                User
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Role
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Workspace
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Status
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Expires
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                  Loading assignments...
                </td>
              </tr>
            ) : assignments.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                  {selectedWorkspace
                    ? "No role assignments found in this workspace."
                    : "Select a workspace to view role assignments."}
                </td>
              </tr>
            ) : (
              assignments.map((assignment) => (
                <tr key={assignment.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium">
                    {assignment.user_name || assignment.user_id}
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">
                      {assignment.role_name}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {assignment.workspace_name || "Global"}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-1 rounded text-xs ${
                        assignment.is_active
                          ? "bg-green-100 text-green-800"
                          : "bg-gray-100 text-gray-800"
                      }`}
                    >
                      {assignment.is_active ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-600">
                    {assignment.valid_until
                      ? new Date(assignment.valid_until).toLocaleDateString()
                      : "Never"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex space-x-2">
                      <button className="text-blue-600 hover:text-blue-800 text-sm">
                        Edit
                      </button>
                      <button
                        onClick={() => handleDeleteAssignment(assignment.id)}
                        className="text-red-600 hover:text-red-800 text-sm"
                      >
                        Remove
                      </button>
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
