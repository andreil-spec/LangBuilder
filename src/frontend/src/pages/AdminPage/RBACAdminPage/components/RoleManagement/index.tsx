import { useEffect, useState } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Badge } from "@/components/ui/badge";
import { useCreateRole } from "../../../../../controllers/API/queries/rbac/use-create-role";
import { useDeleteRole } from "../../../../../controllers/API/queries/rbac/use-delete-role";
import { useGetRoles } from "../../../../../controllers/API/queries/rbac/use-get-roles";
import { useUpdateRole } from "../../../../../controllers/API/queries/rbac/use-update-role";
import { useUpdateRolePermissions } from "../../../../../controllers/API/queries/rbac/use-update-role-permissions";
import useAuthStore from "../../../../../stores/authStore";
import PermissionsModal from "./PermissionsModal";
import PermissionValidationPanel from "./PermissionValidationPanel";

export default function RoleManagement() {
  const [searchTerm, setSearchTerm] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [newRoleName, setNewRoleName] = useState("");
  const [newRoleDescription, setNewRoleDescription] = useState("");
  const [editingRole, setEditingRole] = useState<string | null>(null);
  const [editRoleName, setEditRoleName] = useState("");
  const [editRoleDescription, setEditRoleDescription] = useState("");
  const [showPermissionsModal, setShowPermissionsModal] = useState(false);
  const [selectedRoleForPermissions, setSelectedRoleForPermissions] =
    useState<any>(null);

  // Permission validation state
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);
  const [validationResults, setValidationResults] = useState<any[]>([]);
  const [isValidationValid, setIsValidationValid] = useState(true);

  // Authentication state management - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  const {
    mutate: fetchRoles,
    data: rolesData,
    isPending: isLoading,
    error,
  } = useGetRoles({
    onSuccess: (data) => {
      console.log("Roles fetched successfully:", data);
    },
    onError: (error) => {
      console.error("Failed to fetch roles:", error);
    },
  });

  const { mutate: assignPermissions, isPending: isAssigningPermissions } = useUpdateRolePermissions({
    onSuccess: (data, variables) => {
      console.log(`✅ Permissions assigned to role ${variables.role_id}:`, data);

      // Clean up form state after successful permission assignment
      setIsCreating(false);
      setNewRoleName("");
      setNewRoleDescription("");
      setSelectedPermissions([]);
      setValidationResults([]);
      setIsValidationValid(true);

      // Refresh roles list to show updated permission count
      fetchRoles({ search: searchTerm, is_active: true });
    },
    onError: (error, variables) => {
      console.error(`❌ Failed to assign permissions to role ${variables.role_id}:`, error);
      alert(`Warning: Role created but failed to assign permissions: ${error?.message || "Unknown error"}`);

      // Still clean up form state even if permission assignment failed
      setIsCreating(false);
      setNewRoleName("");
      setNewRoleDescription("");
      setSelectedPermissions([]);
      setValidationResults([]);
      setIsValidationValid(true);

      // Refresh roles list (role was still created)
      fetchRoles({ search: searchTerm, is_active: true });
    },
  });

  const { mutate: createRole, isPending: isCreatingRole } = useCreateRole({
    onSuccess: (roleData) => {
      console.log("✅ Role created successfully:", roleData);

      // If permissions were selected, assign them to the new role
      if (selectedPermissions.length > 0) {
        console.log(`🔐 Assigning ${selectedPermissions.length} permissions to role ${roleData.id}`);
        assignPermissions({
          role_id: roleData.id,
          permission_ids: selectedPermissions,
        });
      } else {
        // No permissions selected, just clean up and refresh
        console.log("ℹ️ No permissions selected, role created without permissions");
        setIsCreating(false);
        setNewRoleName("");
        setNewRoleDescription("");
        setSelectedPermissions([]);
        setValidationResults([]);
        setIsValidationValid(true);
        // Refresh roles list
        fetchRoles({ search: searchTerm, is_active: true });
      }
    },
    onError: (error) => {
      console.error("❌ Failed to create role:", error);
    },
  });

  const { mutate: updateRole, isPending: isUpdatingRole } = useUpdateRole({
    onSuccess: () => {
      setEditingRole(null);
      setEditRoleName("");
      setEditRoleDescription("");
      // Refresh roles list
      fetchRoles({ search: searchTerm, is_active: true });
    },
    onError: (error) => {
      console.error("Failed to update role:", error);
      // Reset edit state on error to prevent getting stuck
      setEditingRole(null);
      setEditRoleName("");
      setEditRoleDescription("");
    },
  });

  const { mutate: deleteRole, error: deleteError } = useDeleteRole({
    onSuccess: () => {
      console.log("Role deleted successfully");
      // Refresh roles list
      fetchRoles({ search: searchTerm, is_active: true });
    },
    onError: (error) => {
      console.error("Failed to delete role:", error);
      alert(`Failed to delete role: ${error?.message || "Unknown error"}`);
    },
  });

  useEffect(() => {
    fetchRoles({ search: searchTerm, is_active: true });
  }, []);

  // Debug authentication state changes
  useEffect(() => {
    console.log("🔄 RoleManagement: Auth state changed:", {
      isAdmin,
    });
  }, [isAdmin]);

  const handleSearch = () => {
    fetchRoles({ search: searchTerm, is_active: true });
  };

  const handleCreateRole = () => {
    if (newRoleName.trim() && isValidationValid) {
      createRole({
        name: newRoleName,
        description: newRoleDescription,
        type: "custom",
        // Note: permissions will be assigned separately after role creation
        // selectedPermissions will be handled via permission assignment API
      });
    }
  };

  const handleValidationChange = (isValid: boolean, results: any[]) => {
    setIsValidationValid(isValid);
    setValidationResults(results);
  };

  const handleEditRole = (role: any) => {
    setEditingRole(role.id);
    setEditRoleName(role.name);
    setEditRoleDescription(role.description || "");
  };

  const handleUpdateRole = () => {
    if (editingRole && editRoleName.trim()) {
      updateRole({
        role_id: editingRole,
        role: {
          name: editRoleName.trim(),
          description: editRoleDescription.trim() || undefined,
          is_active: true,
        },
      });
    }
  };

  const handleCancelEdit = () => {
    setEditingRole(null);
    setEditRoleName("");
    setEditRoleDescription("");
  };

  const handlePermissions = (role: any) => {
    console.log("🔧 RoleManagement: handlePermissions called with role:", role);
    console.log("🔐 RoleManagement auth state:", {
      isAdmin,
    });

    setSelectedRoleForPermissions(role);
    setShowPermissionsModal(true);
    console.log("✅ RoleManagement: showPermissionsModal set to true");
  };

  const handlePermissionsSave = (roleId: string, permissions: string[]) => {
    console.log(
      `✅ Parent: Permissions saved for role ${roleId}:`,
      permissions,
    );

    // Refresh roles to get updated data
    fetchRoles({ search: searchTerm, is_active: true });

    console.log("🔄 Refreshing roles list to reflect permission changes");
  };

  const handleDeleteRole = (roleId: string) => {
    console.log("handleDeleteRole called with:", roleId);
    if (confirm("Are you sure you want to delete this role?")) {
      console.log("Calling deleteRole with:", { role_id: roleId });
      deleteRole({ role_id: roleId });
    }
  };

  // Handle both API response formats
  const roles = Array.isArray(rolesData) ? rolesData : rolesData?.roles || [];

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold">Role Management</h2>
          <p className="text-sm text-gray-600 mt-1">
            Manage roles and their permissions
          </p>
        </div>
        <div className="flex items-center space-x-2">

          <button
            onClick={() => setIsCreating(true)}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            disabled={isCreatingRole || isAssigningPermissions}
          >
            {isCreatingRole ? "Creating..." : isAssigningPermissions ? "Assigning Permissions..." : "Create Role"}
          </button>
        </div>
      </div>

      {isCreating && (
        <div className="mb-6 p-4 border rounded-lg bg-gray-50">
          <h3 className="text-lg font-medium mb-4">Create New Role</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">
                Role Name
              </label>
              <input
                type="text"
                value={newRoleName}
                onChange={(e) => setNewRoleName(e.target.value)}
                className="w-full border rounded px-3 py-2"
                placeholder="Enter role name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">
                Description (Optional)
              </label>
              <textarea
                value={newRoleDescription}
                onChange={(e) => setNewRoleDescription(e.target.value)}
                className="w-full border rounded px-3 py-2"
                rows={3}
                placeholder="Enter role description"
              />
            </div>

            {/* Permission Validation Panel - Re-enabled with error handling */}
            <PermissionValidationPanel
              selectedPermissions={selectedPermissions}
              onPermissionsChange={setSelectedPermissions}
              roleName={newRoleName}
              roleDescription={newRoleDescription}
              onValidationChange={handleValidationChange}
            />

            <div className="flex space-x-2">
              <button
                onClick={handleCreateRole}
                disabled={
                  !newRoleName.trim() || isCreatingRole || isAssigningPermissions || !isValidationValid
                }
                className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
              >
                {isCreatingRole ? "Creating..." : isAssigningPermissions ? "Assigning Permissions..." : "Create Role"}
              </button>
              <button
                onClick={() => {
                  setIsCreating(false);
                  setNewRoleName("");
                  setNewRoleDescription("");
                  setSelectedPermissions([]);
                  setValidationResults([]);
                  setIsValidationValid(true);
                }}
                className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>

            {/* Validation Summary */}
            {validationResults.length > 0 && (
              <div className="mt-4 p-3 border rounded-lg bg-gray-50">
                <h4 className="font-medium text-sm mb-2">Creation Status:</h4>
                <div className="space-y-1 text-sm">
                  {validationResults.filter((r) => r.type === "error").length >
                    0 && (
                    <div className="text-red-600 flex items-center space-x-1">
                      <IconComponent name="XCircle" className="h-4 w-4" />
                      <span>
                        Role cannot be created -{" "}
                        {
                          validationResults.filter((r) => r.type === "error")
                            .length
                        }{" "}
                        error(s) must be resolved
                      </span>
                    </div>
                  )}
                  {validationResults.filter((r) => r.type === "warning")
                    .length > 0 && (
                    <div className="text-yellow-600 flex items-center space-x-1">
                      <IconComponent name="AlertTriangle" className="h-4 w-4" />
                      <span>
                        {
                          validationResults.filter((r) => r.type === "warning")
                            .length
                        }{" "}
                        warning(s) - review before proceeding
                      </span>
                    </div>
                  )}
                  {isValidationValid && selectedPermissions.length > 0 && (
                    <div className="text-green-600 flex items-center space-x-1">
                      <IconComponent name="CheckCircle" className="h-4 w-4" />
                      <span>
                        Ready to create role with {selectedPermissions.length}{" "}
                        permission{selectedPermissions.length !== 1 ? "s" : ""}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="mb-4 flex space-x-2">
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onKeyPress={(e) => e.key === "Enter" && handleSearch()}
          placeholder="Search roles..."
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
            onClick={() => {
              setSearchTerm("");
              fetchRoles({ search: "", is_active: true });
            }}
            disabled={isLoading}
            className="px-4 py-2 bg-gray-500 text-white rounded hover:bg-gray-600 disabled:opacity-50"
          >
            Clear
          </button>
        )}
        <button
          onClick={() => fetchRoles({ search: searchTerm, is_active: true })}
          disabled={isLoading}
          className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700 disabled:opacity-50"
        >
          {isLoading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error loading roles: {error.message}
        </div>
      )}

      <div className="border rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Role Name
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Description
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Assignments
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Permissions
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
                  Loading roles...
                </td>
              </tr>
            ) : roles.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  No roles found. Create your first role!
                </td>
              </tr>
            ) : (
              roles.map((role) => (
                <tr key={role.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium">
                    {editingRole === role.id ? (
                      <input
                        type="text"
                        value={editRoleName}
                        onChange={(e) => setEditRoleName(e.target.value)}
                        className="w-full border rounded px-2 py-1 text-sm"
                      />
                    ) : (
                      <>
                        {role.name}
                        {role.is_system_role && (
                          <span className="ml-2 px-2 py-1 bg-purple-100 text-purple-800 rounded text-xs">
                            System
                          </span>
                        )}
                      </>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-600">
                    {editingRole === role.id ? (
                      <input
                        type="text"
                        value={editRoleDescription}
                        onChange={(e) => setEditRoleDescription(e.target.value)}
                        className="w-full border rounded px-2 py-1 text-sm"
                        placeholder="Role description"
                      />
                    ) : (
                      role.description || "No description"
                    )}
                  </td>
                  <td className="px-4 py-3">{role.assignment_count || 0}</td>
                  <td className="px-4 py-3">{role.permission_count || 0}</td>
                  <td className="px-4 py-3">
                    <div className="flex space-x-2">
                      {editingRole === role.id ? (
                        <>
                          <button
                            onClick={handleUpdateRole}
                            disabled={!editRoleName.trim() || isUpdatingRole}
                            className="text-green-600 hover:text-green-800 text-sm disabled:opacity-50"
                          >
                            {isUpdatingRole ? "Saving..." : "Save"}
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
                          {!role.is_system_role && (
                            <button
                              onClick={() => handleEditRole(role)}
                              className="text-blue-600 hover:text-blue-800 text-sm"
                            >
                              Edit
                            </button>
                          )}
                          <button
                            onClick={() => handlePermissions(role)}
                            className="text-green-600 hover:text-green-800 text-sm"
                          >
                            Permissions
                          </button>
                          {!role.is_system_role && (
                            <button
                              onClick={() => handleDeleteRole(role.id)}
                              className="text-red-600 hover:text-red-800 text-sm"
                            >
                              Delete
                            </button>
                          )}
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

      {/* Permissions Modal */}
      <PermissionsModal
        isOpen={showPermissionsModal}
        onClose={() => {
          setShowPermissionsModal(false);
          setSelectedRoleForPermissions(null);
        }}
        role={selectedRoleForPermissions}
        onSave={handlePermissionsSave}
      />
    </div>
  );
}
