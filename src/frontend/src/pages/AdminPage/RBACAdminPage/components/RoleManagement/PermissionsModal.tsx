import { useEffect, useState } from "react";
import {
  type Permission,
  useGetPermissions,
} from "../../../../../controllers/API/queries/rbac/use-get-permissions";
import { useGetRolePermissions } from "../../../../../controllers/API/queries/rbac/use-get-role-permissions";
import { useUpdateRolePermissions } from "../../../../../controllers/API/queries/rbac/use-update-role-permissions";
import useAuthStore from "../../../../../stores/authStore";
// Note: AuthenticationModal component needs to be created
// import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";

interface PermissionsModalProps {
  isOpen: boolean;
  onClose: () => void;
  role: {
    id: string;
    name: string;
    permissions?: string[];
  } | null;
  onSave: (roleId: string, permissions: string[]) => void;
}

export default function PermissionsModal({
  isOpen,
  onClose,
  role,
  onSave,
}: PermissionsModalProps) {
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [permissions, setPermissions] = useState<Permission[]>([]);

  // Authentication state
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // API hooks
  const {
    mutate: fetchPermissions,
    data: permissionsData,
    isPending: isLoadingPermissions,
    error: permissionsError,
  } = useGetPermissions({
    onSuccess: (data) => {
      console.log("✅ Permissions fetched successfully from API:", data);
      setPermissions(data || []);
    },
    onError: (error) => {
      console.error("❌ Failed to fetch permissions from API:", error);
      setPermissions([]);
    },
  });

  // Get role's current permissions
  const {
    mutate: fetchRolePermissions,
    data: rolePermissionsData,
    isPending: isLoadingRolePermissions,
  } = useGetRolePermissions({
    onSuccess: (data) => {
      console.log("Role permissions fetched successfully:", data);
      const permissionIds = data.map((permission) => permission.id);
      console.log("Setting selectedPermissions to:", permissionIds);
      setSelectedPermissions(permissionIds);
    },
    onError: (error) => {
      console.error("Failed to fetch role permissions:", error);
      // Reset to empty state on error
      setSelectedPermissions([]);
    },
  });

  // Update role permissions
  const { mutate: updatePermissions, isPending: isUpdatingPermissions } =
    useUpdateRolePermissions({
      onSuccess: (data) => {
        console.log("✅ Role permissions updated successfully:", data);
        const actualCount =
          data?.permission_count ?? selectedPermissions.length;
        alert(
          `✅ Permissions updated successfully! (${actualCount} permissions selected)`,
        );
        onSave(role!.id, selectedPermissions);
        onClose();
      },
      onError: (error) => {
        console.error("❌ Failed to update role permissions:", error);
        alert(
          `❌ Failed to update permissions: ${error.message || "Unknown error"}`,
        );
      },
    });

  console.log("PermissionsModal render - isOpen:", isOpen, "role:", role);

  // Authentication helper
  const requireAuth = (action: string, callback: () => void) => {
    console.log("🔐 PermissionsModal auth check:", {
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

  const handleAuthSuccess = () => {
    console.log(
      "🎉 Authentication successful in PermissionsModal, executing pending action:",
      pendingAction,
    );

    setTimeout(() => {
      if (pendingAction === "fetch-permissions") {
        fetchPermissions({
          limit: 1000,
          workspace_id: "default", // TODO: Get actual workspace ID from context
        });
        if (role) {
          fetchRolePermissions({ roleId: role.id });
        }
      }
      setPendingAction(null);
    }, 100);
  };

  // Handle escape key to close modal
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && isOpen) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "hidden"; // Prevent background scroll
    }

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "unset";
    };
  }, [isOpen, onClose]);

  // Fetch permissions when modal opens (with authentication check)
  useEffect(() => {
    if (isOpen && role) {
      console.log(
        "🔍 Permissions modal opened for role:",
        role.id,
        "Auth state:",
        isAdmin,
      );

      requireAuth("fetch-permissions", () => {
        fetchPermissions({
          limit: 1000,
          workspace_id: "default", // TODO: Get actual workspace ID from context
        });
        fetchRolePermissions({ roleId: role.id });
      });

      // TODO: Don't reset until we can load existing permissions properly
      // setSelectedPermissions([]);
    }
  }, [isOpen, role?.id, isAdmin]);

  const handlePermissionToggle = (permissionId: string) => {
    console.log("🔄 Permission toggle called for:", permissionId);
    console.log("Current selectedPermissions:", selectedPermissions);

    setSelectedPermissions((prev) => {
      const newSelection = prev.includes(permissionId)
        ? prev.filter((id) => id !== permissionId)
        : [...prev, permissionId];

      console.log("New selectedPermissions:", newSelection);
      return newSelection;
    });
  };

  const handleSave = () => {
    if (!role) return;

    requireAuth("update-permissions", () => {
      updatePermissions({
        role_id: role.id,
        permission_ids: selectedPermissions,
      });
    });
  };

  if (!isOpen) return null;

  const filteredPermissions = permissions.filter(
    (permission) =>
      permission.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      permission.description
        ?.toLowerCase()
        .includes(searchTerm.toLowerCase()) ||
      permission.code?.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  const groupedPermissions = filteredPermissions.reduce(
    (acc, permission) => {
      const category = permission.category || "Uncategorized";
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push(permission);
      return acc;
    },
    {} as Record<string, Permission[]>,
  );

  return (
    <>
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] flex flex-col">
          <div className="p-6 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-gray-900">
                  Manage Permissions
                </h2>
                <p className="text-sm text-gray-600 mt-1">
                  Configure permissions for role:{" "}
                  <span className="font-medium">{role?.name}</span>
                </p>

                {/* Show error if permissions failed to load */}
                {permissionsError && (
                  <div className="mt-2 px-3 py-2 bg-red-100 border border-red-400 rounded-md">
                    <p className="text-sm text-red-800">
                      ❌ <strong>Error:</strong> Failed to load permissions
                      data.
                      {permissionsError.message &&
                        ` ${permissionsError.message}`}
                    </p>
                  </div>
                )}
              </div>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-gray-600 text-2xl"
              >
                ×
              </button>
            </div>
          </div>

          <div className="p-6 flex-1 overflow-hidden">
            <div className="mb-4">
              <input
                type="text"
                placeholder="Search permissions..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            <div className="flex-1 overflow-y-auto max-h-96">
              {isLoadingPermissions || isLoadingRolePermissions ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-gray-500">Loading permissions...</div>
                </div>
              ) : !isAdmin ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-gray-500">
                    Please authenticate to view permissions
                    <button
                      onClick={() => setShowAuthModal(true)}
                      className="ml-2 text-blue-600 hover:text-blue-800 underline"
                    >
                      Sign In
                    </button>
                  </div>
                </div>
              ) : permissions.length === 0 ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-gray-500">
                    {permissionsError
                      ? "Failed to load permissions"
                      : "No permissions available"}
                  </div>
                </div>
              ) : (
                <div className="space-y-6">
                  {Object.entries(groupedPermissions).map(
                    ([category, categoryPermissions]) => (
                      <div key={category}>
                        <h3 className="text-sm font-medium text-gray-900 mb-3 border-b border-gray-200 pb-1">
                          {category}
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {categoryPermissions.map((permission) => (
                            <div
                              key={permission.id}
                              className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                                selectedPermissions.includes(permission.id)
                                  ? "border-blue-500 bg-blue-50"
                                  : "border-gray-200 hover:border-gray-300"
                              } ${
                                permission.is_dangerous
                                  ? "border-l-4 border-l-red-500"
                                  : ""
                              }`}
                              onClick={() =>
                                handlePermissionToggle(permission.id)
                              }
                            >
                              <div className="flex items-start justify-between">
                                <div className="flex-1">
                                  <div className="flex items-center space-x-2">
                                    <input
                                      type="checkbox"
                                      checked={selectedPermissions.includes(
                                        permission.id,
                                      )}
                                      onChange={(e) => {
                                        e.stopPropagation();
                                        handlePermissionToggle(permission.id);
                                      }}
                                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                    />
                                    <div>
                                      <h4 className="text-sm font-medium text-gray-900">
                                        {permission.name}
                                      </h4>
                                      {permission.code && (
                                        <p className="text-xs text-gray-500 font-mono">
                                          {permission.code}
                                        </p>
                                      )}
                                    </div>
                                  </div>
                                  {permission.description && (
                                    <p className="text-sm text-gray-600 mt-1 ml-6">
                                      {permission.description}
                                    </p>
                                  )}
                                </div>
                                <div className="flex space-x-1 ml-2">
                                  {permission.is_dangerous && (
                                    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                      Dangerous
                                    </span>
                                  )}
                                  {permission.requires_mfa && (
                                    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                      MFA Required
                                    </span>
                                  )}
                                  {permission.is_system && (
                                    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                                      System
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ),
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="p-6 border-t border-gray-200 flex justify-between items-center">
            <div className="text-sm text-gray-600">
              {selectedPermissions.length} permission
              {selectedPermissions.length !== 1 ? "s" : ""} selected
            </div>
            <div className="flex space-x-3">
              <button
                onClick={onClose}
                className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={
                  isLoadingPermissions ||
                  isUpdatingPermissions ||
                  !!permissionsError
                }
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isUpdatingPermissions
                  ? "Saving..."
                  : permissionsError
                    ? "Cannot Save - Error Loading Data"
                    : "Save Permissions"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* <AuthenticationModal
        open={showAuthModal}
        onOpenChange={setShowAuthModal}
        onSuccess={handleAuthSuccess}
      /> */}
    </>
  );
}
