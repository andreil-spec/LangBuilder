// ScopedRoleAssignmentModal - Enhanced role assignment with hierarchical scope support
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
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useCreateRoleAssignment } from "@/controllers/API/queries/rbac/use-create-role-assignment";
import { useGetRoles } from "@/controllers/API/queries/rbac/use-get-roles";
import { useGetUsers } from "@/controllers/API/queries/rbac/use-get-users";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";
import BulkAssignmentPanel from "./BulkAssignmentPanel";
import ConflictDetectionPanel from "./ConflictDetectionPanel";
import PermissionInheritanceViewer from "./PermissionInheritanceViewer";
import ScopePickerTree from "./ScopePickerTree";

export interface ScopeHierarchy {
  type: "workspace" | "project" | "environment" | "flow" | "component";
  id: string;
  name: string;
  parent?: ScopeHierarchy;
  children?: ScopeHierarchy[];
}

export interface RoleAssignmentRequest {
  principal_type: "user" | "group" | "service_account";
  principal_id: string;
  role_id: string;
  scope: ScopeHierarchy;
  expires_at?: string;
  metadata?: Record<string, any>;
}

export interface ConflictDetection {
  type: "duplicate" | "override" | "inheritance_conflict";
  message: string;
  severity: "warning" | "error";
  suggestions: string[];
}

interface ScopedRoleAssignmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  initialScope?: ScopeHierarchy;
  initialPrincipal?: { type: string; id: string; name: string };
  mode?: "single" | "bulk";
}

export default function ScopedRoleAssignmentModal({
  isOpen,
  onClose,
  onSuccess,
  initialScope,
  initialPrincipal,
  mode = "single",
}: ScopedRoleAssignmentModalProps) {
  // State management
  const [activeStep, setActiveStep] = useState(1);
  const [selectedPrincipal, setSelectedPrincipal] = useState<any>(
    initialPrincipal || null,
  );
  const [selectedScope, setSelectedScope] = useState<ScopeHierarchy | null>(
    initialScope || null,
  );
  const [selectedRole, setSelectedRole] = useState<string>("");
  const [expiresAt, setExpiresAt] = useState<string>("");
  const [assignments, setAssignments] = useState<RoleAssignmentRequest[]>([]);
  const [conflicts, setConflicts] = useState<ConflictDetection[]>([]);
  const [showAuthModal, setShowAuthModal] = useState(false);

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // API hooks
  const {
    mutate: fetchRoles,
    data: rolesData,
    isPending: isLoadingRoles,
    error: rolesError,
    // @ts-ignore - Temporary suppress for testing
  } = useGetRoles();

  const {
    mutate: fetchUsers,
    data: usersData,
    isPending: isLoadingUsers,
    error: usersError,
    // @ts-ignore - Temporary suppress for testing
  } = useGetUsers();

  const {
    mutate: createAssignment,
    isPending: isCreatingAssignment,
    // @ts-ignore - Temporary suppress for testing
  } = useCreateRoleAssignment({
    onSuccess: (assignment) => {
      console.log("✅ Role assignment created successfully:", assignment);
      alert("✅ Role assignment created successfully!");
      onSuccess();
      onClose();
    },
    onError: (error) => {
      console.error("❌ Failed to create role assignment:", error);
      alert(
        `❌ Failed to create assignment: ${error.message || "Unknown error"}`,
      );
    },
  });

  // Load data when authenticated
  useEffect(() => {
    if (isAdmin && isOpen) {
      fetchRoles({
        page: 1,
        page_size: 100,
        include_system_roles: true,
        is_active: true,
      });
      fetchUsers({});
    }
  }, [isAdmin, isOpen]);

  // Reset form state when modal opens
  useEffect(() => {
    if (isOpen) {
      // Reset all form state to initial values
      setActiveStep(1);
      setSelectedPrincipal(initialPrincipal || null);
      setSelectedRole("");
      setSelectedScope(initialScope || null);
      setExpiresAt("");
      setAssignments([]);
      setConflicts([]);

      console.log("🔄 Role assignment modal opened - form state reset");
    }
  }, [isOpen, initialPrincipal, initialScope]);

  // Handle data fetch success/errors with console logs
  useEffect(() => {
    if (rolesData) {
      console.log("✅ Roles fetched:", rolesData);
    }
    if (rolesError) {
      console.error("❌ Failed to fetch roles:", rolesError);
    }
  }, [rolesData, rolesError]);

  useEffect(() => {
    if (usersData) {
      console.log("✅ Users fetched:", usersData);
    }
    if (usersError) {
      console.error("❌ Failed to fetch users:", usersError);
    }
  }, [usersData, usersError]);

  // Authentication helper
  const requireAuth = (action: string, callback: () => void) => {
    if (!isAdmin) {
      setShowAuthModal(true);
    } else {
      callback();
    }
  };

  // Step navigation
  const nextStep = () => {
    if (activeStep < 5) setActiveStep(activeStep + 1);
  };

  const prevStep = () => {
    if (activeStep > 1) setActiveStep(activeStep - 1);
  };

  // Conflict detection logic
  const detectConflicts = () => {
    const newConflicts: ConflictDetection[] = [];

    // Check for duplicate assignments
    if (
      assignments.some(
        (a) =>
          a.principal_id === selectedPrincipal?.id &&
          a.role_id === selectedRole &&
          a.scope.id === selectedScope?.id,
      )
    ) {
      newConflicts.push({
        type: "duplicate",
        message: "This principal already has this role in the selected scope",
        severity: "error",
        suggestions: ["Choose a different role", "Select a different scope"],
      });
    }

    // Check for inheritance conflicts
    if (selectedScope && selectedScope.parent) {
      newConflicts.push({
        type: "inheritance_conflict",
        message:
          "This assignment may conflict with inherited permissions from parent scope",
        severity: "warning",
        suggestions: [
          "Review inherited permissions",
          "Consider assigning at parent scope instead",
        ],
      });
    }

    setConflicts(newConflicts);
  };

  // Handle assignment creation
  const handleCreateAssignment = () => {
    if (!selectedPrincipal || !selectedRole || !selectedScope) {
      alert("Please complete all required fields");
      return;
    }

    requireAuth("create-assignment", () => {
      // Transform our request format to the API format
      const apiAssignment: any = {
        role_id: selectedRole,
        assignment_type:
          selectedPrincipal.type === "user"
            ? "user"
            : selectedPrincipal.type === "group"
              ? "group"
              : "service_account",
        scope_type: selectedScope.type,
        valid_until: expiresAt || undefined,
      };

      // Set the assignee ID field based on type
      if (selectedPrincipal.type === "user") {
        apiAssignment.user_id = selectedPrincipal.id;
      } else if (selectedPrincipal.type === "group") {
        apiAssignment.group_id = selectedPrincipal.id;
      } else if (selectedPrincipal.type === "service_account") {
        apiAssignment.service_account_id = selectedPrincipal.id;
      }

      // Set the scope ID field based on scope type
      if (selectedScope.type === "workspace") {
        apiAssignment.workspace_id = selectedScope.id;
      } else if (selectedScope.type === "project") {
        apiAssignment.project_id = selectedScope.id;
      } else if (selectedScope.type === "environment") {
        apiAssignment.environment_id = selectedScope.id;
      } else if (selectedScope.type === "flow") {
        apiAssignment.flow_id = selectedScope.id;
      } else if (selectedScope.type === "component") {
        apiAssignment.component_id = selectedScope.id;
      }

      console.log("🚀 Creating role assignment:", apiAssignment);
      createAssignment(apiAssignment);
    });
  };

  if (!isOpen) return null;

  return (
    <>
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg shadow-xl w-full max-w-6xl max-h-[90vh] flex flex-col">
          {/* Header */}
          <div className="p-6 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-gray-900 flex items-center space-x-2">
                  <IconComponent name="UserPlus" className="h-5 w-5" />
                  <span>Scoped Role Assignment</span>
                </h2>
                <p className="text-sm text-gray-600 mt-1">
                  Assign roles to users, groups, or service accounts within
                  specific scopes
                </p>
              </div>
              <div className="flex items-center space-x-4">
                <button
                  onClick={onClose}
                  className="text-gray-400 hover:text-gray-600 text-2xl"
                >
                  ×
                </button>
              </div>
            </div>
          </div>

          {/* Progress Indicator */}
          <div className="p-4 border-b border-gray-100">
            <div className="flex items-center space-x-4">
              {[1, 2, 3, 4, 5].map((step) => (
                <div key={step} className="flex items-center">
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                      step <= activeStep
                        ? "bg-blue-600 text-white"
                        : "bg-gray-200 text-gray-600"
                    }`}
                  >
                    {step}
                  </div>
                  {step < 5 && (
                    <div
                      className={`w-16 h-1 mx-2 ${
                        step < activeStep ? "bg-blue-600" : "bg-gray-200"
                      }`}
                    />
                  )}
                </div>
              ))}
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {activeStep === 1 && "Select Principal"}
              {activeStep === 2 && "Choose Scope"}
              {activeStep === 3 && "Pick Role"}
              {activeStep === 4 && "Configure Options"}
              {activeStep === 5 && "Review & Confirm"}
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1 overflow-y-auto p-6">
            {activeStep === 1 && (
              <div className="space-y-6">
                <h3 className="text-lg font-medium">Select Principal</h3>
                <Tabs defaultValue="user" className="w-full">
                  <TabsList>
                    <TabsTrigger value="user">User</TabsTrigger>
                    <TabsTrigger value="group">Group</TabsTrigger>
                    <TabsTrigger value="service_account">
                      Service Account
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="user" className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {usersData?.users?.map((user) => (
                        <Card
                          key={user.id}
                          className={`cursor-pointer transition-colors ${
                            selectedPrincipal?.id === user.id
                              ? "border-blue-500 bg-blue-50"
                              : "hover:border-gray-300"
                          }`}
                          onClick={() =>
                            setSelectedPrincipal({
                              type: "user",
                              id: user.id,
                              name: user.username,
                              email: user.email,
                            })
                          }
                        >
                          <CardContent className="p-4">
                            <div className="flex items-center space-x-3">
                              <IconComponent
                                name="User"
                                className="h-8 w-8 text-gray-400"
                              />
                              <div>
                                <h4 className="font-medium">{user.username}</h4>
                                <p className="text-sm text-gray-500">
                                  {user.email}
                                </p>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="group">
                    <p className="text-gray-500">
                      Group selection coming soon...
                    </p>
                  </TabsContent>

                  <TabsContent value="service_account">
                    <p className="text-gray-500">
                      Service account selection coming soon...
                    </p>
                  </TabsContent>
                </Tabs>
              </div>
            )}

            {activeStep === 2 && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium">Choose Scope</h3>
                  <p className="text-sm text-gray-600 mt-1">
                    Select the scope where this role assignment will apply. You
                    can assign roles at any level of the hierarchy:
                  </p>
                  <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                    <span>🏢 Workspace (Rank 1)</span>
                    <span>→</span>
                    <span>📁 Project (Rank 2)</span>
                    <span>→</span>
                    <span>⚙️ Environment (Rank 3)</span>
                    <span>→</span>
                    <span>🔗 Flow (Rank 4)</span>
                    <span>→</span>
                    <span>📦 Component (Rank 5)</span>
                  </div>
                </div>
                <ScopePickerTree
                  onScopeSelect={setSelectedScope}
                  selectedScope={selectedScope}
                />
              </div>
            )}

            {activeStep === 3 && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium">Pick Role</h3>
                  {selectedScope && (
                    <div className="mt-2 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                      <p className="text-sm text-blue-800">
                        <strong>Assigning to:</strong> {selectedScope.type} "
                        {selectedScope.name}"
                        {selectedScope.parent && (
                          <span className="text-blue-600">
                            {" "}
                            in {selectedScope.parent.type} "
                            {selectedScope.parent.name}"
                          </span>
                        )}
                      </p>
                    </div>
                  )}
                </div>
                {isLoadingRoles ? (
                  <div className="flex items-center justify-center py-8">
                    <IconComponent
                      name="Loader2"
                      className="h-6 w-6 animate-spin mr-2"
                    />
                    <span>Loading available roles...</span>
                  </div>
                ) : !rolesData?.roles?.length ? (
                  <div className="text-center py-8 text-gray-500">
                    <IconComponent
                      name="Shield"
                      className="h-12 w-12 mx-auto mb-3 text-gray-300"
                    />
                    <p>No roles available for selection</p>
                    <p className="text-sm mt-1 text-gray-400">
                      {rolesError
                        ? `API Error: ${rolesError.message || "Unable to fetch roles"}`
                        : "Ensure the backend server is running and RBAC endpoints are available"}
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {rolesData.roles.map((role) => (
                      <Card
                        key={role.id}
                        className={`cursor-pointer transition-colors ${
                          selectedRole === role.id
                            ? "border-blue-500 bg-blue-50"
                            : "hover:border-gray-300"
                        }`}
                        onClick={() => setSelectedRole(role.id)}
                      >
                        <CardContent className="p-4">
                          <div className="space-y-2">
                            <h4 className="font-medium">{role.name}</h4>
                            <p className="text-sm text-gray-500">
                              {role.description}
                            </p>
                            <div className="flex flex-wrap gap-1">
                              {role.permissions
                                ?.slice(0, 3)
                                .map((perm, idx) => (
                                  <Badge
                                    key={idx}
                                    variant="outline"
                                    className="text-xs"
                                  >
                                    {perm.split(":")[1] || perm}
                                  </Badge>
                                ))}
                              {role.permissions?.length > 3 && (
                                <Badge variant="outline" className="text-xs">
                                  +{role.permissions.length - 3} more
                                </Badge>
                              )}
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeStep === 4 && (
              <div className="space-y-6">
                <h3 className="text-lg font-medium">Configure Options</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="expires_at">
                        Expiration Date (Optional)
                      </Label>
                      <Input
                        id="expires_at"
                        type="datetime-local"
                        value={expiresAt}
                        onChange={(e) => setExpiresAt(e.target.value)}
                        className="mt-1"
                      />
                    </div>
                  </div>

                  <PermissionInheritanceViewer
                    scope={selectedScope}
                    role={selectedRole}
                  />
                </div>

                <ConflictDetectionPanel
                  conflicts={conflicts}
                  onResolve={() => detectConflicts()}
                />
              </div>
            )}

            {activeStep === 5 && (
              <div className="space-y-6">
                <h3 className="text-lg font-medium">Review & Confirm</h3>
                <Card>
                  <CardContent className="p-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div>
                        <h4 className="font-medium mb-2">Principal</h4>
                        <p className="text-sm text-gray-600">
                          {selectedPrincipal?.name} ({selectedPrincipal?.type})
                        </p>
                      </div>
                      <div>
                        <h4 className="font-medium mb-2">Role</h4>
                        <p className="text-sm text-gray-600">
                          {
                            rolesData?.roles?.find((r) => r.id === selectedRole)
                              ?.name
                          }
                        </p>
                      </div>
                      <div>
                        <h4 className="font-medium mb-2">Scope</h4>
                        <p className="text-sm text-gray-600">
                          {selectedScope?.type}: {selectedScope?.name}
                        </p>
                      </div>
                      <div>
                        <h4 className="font-medium mb-2">Expiration</h4>
                        <p className="text-sm text-gray-600">
                          {expiresAt
                            ? new Date(expiresAt).toLocaleDateString()
                            : "Never"}
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-6 border-t border-gray-200 flex justify-between">
            <Button
              variant="outline"
              onClick={prevStep}
              disabled={activeStep === 1}
            >
              Previous
            </Button>

            <div className="flex space-x-3">
              <Button variant="outline" onClick={onClose}>
                Cancel
              </Button>

              {activeStep < 5 ? (
                <Button
                  onClick={nextStep}
                  disabled={
                    (activeStep === 1 && !selectedPrincipal) ||
                    (activeStep === 2 && !selectedScope) ||
                    (activeStep === 3 && !selectedRole)
                  }
                >
                  Next
                </Button>
              ) : (
                <Button
                  onClick={handleCreateAssignment}
                  disabled={
                    isCreatingAssignment ||
                    conflicts.some((c) => c.severity === "error")
                  }
                >
                  {isCreatingAssignment ? "Creating..." : "Create Assignment"}
                </Button>
              )}
            </div>
          </div>
        </div>
      </div>

      <AuthenticationModal
        open={showAuthModal}
        onOpenChange={setShowAuthModal}
        onSuccess={() => {
          fetchRoles({
            page: 1,
            page_size: 100,
            include_system_roles: true,
            is_active: true,
          });
          fetchUsers({});
        }}
      />
    </>
  );
}
