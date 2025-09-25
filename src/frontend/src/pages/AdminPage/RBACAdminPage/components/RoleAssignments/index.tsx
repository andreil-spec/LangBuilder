// Role Assignments Component - Real API Implementation
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useGetAutoLogin } from "@/controllers/API/queries/auth";
import { useGetRoleAssignments } from "@/controllers/API/queries/rbac/use-get-role-assignments";
import { useDeleteRoleAssignment } from "@/controllers/API/queries/rbac/use-delete-role-assignment";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";
import ScopedRoleAssignmentModal from "../ScopedRoleAssignment";

export default function RoleAssignments() {
  const [searchTerm, setSearchTerm] = useState("");
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [showScopedAssignmentModal, setShowScopedAssignmentModal] =
    useState(false);
  const [deletingAssignments, setDeletingAssignments] = useState<Set<string>>(new Set());

  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // Auto-login query to get authentication token
  const { data: autoLoginData, isSuccess: autoLoginSuccess } = useGetAutoLogin({
    retry: 3,
    retryDelay: 1000,
  });

  // API hooks
  const {
    mutate: fetchRoleAssignments,
    data: roleAssignmentsData,
    isPending: isLoading,
    isSuccess: isRoleAssignmentsSuccess,
    isError: isRoleAssignmentsError,
    error,
    // @ts-ignore - Temporary suppress for testing
  } = useGetRoleAssignments();

  const { mutate: deleteRoleAssignment } = useDeleteRoleAssignment({
    onSuccess: (data, variables) => {
      console.log("✅ Role assignment deleted successfully");
      // Remove from deleting state
      setDeletingAssignments(prev => {
        const newSet = new Set(prev);
        newSet.delete(variables.assignment_id);
        return newSet;
      });
      // Refresh the assignments list
      fetchRoleAssignments({});
    },
    onError: (error, variables) => {
      console.error("❌ Failed to delete role assignment:", error);
      // Remove from deleting state
      setDeletingAssignments(prev => {
        const newSet = new Set(prev);
        newSet.delete(variables.assignment_id);
        return newSet;
      });
      alert(`Failed to delete role assignment: ${error?.message || "Unknown error"}`);
    },
  });

  // Handle role assignments success
  useEffect(() => {
    if (isRoleAssignmentsSuccess && roleAssignmentsData) {
      console.log("✅ Role assignments fetched:", roleAssignmentsData);
    }
  }, [isRoleAssignmentsSuccess, roleAssignmentsData]);

  // Handle role assignments error
  useEffect(() => {
    if (isRoleAssignmentsError && error) {
      console.error("❌ Failed to fetch role assignments:", error);
    }
  }, [isRoleAssignmentsError, error]);

  // Fetch data when authenticated (either through auto-login or existing auth)
  useEffect(() => {
    if (isAdmin || autoLoginSuccess) {
      console.log("🔓 Authenticated - fetching role assignments");
      fetchRoleAssignments({});
    }
  }, [isAdmin, autoLoginSuccess]);

  const requireAuth = (action: string, callback: () => void) => {
    if (!isAdmin) {
      setShowAuthModal(true);
    } else {
      callback();
    }
  };

  const handleSearch = () => {
    requireAuth("search-role-assignments", () => {
      // Refresh the data without search parameter (API doesn't support search)
      fetchRoleAssignments({});
    });
  };

  const handleDeleteAssignment = (assignmentId: string) => {
    if (!isAdmin) {
      setShowAuthModal(true);
      return;
    }

    if (confirm("Are you sure you want to delete this role assignment?")) {
      console.log("Deleting role assignment:", assignmentId);
      // Add to deleting state
      setDeletingAssignments(prev => new Set(prev).add(assignmentId));
      deleteRoleAssignment({ assignment_id: assignmentId });
    }
  };

  // Client-side filtering for search functionality
  const roleAssignments = roleAssignmentsData?.assignments || [];
  const filteredAssignments = searchTerm
    ? roleAssignments.filter((assignment) => {
        const searchLower = searchTerm.toLowerCase();
        return (
          assignment.user_name?.toLowerCase().includes(searchLower) ||
          assignment.user_id?.toLowerCase().includes(searchLower) ||
          assignment.role_name?.toLowerCase().includes(searchLower) ||
          assignment.role_id?.toLowerCase().includes(searchLower) ||
          assignment.scope_type?.toLowerCase().includes(searchLower) ||
          assignment.assigned_by_name?.toLowerCase().includes(searchLower)
        );
      })
    : roleAssignments;

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold flex items-center space-x-2">
            <IconComponent name="UserPlus" className="h-5 w-5" />
            <span>Role Assignments</span>
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Manage user role assignments
          </p>
        </div>
      </div>

      <div className="mb-4 flex space-x-2">
        <Input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search role assignments (live)..."
          className="w-64"
        />
        <Button
          onClick={() => fetchRoleAssignments({})}
          disabled={isLoading || !isAdmin}
        >
          {isLoading ? "Refreshing..." : "Refresh"}
        </Button>
        <Button
          onClick={() => setShowScopedAssignmentModal(true)}
          disabled={!isAdmin}
          className="bg-blue-600 hover:bg-blue-700"
        >
          <IconComponent name="Plus" className="h-4 w-4 mr-2" />
          New Scoped Assignment
        </Button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          Error: {error.message}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Role Assignments</CardTitle>
          <CardDescription>
            {isLoading
              ? "Loading..."
              : `Found ${filteredAssignments.length} assignment${filteredAssignments.length !== 1 ? "s" : ""}`}
            {searchTerm && ` (filtered from ${roleAssignments.length} total)`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Assigned By</TableHead>
                <TableHead>Assigned</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <IconComponent
                      name="Loader2"
                      className="h-4 w-4 animate-spin mr-2"
                    />
                    Loading role assignments...
                  </TableCell>
                </TableRow>
              ) : !isAdmin ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    Please authenticate to view role assignments
                    <Button
                      variant="link"
                      onClick={() => setShowAuthModal(true)}
                      className="ml-2"
                    >
                      Sign In
                    </Button>
                  </TableCell>
                </TableRow>
              ) : filteredAssignments.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    {searchTerm
                      ? `No assignments found matching "${searchTerm}"`
                      : "No role assignments found"}
                  </TableCell>
                </TableRow>
              ) : (
                filteredAssignments.map((assignment) => (
                  <TableRow key={assignment.id}>
                    <TableCell className="font-medium">
                      {assignment.user_name || assignment.user_id}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">
                        {assignment.role_name || assignment.role_id}
                      </Badge>
                    </TableCell>
                    <TableCell>{assignment.scope_type}</TableCell>
                    <TableCell>
                      {assignment.assigned_by_name || "System"}
                    </TableCell>
                    <TableCell>
                      {new Date(assignment.assigned_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <div className="flex space-x-2">
                        <button
                          onClick={() => handleDeleteAssignment(assignment.id)}
                          disabled={!isAdmin || deletingAssignments.has(assignment.id)}
                          className="text-red-600 hover:text-red-800 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {deletingAssignments.has(assignment.id) ? "Deleting..." : "Delete"}
                        </button>
                      </div>
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
          fetchRoleAssignments({});
        }}
      />

      <ScopedRoleAssignmentModal
        isOpen={showScopedAssignmentModal}
        onClose={() => setShowScopedAssignmentModal(false)}
        onSuccess={() => {
          setShowScopedAssignmentModal(false);
          fetchRoleAssignments({});
        }}
      />
    </div>
  );
}
