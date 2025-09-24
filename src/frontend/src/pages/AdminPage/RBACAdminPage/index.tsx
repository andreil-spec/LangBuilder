import { useEffect, useState } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import useAuthStore from "@/stores/authStore";
import AuditLogs from "./components/AuditLogs";
import ComplianceReportGenerator from "./components/ComplianceReportGenerator";
import EnvironmentManagement from "./components/EnvironmentManagement";
import PermissionManagement from "./components/PermissionManagement";
import ProjectManagement from "./components/ProjectManagement";
import RoleAssignments from "./components/RoleAssignments";
import RoleManagement from "./components/RoleManagement";
import SCIMProvisioning from "./components/SCIMProvisioning";
import ServiceAccounts from "./components/ServiceAccounts";
import SSOConfiguration from "./components/SSOConfiguration";
import UserGroups from "./components/UserGroups";
import WorkspaceManagement from "./components/WorkspaceManagement";

export default function RBACAdminPage() {
  const [activeTab, setActiveTab] = useState("permissions");

  // Centralized authentication state management - following AccountMenu pattern
  const { isAdmin, autoLogin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
    autoLogin: state.autoLogin,
  }));

  // Debug authentication state changes across all tabs
  useEffect(() => {
    console.log("🔄 RBACAdminPage: Global auth state changed:", {
      isAdmin,
      autoLogin,
      activeTab,
    });
  }, [isAdmin, autoLogin, activeTab]);

  return (
    <div className="w-full h-full flex flex-col">
      {/* Header */}
      <div className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex h-14 items-center px-6">
          <div className="flex items-center space-x-2">
            <IconComponent name="Shield" className="h-6 w-6" />
            <h1 className="text-lg font-semibold">RBAC Management</h1>
          </div>
          <div className="ml-auto flex items-center space-x-4">
            <span className="text-sm text-muted-foreground">
              Role-Based Access Control Administration
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <Tabs
        value={activeTab}
        onValueChange={setActiveTab}
        className="w-full flex-1 flex flex-col"
      >
        <div className="border-b bg-muted/50">
          {/* Category Headers */}
          <div className="px-6 py-3 bg-gradient-to-r from-gray-50 to-gray-100 border-b">
            <div className="grid grid-cols-6 gap-4 text-xs font-medium text-gray-600 uppercase tracking-wide">
              <div className="col-span-3 flex items-center space-x-6">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                  <span>Core Management</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span>Resources & Access</span>
                </div>
              </div>
              <div className="col-span-3 flex items-center space-x-6">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
                  <span>User & Service Mgmt</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                  <span>Enterprise & Compliance</span>
                </div>
              </div>
            </div>
          </div>

          {/* Main Navigation - Two Rows */}
          <div className="space-y-0">
            {/* First Row - Core Management & Resources */}
            <TabsList className="grid w-full grid-cols-6 bg-transparent h-12 rounded-none border-b">
              {/* Core Management (3 tabs) */}
              <TabsTrigger
                value="permissions"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="Key" className="h-4 w-4" />
                <span>Permissions</span>
              </TabsTrigger>
              <TabsTrigger
                value="roles"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="Users" className="h-4 w-4" />
                <span>Roles</span>
              </TabsTrigger>
              <TabsTrigger
                value="assignments"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="UserPlus" className="h-4 w-4" />
                <span>Assignments</span>
              </TabsTrigger>

              {/* Resources & Access (3 tabs) */}
              <TabsTrigger
                value="workspaces"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="Building" className="h-4 w-4" />
                <span>Workspaces</span>
              </TabsTrigger>
              <TabsTrigger
                value="projects"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="Building2" className="h-4 w-4" />
                <span>Projects</span>
              </TabsTrigger>
              <TabsTrigger
                value="environments"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="Settings" className="h-4 w-4" />
                <span>Environments</span>
              </TabsTrigger>
            </TabsList>

            {/* Second Row - Advanced Features */}
            <TabsList className="grid w-full grid-cols-6 bg-transparent h-12 rounded-none bg-gray-25">
              {/* User Management & Services (2 tabs) */}
              <TabsTrigger
                value="user-groups"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="UserCheck" className="h-4 w-4" />
                <span>User Groups</span>
              </TabsTrigger>
              <TabsTrigger
                value="service-accounts"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="Bot" className="h-4 w-4" />
                <span>Service Accounts</span>
              </TabsTrigger>

              {/* Enterprise Integration (2 tabs) */}
              <TabsTrigger
                value="sso"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="KeyRound" className="h-4 w-4" />
                <span>SSO Config</span>
              </TabsTrigger>
              <TabsTrigger
                value="scim"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="RefreshCw" className="h-4 w-4" />
                <span>SCIM Provisioning</span>
              </TabsTrigger>

              {/* Monitoring & Compliance (2 tabs) */}
              <TabsTrigger
                value="audit"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="FileText" className="h-4 w-4" />
                <span>Audit Logs</span>
              </TabsTrigger>
              <TabsTrigger
                value="compliance"
                className="flex items-center space-x-2 data-[state=active]:bg-background text-xs"
              >
                <IconComponent name="Shield" className="h-4 w-4" />
                <span>Compliance</span>
              </TabsTrigger>
            </TabsList>
          </div>
        </div>

        {/* Tab Content */}
        <div className="w-full flex-1 overflow-hidden">
          <TabsContent
            value="permissions"
            className="m-0 p-0 h-full overflow-y-auto"
          >
            <PermissionManagement />
          </TabsContent>

          <TabsContent value="roles" className="m-0 p-0 h-full overflow-y-auto">
            <RoleManagement />
          </TabsContent>

          <TabsContent
            value="projects"
            className="m-0 p-0 h-full overflow-y-auto"
          >
            <ProjectManagement />
          </TabsContent>

          <TabsContent
            value="service-accounts"
            className="m-0 p-0 h-full overflow-y-auto"
          >
            <ServiceAccounts />
          </TabsContent>

          <TabsContent
            value="environments"
            className="m-0 p-0 h-full overflow-y-auto"
          >
            <EnvironmentManagement />
          </TabsContent>

          <TabsContent
            value="workspaces"
            className="m-0 p-0 h-full overflow-y-auto"
          >
            <WorkspaceManagement />
          </TabsContent>

          <TabsContent
            value="user-groups"
            className="m-0 p-0 h-full overflow-y-auto"
          >
            <UserGroups />
          </TabsContent>

          <TabsContent
            value="assignments"
            className="m-0 p-0 h-full overflow-y-auto"
          >
            <RoleAssignments />
          </TabsContent>

          <TabsContent value="audit" className="m-0 p-0 h-full overflow-y-auto">
            <AuditLogs />
          </TabsContent>

          <TabsContent
            value="compliance"
            className="m-0 p-0 h-full overflow-y-auto"
          >
            <ComplianceReportGenerator />
          </TabsContent>

          <TabsContent value="sso" className="m-0 p-0 h-full overflow-y-auto">
            <SSOConfiguration />
          </TabsContent>

          <TabsContent value="scim" className="m-0 p-0 h-full overflow-y-auto">
            <SCIMProvisioning />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
