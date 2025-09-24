import { useEffect, useState } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import RBACAdminPage from "./RBACAdminPage";
import UserManagementPage from "./UserManagementPage";

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState("rbac");

  // Override body overflow for admin pages only
  useEffect(() => {
    const body = document.body;
    const originalOverflow = body.style.overflow;
    body.style.overflow = "auto";

    return () => {
      body.style.overflow = originalOverflow;
    };
  }, []);

  return (
    <div className="min-h-screen w-full">
      {/* Main Admin Header */}
      <div className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex h-16 items-center px-6">
          <div className="flex items-center space-x-3">
            <IconComponent name="ShieldCheck" className="h-7 w-7" />
            <div>
              <h1 className="text-xl font-bold">Administration</h1>
              <p className="text-sm text-muted-foreground">
                System administration and access control management
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Admin Navigation Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <div className="border-b bg-muted/30">
          <TabsList className="grid w-full grid-cols-2 bg-transparent h-12">
            <TabsTrigger
              value="rbac"
              className="flex items-center space-x-2 data-[state=active]:bg-background"
            >
              <IconComponent name="Shield" className="h-4 w-4" />
              <span>Access Control (RBAC)</span>
            </TabsTrigger>
            <TabsTrigger
              value="users"
              className="flex items-center space-x-2 data-[state=active]:bg-background"
            >
              <IconComponent name="Users" className="h-4 w-4" />
              <span>User Management</span>
            </TabsTrigger>
          </TabsList>
        </div>

        {/* Tab Content */}
        <div className="w-full" style={{ height: "calc(100vh - 7rem)" }}>
          <TabsContent value="rbac" className="m-0 p-0 h-full overflow-y-auto">
            <RBACAdminPage />
          </TabsContent>

          <TabsContent value="users" className="m-0 p-0 h-full overflow-y-auto">
            <UserManagementPage />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
