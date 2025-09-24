// PermissionInheritanceViewer - Visualizes permission inheritance across scope hierarchy
import { useEffect, useState } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { useGetPermissions } from "@/controllers/API/queries/rbac/use-get-permissions";
import { useGetRoles } from "@/controllers/API/queries/rbac/use-get-roles";
import type { ScopeHierarchy } from "./index";

interface PermissionInheritanceViewerProps {
  scope: ScopeHierarchy | null;
  role: string;
}

interface EffectivePermission {
  permission_id: string;
  permission_name: string;
  permission_code: string;
  source_scope: {
    type: string;
    id: string;
    name: string;
  };
  is_inherited: boolean;
  is_dangerous: boolean;
  requires_mfa: boolean;
  category: string;
}

interface InheritanceLevel {
  scope: ScopeHierarchy;
  permissions: EffectivePermission[];
  is_current_scope: boolean;
  is_inherited: boolean;
  hierarchy_distance: number;
}

export default function PermissionInheritanceViewer({
  scope,
  role,
}: PermissionInheritanceViewerProps) {
  console.log("🔍 PermissionInheritanceViewer rendered with:", { scope, role });
  const [inheritanceLevels, setInheritanceLevels] = useState<
    InheritanceLevel[]
  >([]);
  const [effectivePermissions, setEffectivePermissions] = useState<
    EffectivePermission[]
  >([]);
  const [isExpanded, setIsExpanded] = useState(true);

  // API hooks
  const {
    mutate: fetchPermissions,
    data: permissionsData,
    isSuccess: isPermissionsSuccess,
    isError: isPermissionsError,
    error: permissionsError,
    // @ts-ignore - Temporary suppress for testing
  } = useGetPermissions();

  const {
    mutate: fetchRoles,
    data: rolesData,
    isSuccess: isRolesSuccess,
    isError: isRolesError,
    error: rolesError,
    // @ts-ignore - Temporary suppress for testing
  } = useGetRoles();

  // Load role and permission data when inputs change
  useEffect(() => {
    console.log("🔄 PermissionInheritanceViewer: Effect triggered", {
      scope,
      role,
    });
    if (scope && role) {
      console.log("✅ PermissionInheritanceViewer: Fetching roles");
      fetchRoles({
        page: 1,
        page_size: 100,
        include_system_roles: true,
        is_active: true,
      });
    } else {
      console.log("❌ PermissionInheritanceViewer: Missing scope or role", {
        scope,
        role,
      });
    }
  }, [scope, role]);

  // Handle roles success - fetch permissions when roles are loaded
  useEffect(() => {
    if (isRolesSuccess && rolesData && role) {
      fetchPermissions({});
    }
  }, [isRolesSuccess, rolesData, role]);

  // Handle permissions success - calculate inheritance
  useEffect(() => {
    if (isPermissionsSuccess && permissionsData) {
      calculateInheritance(permissionsData);
    }
  }, [isPermissionsSuccess, permissionsData]);

  // Handle errors
  useEffect(() => {
    if (isPermissionsError && permissionsError) {
      console.error(
        "❌ PermissionInheritanceViewer: Failed to fetch permissions:",
        permissionsError,
      );
      alert(
        `Permission fetch error: ${permissionsError.message || "Unknown error"}`,
      );
    }
  }, [isPermissionsError, permissionsError]);

  useEffect(() => {
    if (isRolesError && rolesError) {
      console.error(
        "❌ PermissionInheritanceViewer: Failed to fetch roles:",
        rolesError,
      );
      alert(`Role fetch error: ${rolesError.message || "Unknown error"}`);
    }
  }, [isRolesError, rolesError]);

  // Calculate permission inheritance based on PRD hierarchy rules
  const calculateInheritance = (permissions: any[]) => {
    if (!scope || !role || !rolesData?.roles) return;

    const selectedRole = rolesData.roles.find((r) => r.id === role);
    if (!selectedRole) return;

    // Build hierarchy chain from current scope to root
    const buildHierarchyChain = (
      currentScope: ScopeHierarchy,
    ): ScopeHierarchy[] => {
      const chain = [currentScope];
      if (currentScope.parent) {
        chain.unshift(...buildHierarchyChain(currentScope.parent));
      }
      return chain;
    };

    const hierarchyChain = buildHierarchyChain(scope);
    const levels: InheritanceLevel[] = [];
    const allEffective: EffectivePermission[] = [];

    // For each level in the hierarchy, calculate effective permissions
    hierarchyChain.forEach((scopeLevel, index) => {
      const levelPermissions: EffectivePermission[] = [];

      // Get permissions that would be assigned at this level
      if (selectedRole.permissions) {
        selectedRole.permissions.forEach((permId) => {
          const permission = permissions.find(
            (p) => p.id === permId || p.code === permId,
          );
          if (permission) {
            const effectivePerm: EffectivePermission = {
              permission_id: permission.id,
              permission_name: permission.name,
              permission_code: permission.code,
              source_scope: {
                type: scopeLevel.type,
                id: scopeLevel.id,
                name: scopeLevel.name,
              },
              is_inherited: index < hierarchyChain.length - 1, // Not inherited if it's the target scope
              is_dangerous: permission.is_dangerous || false,
              requires_mfa: permission.requires_mfa || false,
              category: permission.category || "general",
            };

            levelPermissions.push(effectivePerm);

            // Add to effective permissions if not already present from a closer scope
            if (
              !allEffective.some((ep) => ep.permission_id === permission.id)
            ) {
              allEffective.push(effectivePerm);
            }
          }
        });
      }

      levels.push({
        scope: scopeLevel,
        permissions: levelPermissions,
        is_current_scope: index === hierarchyChain.length - 1,
        is_inherited: index < hierarchyChain.length - 1,
        hierarchy_distance: hierarchyChain.length - 1 - index,
      });
    });

    setInheritanceLevels(levels);
    setEffectivePermissions(allEffective);
  };

  // Group permissions by category for better display
  const groupPermissionsByCategory = (permissions: EffectivePermission[]) => {
    return permissions.reduce(
      (groups, perm) => {
        const category = perm.category || "general";
        if (!groups[category]) {
          groups[category] = [];
        }
        groups[category].push(perm);
        return groups;
      },
      {} as Record<string, EffectivePermission[]>,
    );
  };

  // Get scope hierarchy rank for display
  const getScopeRank = (type: string) => {
    const ranks = {
      workspace: 1,
      project: 2,
      environment: 3,
      flow: 4,
      component: 5,
    };
    return ranks[type as keyof typeof ranks] || 0;
  };

  // Get scope icon
  const getScopeIcon = (type: string) => {
    const icons = {
      workspace: "Building",
      project: "Folder",
      environment: "Settings",
      flow: "GitBranch",
      component: "Box",
    };
    return icons[type as keyof typeof icons] || "Circle";
  };

  if (!scope || !role) {
    return (
      <Card>
        <CardContent className="p-6 text-center text-gray-500">
          <IconComponent name="Info" className="h-8 w-8 mx-auto mb-2" />
          <p>Select a scope and role to view permission inheritance</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <Collapsible open={isExpanded} onOpenChange={setIsExpanded}>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <IconComponent name="GitBranch" className="h-5 w-5" />
              <span>Permission Inheritance</span>
            </div>
            <CollapsibleTrigger asChild>
              <button className="text-gray-400 hover:text-gray-600">
                <IconComponent
                  name={isExpanded ? "ChevronUp" : "ChevronDown"}
                  className="h-4 w-4"
                />
              </button>
            </CollapsibleTrigger>
          </CardTitle>
          <CardDescription>
            Shows how permissions cascade through the scope hierarchy (Workspace
            → Project → Environment → Flow → Component)
          </CardDescription>
        </CardHeader>

        <CollapsibleContent>
          <CardContent className="space-y-6">
            {/* Effective Permissions Summary */}
            <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
              <h4 className="font-medium text-blue-900 mb-2 flex items-center">
                <IconComponent name="Target" className="h-4 w-4 mr-2" />
                Effective Permissions for Selected Assignment
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                <div>
                  <span className="text-blue-700 font-medium">
                    Total Permissions:
                  </span>
                  <span className="ml-2">{effectivePermissions.length}</span>
                </div>
                <div>
                  <span className="text-blue-700 font-medium">Inherited:</span>
                  <span className="ml-2">
                    {effectivePermissions.filter((p) => p.is_inherited).length}
                  </span>
                </div>
                <div>
                  <span className="text-blue-700 font-medium">Dangerous:</span>
                  <span className="ml-2 text-red-600">
                    {effectivePermissions.filter((p) => p.is_dangerous).length}
                  </span>
                </div>
              </div>
            </div>

            {/* Inheritance Hierarchy */}
            <div className="space-y-4">
              <h4 className="font-medium flex items-center">
                <IconComponent name="Layers" className="h-4 w-4 mr-2" />
                Inheritance Hierarchy
              </h4>

              {inheritanceLevels.map((level, index) => (
                <div
                  key={level.scope.id}
                  className={`border rounded-lg p-4 ${
                    level.is_current_scope
                      ? "border-blue-500 bg-blue-50"
                      : "border-gray-200 bg-gray-50"
                  }`}
                >
                  {/* Hierarchy Level Header */}
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className="flex items-center space-x-2">
                        <IconComponent
                          name={getScopeIcon(level.scope.type) as any}
                          className="h-5 w-5 text-gray-600"
                        />
                        <span className="font-medium">{level.scope.name}</span>
                        <Badge variant="outline" className="text-xs">
                          {level.scope.type}
                        </Badge>
                      </div>

                      {level.is_current_scope && (
                        <Badge className="bg-blue-600 text-white text-xs">
                          Target Scope
                        </Badge>
                      )}

                      {level.is_inherited && (
                        <Badge variant="secondary" className="text-xs">
                          Inherited ({level.hierarchy_distance} levels up)
                        </Badge>
                      )}
                    </div>

                    <div className="text-sm text-gray-500">
                      Rank {getScopeRank(level.scope.type)} •{" "}
                      {level.permissions.length} permissions
                    </div>
                  </div>

                  {/* Permissions at this level */}
                  {level.permissions.length > 0 && (
                    <div className="space-y-3">
                      {Object.entries(
                        groupPermissionsByCategory(level.permissions),
                      ).map(([category, perms]) => (
                        <div key={category}>
                          <h5 className="text-sm font-medium text-gray-700 mb-2 capitalize">
                            {category} ({perms.length})
                          </h5>
                          <div className="flex flex-wrap gap-2">
                            {perms.map((perm) => (
                              <Badge
                                key={perm.permission_id}
                                variant={
                                  perm.is_dangerous
                                    ? "destructive"
                                    : "secondary"
                                }
                                className="text-xs flex items-center space-x-1"
                              >
                                <span>{perm.permission_name}</span>
                                {perm.requires_mfa && (
                                  <IconComponent
                                    name="Shield"
                                    className="h-3 w-3"
                                  />
                                )}
                                {perm.is_dangerous && (
                                  <IconComponent
                                    name="AlertTriangle"
                                    className="h-3 w-3"
                                  />
                                )}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Inheritance Flow Arrow */}
                  {index < inheritanceLevels.length - 1 && (
                    <div className="flex justify-center mt-4">
                      <div className="flex items-center space-x-2 text-gray-400">
                        <div className="w-8 h-px bg-gray-300"></div>
                        <IconComponent name="ArrowDown" className="h-4 w-4" />
                        <div className="w-8 h-px bg-gray-300"></div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Permission Details */}
            {effectivePermissions.length > 0 && (
              <div className="border-t pt-4">
                <h4 className="font-medium mb-3 flex items-center">
                  <IconComponent name="List" className="h-4 w-4 mr-2" />
                  All Effective Permissions
                </h4>

                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {effectivePermissions.map((perm) => (
                    <div
                      key={perm.permission_id}
                      className="flex items-center justify-between p-2 bg-gray-50 rounded text-sm"
                    >
                      <div className="flex items-center space-x-2">
                        <IconComponent
                          name={perm.is_dangerous ? "AlertTriangle" : "Key"}
                          className={`h-4 w-4 ${perm.is_dangerous ? "text-red-500" : "text-gray-400"}`}
                        />
                        <span className="font-medium">
                          {perm.permission_name}
                        </span>
                        <code className="text-xs bg-gray-200 px-1 rounded">
                          {perm.permission_code}
                        </code>
                      </div>

                      <div className="flex items-center space-x-2">
                        <Badge variant="outline" className="text-xs">
                          {perm.source_scope.type}: {perm.source_scope.name}
                        </Badge>
                        {perm.is_inherited && (
                          <Badge variant="secondary" className="text-xs">
                            Inherited
                          </Badge>
                        )}
                        {perm.requires_mfa && (
                          <Badge variant="outline" className="text-xs">
                            MFA
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Security Warnings */}
            {effectivePermissions.some((p) => p.is_dangerous) && (
              <div className="border border-red-200 bg-red-50 rounded-lg p-4">
                <div className="flex items-center space-x-2 text-red-800 mb-2">
                  <IconComponent name="AlertTriangle" className="h-5 w-5" />
                  <span className="font-medium">Security Warning</span>
                </div>
                <p className="text-sm text-red-700">
                  This assignment includes{" "}
                  {effectivePermissions.filter((p) => p.is_dangerous).length}{" "}
                  dangerous permission(s). Please review carefully and ensure
                  the principal requires these elevated privileges.
                </p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {effectivePermissions
                    .filter((p) => p.is_dangerous)
                    .map((perm) => (
                      <Badge
                        key={perm.permission_id}
                        variant="destructive"
                        className="text-xs"
                      >
                        {perm.permission_name}
                      </Badge>
                    ))}
                </div>
              </div>
            )}
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}
