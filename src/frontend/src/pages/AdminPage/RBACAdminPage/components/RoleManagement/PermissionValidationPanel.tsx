// PermissionValidationPanel - Validates permissions during role creation
import { useEffect, useState } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";
import {
  type Permission,
  useGetPermissions,
} from "@/controllers/API/queries/rbac/use-get-permissions";

interface ValidationResult {
  type: "error" | "warning" | "info";
  message: string;
  permissions: string[];
  suggestions?: string[];
}

interface PermissionValidationPanelProps {
  selectedPermissions: string[];
  onPermissionsChange: (permissions: string[]) => void;
  roleName: string;
  roleDescription: string;
  onValidationChange: (isValid: boolean, results: ValidationResult[]) => void;
}

export default function PermissionValidationPanel({
  selectedPermissions,
  onPermissionsChange,
  roleName,
  roleDescription,
  onValidationChange,
}: PermissionValidationPanelProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [showDangerous, setShowDangerous] = useState(false);
  const [validationResults, setValidationResults] = useState<
    ValidationResult[]
  >([]);
  const [isExpanded, setIsExpanded] = useState(true);

  // Fetch permissions for validation
  const {
    mutate: fetchPermissions,
    data: permissionsData,
    isPending: isLoading,
  } = useGetPermissions({
    onSuccess: (data) =>
      console.log("✅ Permissions fetched for validation:", data),
    onError: (error) => console.error("❌ Failed to fetch permissions:", error),
  });

  useEffect(() => {
    try {
      fetchPermissions({ limit: 1000, workspace_id: "default" });
    } catch (error) {
      console.error("Failed to fetch permissions for validation:", error);
      // Continue without permissions to prevent UI crash
    }
  }, []);

  const permissions: Permission[] = permissionsData || [];

  // Perform validation when permissions change
  useEffect(() => {
    try {
      const results = validatePermissions();
      setValidationResults(results);

      // Check if there are any blocking errors
      const hasErrors = results.some((r) => r.type === "error");
      onValidationChange(!hasErrors, results);
    } catch (error) {
      console.error("Error during permission validation:", error);
      // Set a safe fallback state
      setValidationResults([]);
      onValidationChange(true, []); // Allow creation if validation fails
    }
  }, [selectedPermissions, permissions, roleName]);

  const validatePermissions = (): ValidationResult[] => {
    const results: ValidationResult[] = [];

    // Safety check: ensure permissions array exists
    if (!permissions || !Array.isArray(permissions)) {
      return results;
    }

    const selectedPerms = permissions.filter((p) =>
      selectedPermissions.includes(p.id),
    );

    // Check for dangerous permissions
    const dangerousPerms = selectedPerms.filter((p) => p.is_dangerous);
    if (dangerousPerms.length > 0) {
      results.push({
        type: "warning",
        message: `${dangerousPerms.length} dangerous permission${dangerousPerms.length > 1 ? "s" : ""} selected`,
        permissions: dangerousPerms.map((p) => p.action),
        suggestions: [
          "Review business justification for dangerous permissions",
          "Consider creating a more restricted role instead",
          "Ensure proper approval workflow is in place",
        ],
      });
    }

    // Check for MFA requirements
    const mfaPerms = selectedPerms.filter((p) => p.requires_mfa);
    if (mfaPerms.length > 0) {
      results.push({
        type: "info",
        message: `${mfaPerms.length} permission${mfaPerms.length > 1 ? "s" : ""} require MFA`,
        permissions: mfaPerms.map((p) => p.action),
        suggestions: [
          "Users with this role will need MFA enabled",
          "Ensure MFA policies are configured correctly",
        ],
      });
    }

    // Check for system permissions
    const systemPerms = selectedPerms.filter((p) => p.is_system);
    if (systemPerms.length > 0) {
      results.push({
        type: "error",
        message: `${systemPerms.length} system permission${systemPerms.length > 1 ? "s" : ""} cannot be assigned to custom roles`,
        permissions: systemPerms.map((p) => p.action),
        suggestions: [
          "Remove system permissions from selection",
          "Use built-in system roles instead",
        ],
      });
    }

    // Check for permission conflicts
    const conflicts = detectPermissionConflicts(selectedPerms);
    conflicts.forEach((conflict) => results.push(conflict));

    // Check compliance requirements
    const complianceIssues = checkComplianceRequirements(selectedPerms);
    complianceIssues.forEach((issue) => results.push(issue));

    // Check role naming conventions
    if (roleName) {
      const namingIssues = validateRoleNaming(roleName, selectedPerms);
      namingIssues.forEach((issue) => results.push(issue));
    }

    return results;
  };

  const detectPermissionConflicts = (
    perms: Permission[],
  ): ValidationResult[] => {
    const conflicts: ValidationResult[] = [];

    // Check for read/write conflicts
    const readPerms = perms.filter(
      (p) => p.action.includes("read") || p.action.includes("view"),
    );
    const writePerms = perms.filter(
      (p) =>
        p.action.includes("write") ||
        p.action.includes("create") ||
        p.action.includes("update"),
    );
    const deletePerms = perms.filter((p) => p.action.includes("delete"));

    if (deletePerms.length > 0 && readPerms.length === 0) {
      conflicts.push({
        type: "warning",
        message:
          "Delete permissions without read permissions may cause usability issues",
        permissions: deletePerms.map((p) => p.action),
        suggestions: ["Consider adding corresponding read permissions"],
      });
    }

    // Check for admin permissions mixed with restricted permissions
    const adminPerms = perms.filter(
      (p) => p.action.includes("admin") || p.action.includes("manage"),
    );
    const restrictedPerms = perms.filter(
      (p) => p.security_risk_level === "critical",
    );

    if (adminPerms.length > 0 && restrictedPerms.length > 0) {
      conflicts.push({
        type: "warning",
        message:
          "Administrative permissions combined with critical security permissions",
        permissions: [
          ...adminPerms.map((p) => p.action),
          ...restrictedPerms.map((p) => p.action),
        ],
        suggestions: [
          "Consider separating into multiple roles",
          "Review principle of least privilege",
        ],
      });
    }

    return conflicts;
  };

  const checkComplianceRequirements = (
    perms: Permission[],
  ): ValidationResult[] => {
    const issues: ValidationResult[] = [];

    // Check SOC 2 compliance
    const socPerms = perms.filter((p) =>
      p.compliance_tags?.includes("SOC2_RESTRICTED"),
    );
    if (socPerms.length > 0) {
      issues.push({
        type: "info",
        message: `${socPerms.length} permission${socPerms.length > 1 ? "s" : ""} have SOC 2 restrictions`,
        permissions: socPerms.map((p) => p.action),
        suggestions: [
          "Ensure SOC 2 compliance documentation is updated",
          "Review access control matrices",
        ],
      });
    }

    // Check PCI compliance
    const pciPerms = perms.filter((p) =>
      p.compliance_tags?.includes("PCI_DSS"),
    );
    if (pciPerms.length > 0) {
      issues.push({
        type: "warning",
        message: `${pciPerms.length} permission${pciPerms.length > 1 ? "s" : ""} affect PCI DSS compliance`,
        permissions: pciPerms.map((p) => p.action),
        suggestions: [
          "Ensure PCI DSS requirements are met",
          "Document business justification",
        ],
      });
    }

    return issues;
  };

  const validateRoleNaming = (
    name: string,
    perms: Permission[],
  ): ValidationResult[] => {
    const issues: ValidationResult[] = [];

    // Check for descriptive naming
    if (name.length < 3) {
      issues.push({
        type: "error",
        message: "Role name too short (minimum 3 characters)",
        permissions: [],
        suggestions: ["Use descriptive role names"],
      });
    }

    // Check for reserved names
    const reservedNames = ["admin", "root", "system", "superuser"];
    if (
      reservedNames.some((reserved) => name.toLowerCase().includes(reserved))
    ) {
      issues.push({
        type: "warning",
        message: "Role name contains reserved terms",
        permissions: [],
        suggestions: ["Use more specific, business-focused role names"],
      });
    }

    // Suggest naming based on permissions
    const hasReadOnly = perms.every(
      (p) =>
        (p.action || "").includes("read") || (p.action || "").includes("view"),
    );
    if (
      hasReadOnly &&
      !name.toLowerCase().includes("read") &&
      !name.toLowerCase().includes("view")
    ) {
      issues.push({
        type: "info",
        message:
          "Consider including 'read' or 'view' in role name for read-only permissions",
        permissions: [],
        suggestions: ["Use naming conventions that reflect permission scope"],
      });
    }

    return issues;
  };

  const handlePermissionToggle = (permissionId: string) => {
    const updated = selectedPermissions.includes(permissionId)
      ? selectedPermissions.filter((id) => id !== permissionId)
      : [...selectedPermissions, permissionId];

    onPermissionsChange(updated);
  };

  const handleBulkAction = (
    action: "selectAll" | "selectNone" | "selectBasic" | "selectSafe",
  ) => {
    let updated: string[] = [];

    switch (action) {
      case "selectAll":
        updated = filteredPermissions.map((p) => p.id);
        break;
      case "selectNone":
        updated = [];
        break;
      case "selectBasic":
        updated = filteredPermissions
          .filter((p) => p.category === "Flow Management")
          .map((p) => p.id);
        break;
      case "selectSafe":
        updated = filteredPermissions
          .filter((p) => !p.is_dangerous && !p.is_system)
          .map((p) => p.id);
        break;
    }

    onPermissionsChange(updated);
  };

  // Filter permissions with safety checks
  const filteredPermissions = (permissions || []).filter((permission) => {
    try {
      const matchesSearch =
        (permission.name || "")
          .toLowerCase()
          .includes(searchTerm.toLowerCase()) ||
        (permission.action || "")
          .toLowerCase()
          .includes(searchTerm.toLowerCase()) ||
        (permission.description || "")
          .toLowerCase()
          .includes(searchTerm.toLowerCase());
      const matchesCategory =
        selectedCategory === "all" || permission.category === selectedCategory;
      const matchesDangerous = !showDangerous || permission.is_dangerous;

      return matchesSearch && matchesCategory && matchesDangerous;
    } catch (error) {
      console.warn("Error filtering permission:", permission, error);
      return false;
    }
  });

  const getValidationSummary = () => {
    const errors = validationResults.filter((r) => r.type === "error").length;
    const warnings = validationResults.filter(
      (r) => r.type === "warning",
    ).length;
    const infos = validationResults.filter((r) => r.type === "info").length;

    return { errors, warnings, infos };
  };

  const summary = getValidationSummary();

  return (
    <Card>
      <Collapsible open={isExpanded} onOpenChange={setIsExpanded}>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <IconComponent name="Shield" className="h-5 w-5" />
              <span>Permission Validation</span>
              <Badge variant="outline" className="text-xs">
                {selectedPermissions.length} selected
              </Badge>
            </div>

            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="sm">
                <IconComponent
                  name={isExpanded ? "ChevronUp" : "ChevronDown"}
                  className="h-4 w-4"
                />
              </Button>
            </CollapsibleTrigger>
          </CardTitle>

          <CardDescription>
            Select permissions and review validation results before creating the
            role
          </CardDescription>

          {/* Validation Summary */}
          {validationResults.length > 0 && (
            <div className="flex items-center space-x-4 text-sm">
              {summary.errors > 0 && (
                <div className="flex items-center space-x-1 text-red-600">
                  <IconComponent name="XCircle" className="h-4 w-4" />
                  <span>
                    {summary.errors} error{summary.errors !== 1 ? "s" : ""}
                  </span>
                </div>
              )}
              {summary.warnings > 0 && (
                <div className="flex items-center space-x-1 text-yellow-600">
                  <IconComponent name="AlertTriangle" className="h-4 w-4" />
                  <span>
                    {summary.warnings} warning
                    {summary.warnings !== 1 ? "s" : ""}
                  </span>
                </div>
              )}
              {summary.infos > 0 && (
                <div className="flex items-center space-x-1 text-blue-600">
                  <IconComponent name="Info" className="h-4 w-4" />
                  <span>{summary.infos} info</span>
                </div>
              )}
            </div>
          )}
        </CardHeader>

        <CollapsibleContent>
          <CardContent className="space-y-6">
            {/* Validation Results */}
            {validationResults.length > 0 && (
              <div className="space-y-3">
                {validationResults.map((result, index) => (
                  <Alert
                    key={index}
                    className={
                      result.type === "error"
                        ? "border-red-300 bg-red-50"
                        : result.type === "warning"
                          ? "border-yellow-300 bg-yellow-50"
                          : "border-blue-300 bg-blue-50"
                    }
                  >
                    <IconComponent
                      name={
                        result.type === "error"
                          ? "XCircle"
                          : result.type === "warning"
                            ? "AlertTriangle"
                            : "Info"
                      }
                      className="h-4 w-4"
                    />
                    <AlertTitle className="flex items-center space-x-2">
                      <span>{result.message}</span>
                      <Badge
                        variant={
                          result.type === "error"
                            ? "destructive"
                            : result.type === "warning"
                              ? "secondary"
                              : "outline"
                        }
                        className="text-xs"
                      >
                        {result.type}
                      </Badge>
                    </AlertTitle>

                    {result.permissions.length > 0 && (
                      <AlertDescription>
                        <p className="font-medium mt-2">
                          Affected permissions:
                        </p>
                        <ul className="list-disc list-inside text-sm mt-1">
                          {result.permissions.map((perm, permIndex) => (
                            <li key={permIndex}>{perm}</li>
                          ))}
                        </ul>
                      </AlertDescription>
                    )}

                    {result.suggestions && result.suggestions.length > 0 && (
                      <AlertDescription>
                        <p className="font-medium mt-2">Suggestions:</p>
                        <ul className="list-disc list-inside text-sm mt-1">
                          {result.suggestions.map((suggestion, suggIndex) => (
                            <li key={suggIndex}>{suggestion}</li>
                          ))}
                        </ul>
                      </AlertDescription>
                    )}
                  </Alert>
                ))}
              </div>
            )}

            {/* Filter Controls */}
            <div className="space-y-4">
              <div className="flex space-x-2">
                <Input
                  placeholder="Search permissions..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="flex-1"
                />
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="border rounded px-3 py-2"
                >
                  <option value="all">All Categories</option>
                  <option value="Flow Management">Flow Management</option>
                  <option value="Workspace Management">
                    Workspace Management
                  </option>
                  <option value="Project Management">Project Management</option>
                </select>
              </div>

              <div className="flex items-center space-x-4">
                <label className="flex items-center space-x-2">
                  <Checkbox
                    checked={showDangerous}
                    onCheckedChange={setShowDangerous}
                  />
                  <span className="text-sm">
                    Show dangerous permissions only
                  </span>
                </label>
              </div>

              {/* Bulk Actions */}
              <div className="flex space-x-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleBulkAction("selectSafe")}
                >
                  Select Safe Only
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleBulkAction("selectBasic")}
                >
                  Select Flow Management Only
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleBulkAction("selectAll")}
                >
                  Select All
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleBulkAction("selectNone")}
                >
                  Clear All
                </Button>
              </div>
            </div>

            {/* Permissions List */}
            <div className="border rounded-lg max-h-96 overflow-y-auto">
              {isLoading ? (
                <div className="p-4 text-center text-gray-500">
                  <IconComponent
                    name="Loader2"
                    className="h-4 w-4 animate-spin mx-auto mb-2"
                  />
                  Loading permissions...
                </div>
              ) : filteredPermissions.length === 0 ? (
                <div className="p-4 text-center text-gray-500">
                  No permissions found matching current filters
                </div>
              ) : (
                <div className="divide-y">
                  {filteredPermissions.map((permission) => {
                    const isSelected = selectedPermissions.includes(
                      permission.id,
                    );

                    return (
                      <div
                        key={permission.id}
                        className={`p-3 hover:bg-gray-50 ${isSelected ? "bg-blue-50" : ""}`}
                      >
                        <label className="flex items-start space-x-3 cursor-pointer">
                          <Checkbox
                            checked={isSelected}
                            onCheckedChange={() =>
                              handlePermissionToggle(permission.id)
                            }
                            className="mt-1"
                          />

                          <div className="flex-1 min-w-0">
                            <div className="flex items-center space-x-2">
                              <span className="font-medium">
                                {permission.code || `${permission.action}:${permission.resource_type}`}
                              </span>

                              <Badge variant="outline" className="text-xs">
                                {permission.category}
                              </Badge>

                              {permission.is_dangerous && (
                                <Badge
                                  variant="destructive"
                                  className="text-xs"
                                >
                                  Dangerous
                                </Badge>
                              )}

                              {permission.requires_mfa && (
                                <Badge variant="secondary" className="text-xs">
                                  MFA Required
                                </Badge>
                              )}

                              {permission.is_system && (
                                <Badge variant="outline" className="text-xs">
                                  System
                                </Badge>
                              )}
                            </div>

                            <p className="text-sm text-gray-600 mt-1">
                              {permission.description}
                            </p>

                            {permission.compliance_tags &&
                              permission.compliance_tags.length > 0 && (
                                <div className="flex space-x-1 mt-2">
                                  {permission.compliance_tags.map((tag) => (
                                    <Badge
                                      key={tag}
                                      variant="outline"
                                      className="text-xs"
                                    >
                                      {tag}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                          </div>
                        </label>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Summary */}
            <div className="border-t pt-4">
              <div className="flex items-center justify-between text-sm">
                <div className="space-x-4">
                  <span>Selected: {selectedPermissions.length}</span>
                  <span>
                    Dangerous:{" "}
                    {
                      permissions.filter(
                        (p) =>
                          selectedPermissions.includes(p.id) && p.is_dangerous,
                      ).length
                    }
                  </span>
                  <span>
                    MFA Required:{" "}
                    {
                      permissions.filter(
                        (p) =>
                          selectedPermissions.includes(p.id) && p.requires_mfa,
                      ).length
                    }
                  </span>
                </div>

                {summary.errors > 0 && (
                  <Badge variant="destructive" className="text-xs">
                    Role cannot be created with errors
                  </Badge>
                )}
              </div>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}
