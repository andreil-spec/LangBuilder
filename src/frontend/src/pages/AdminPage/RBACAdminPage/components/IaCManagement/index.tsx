import {
  AlertTriangle,
  Check,
  Code,
  Download,
  Eye,
  FileText,
  Settings,
  Upload,
  X,
} from "lucide-react";
import React, { useCallback, useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
import { useToast } from "@/components/ui/use-toast";
import { useRBACIaC } from "../hooks/useRBACIaC";

interface IaCManagementProps {
  workspaceId?: string;
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

interface ImportResult {
  success: boolean;
  message: string;
  created_roles: number;
  updated_roles: number;
  created_permissions: number;
  updated_permissions: number;
  created_assignments: number;
  updated_assignments: number;
  created_groups: number;
  updated_groups: number;
  errors: string[];
  warnings: string[];
}

export const IaCManagement: React.FC<IaCManagementProps> = ({
  workspaceId,
}) => {
  const { toast } = useToast();
  const {
    exportWorkspaceConfig,
    exportGlobalConfig,
    validateConfig,
    previewImport,
    applyImport,
    listTemplates,
    generateTemplate,
    isLoading,
  } = useRBACIaC();

  const [exportFormat, setExportFormat] = useState<
    "yaml" | "json" | "terraform"
  >("yaml");
  const [includeSystem, setIncludeSystem] = useState(false);
  const [configText, setConfigText] = useState("");
  const [validationResult, setValidationResult] =
    useState<ValidationResult | null>(null);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [previewData, setPreviewData] = useState<any>(null);
  const [selectedTemplate, setSelectedTemplate] = useState("");
  const [templateWorkspace, setTemplateWorkspace] = useState("");

  // Export functionality
  const handleExportWorkspace = useCallback(async () => {
    if (!workspaceId) {
      toast({
        title: "Error",
        description: "No workspace selected for export",
        variant: "destructive",
      });
      return;
    }

    try {
      const blob = await exportWorkspaceConfig(
        workspaceId,
        exportFormat,
        includeSystem,
      );
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `workspace-${workspaceId}-rbac.${exportFormat === "terraform" ? "tf" : exportFormat}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      toast({
        title: "Export Successful",
        description: `Workspace RBAC configuration exported as ${exportFormat.toUpperCase()}`,
      });
    } catch (error) {
      toast({
        title: "Export Failed",
        description:
          error instanceof Error ? error.message : "An error occurred",
        variant: "destructive",
      });
    }
  }, [workspaceId, exportFormat, includeSystem, exportWorkspaceConfig, toast]);

  const handleExportGlobal = useCallback(async () => {
    try {
      const blob = await exportGlobalConfig(exportFormat, includeSystem);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `global-rbac.${exportFormat === "terraform" ? "tf" : exportFormat}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      toast({
        title: "Export Successful",
        description: `Global RBAC configuration exported as ${exportFormat.toUpperCase()}`,
      });
    } catch (error) {
      toast({
        title: "Export Failed",
        description:
          error instanceof Error ? error.message : "An error occurred",
        variant: "destructive",
      });
    }
  }, [exportFormat, includeSystem, exportGlobalConfig, toast]);

  // Validation functionality
  const handleValidate = useCallback(async () => {
    if (!configText.trim()) {
      toast({
        title: "Validation Error",
        description: "Please enter a configuration to validate",
        variant: "destructive",
      });
      return;
    }

    try {
      const result = await validateConfig(configText);
      setValidationResult(result);

      if (result.valid) {
        toast({
          title: "Validation Successful",
          description: "Configuration is valid",
        });
      } else {
        toast({
          title: "Validation Failed",
          description: `Found ${result.errors.length} error(s)`,
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Validation Failed",
        description:
          error instanceof Error ? error.message : "An error occurred",
        variant: "destructive",
      });
    }
  }, [configText, validateConfig, toast]);

  // Preview functionality
  const handlePreview = useCallback(async () => {
    if (!configText.trim()) {
      toast({
        title: "Preview Error",
        description: "Please enter a configuration to preview",
        variant: "destructive",
      });
      return;
    }

    try {
      const result = await previewImport(configText, workspaceId);
      setPreviewData(result);

      toast({
        title: "Preview Generated",
        description: `Found ${result.summary.total_changes} potential changes`,
      });
    } catch (error) {
      toast({
        title: "Preview Failed",
        description:
          error instanceof Error ? error.message : "An error occurred",
        variant: "destructive",
      });
    }
  }, [configText, workspaceId, previewImport, toast]);

  // Import functionality
  const handleImport = useCallback(
    async (dryRun: boolean = false) => {
      if (!configText.trim()) {
        toast({
          title: "Import Error",
          description: "Please enter a configuration to import",
          variant: "destructive",
        });
        return;
      }

      try {
        const result = await applyImport(configText, workspaceId, dryRun);
        setImportResult(result);

        if (result.success) {
          const action = dryRun ? "validated" : "imported";
          const summary = `${result.created_roles + result.updated_roles} roles, ${result.created_permissions + result.updated_permissions} permissions, ${result.created_assignments + result.updated_assignments} assignments, ${result.created_groups + result.updated_groups} groups`;

          toast({
            title: `Import ${dryRun ? "Validation" : "Completion"} Successful`,
            description: `Successfully ${action}: ${summary}`,
          });
        } else {
          toast({
            title: "Import Failed",
            description: result.message,
            variant: "destructive",
          });
        }
      } catch (error) {
        toast({
          title: "Import Failed",
          description:
            error instanceof Error ? error.message : "An error occurred",
          variant: "destructive",
        });
      }
    },
    [configText, workspaceId, applyImport, toast],
  );

  // Template functionality
  const handleGenerateTemplate = useCallback(async () => {
    if (!selectedTemplate || !templateWorkspace) {
      toast({
        title: "Template Error",
        description: "Please select a template and enter a workspace name",
        variant: "destructive",
      });
      return;
    }

    try {
      const blob = await generateTemplate(
        selectedTemplate,
        templateWorkspace,
        true,
      );
      const text = await blob.text();
      setConfigText(text);

      toast({
        title: "Template Generated",
        description: `Generated ${selectedTemplate} template for ${templateWorkspace}`,
      });
    } catch (error) {
      toast({
        title: "Template Generation Failed",
        description:
          error instanceof Error ? error.message : "An error occurred",
        variant: "destructive",
      });
    }
  }, [selectedTemplate, templateWorkspace, generateTemplate, toast]);

  // File upload functionality
  const handleFileUpload = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setConfigText(content);
        toast({
          title: "File Loaded",
          description: `Loaded ${file.name}`,
        });
      };
      reader.readAsText(file);
    },
    [toast],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Infrastructure as Code</h3>
          <p className="text-sm text-muted-foreground">
            Manage RBAC policies using YAML/JSON configurations and Terraform
          </p>
        </div>
      </div>

      <Tabs defaultValue="export" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="export">Export</TabsTrigger>
          <TabsTrigger value="import">Import</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="terraform">Terraform</TabsTrigger>
        </TabsList>

        <TabsContent value="export" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Download className="h-4 w-4" />
                Export RBAC Configuration
              </CardTitle>
              <CardDescription>
                Export current RBAC policies as YAML, JSON, or Terraform
                configuration
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="export-format">Export Format</Label>
                  <Select
                    value={exportFormat}
                    onValueChange={(value: "yaml" | "json" | "terraform") =>
                      setExportFormat(value)
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="yaml">YAML</SelectItem>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="terraform">Terraform HCL</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Options</Label>
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="include-system"
                      checked={includeSystem}
                      onChange={(e) => setIncludeSystem(e.target.checked)}
                    />
                    <Label htmlFor="include-system">Include system roles</Label>
                  </div>
                </div>
              </div>

              <div className="flex gap-2">
                <Button
                  onClick={handleExportWorkspace}
                  disabled={!workspaceId || isLoading}
                >
                  <FileText className="h-4 w-4 mr-2" />
                  Export Workspace
                </Button>
                <Button
                  onClick={handleExportGlobal}
                  variant="outline"
                  disabled={isLoading}
                >
                  <Settings className="h-4 w-4 mr-2" />
                  Export Global
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="import" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="h-4 w-4" />
                Import RBAC Configuration
              </CardTitle>
              <CardDescription>
                Import RBAC policies from YAML or JSON configuration
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="config-upload">Upload Configuration File</Label>
                <Input
                  id="config-upload"
                  type="file"
                  accept=".yaml,.yml,.json"
                  onChange={handleFileUpload}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="config-text">Configuration</Label>
                <Textarea
                  id="config-text"
                  placeholder="Paste your YAML or JSON configuration here..."
                  value={configText}
                  onChange={(e) => setConfigText(e.target.value)}
                  className="min-h-[300px] font-mono"
                />
              </div>

              <div className="flex gap-2">
                <Button
                  onClick={handleValidate}
                  variant="outline"
                  disabled={!configText.trim() || isLoading}
                >
                  <Check className="h-4 w-4 mr-2" />
                  Validate
                </Button>
                <Button
                  onClick={handlePreview}
                  variant="outline"
                  disabled={!configText.trim() || isLoading}
                >
                  <Eye className="h-4 w-4 mr-2" />
                  Preview
                </Button>
                <Button
                  onClick={() => handleImport(true)}
                  disabled={!configText.trim() || isLoading}
                >
                  <Code className="h-4 w-4 mr-2" />
                  Dry Run
                </Button>
                <Button
                  onClick={() => handleImport(false)}
                  disabled={!configText.trim() || isLoading}
                >
                  <Upload className="h-4 w-4 mr-2" />
                  Import
                </Button>
              </div>

              {/* Validation Results */}
              {validationResult && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      {validationResult.valid ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <X className="h-4 w-4 text-red-500" />
                      )}
                      Validation Result
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {validationResult.valid ? (
                      <Alert>
                        <Check className="h-4 w-4" />
                        <AlertDescription>
                          Configuration is valid
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <div className="space-y-2">
                        {validationResult.errors.map((error, index) => (
                          <Alert key={index} variant="destructive">
                            <X className="h-4 w-4" />
                            <AlertDescription>{error}</AlertDescription>
                          </Alert>
                        ))}
                        {validationResult.warnings.map((warning, index) => (
                          <Alert key={index}>
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription>{warning}</AlertDescription>
                          </Alert>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Preview Results */}
              {previewData && (
                <Card>
                  <CardHeader>
                    <CardTitle>Import Preview</CardTitle>
                    <CardDescription>
                      Changes that will be applied (
                      {previewData.summary.total_changes} total)
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4">
                      {Object.entries(previewData.changes).map(
                        ([section, changes]: [string, any]) => (
                          <div key={section} className="space-y-2">
                            <h4 className="font-medium capitalize">
                              {section}
                            </h4>
                            <div className="space-y-1">
                              {changes.create.length > 0 && (
                                <div className="flex items-center gap-2">
                                  <Badge
                                    variant="outline"
                                    className="text-green-600"
                                  >
                                    Create: {changes.create.length}
                                  </Badge>
                                </div>
                              )}
                              {changes.update.length > 0 && (
                                <div className="flex items-center gap-2">
                                  <Badge
                                    variant="outline"
                                    className="text-blue-600"
                                  >
                                    Update: {changes.update.length}
                                  </Badge>
                                </div>
                              )}
                              {changes.delete.length > 0 && (
                                <div className="flex items-center gap-2">
                                  <Badge
                                    variant="outline"
                                    className="text-red-600"
                                  >
                                    Delete: {changes.delete.length}
                                  </Badge>
                                </div>
                              )}
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Import Results */}
              {importResult && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      {importResult.success ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <X className="h-4 w-4 text-red-500" />
                      )}
                      Import Result
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Alert
                      variant={importResult.success ? "default" : "destructive"}
                    >
                      <AlertDescription>
                        {importResult.message}
                      </AlertDescription>
                    </Alert>

                    {importResult.success && (
                      <div className="mt-4 grid grid-cols-2 gap-4">
                        <div>
                          <h5 className="font-medium">Created</h5>
                          <ul className="text-sm text-muted-foreground">
                            <li>Roles: {importResult.created_roles}</li>
                            <li>
                              Permissions: {importResult.created_permissions}
                            </li>
                            <li>
                              Assignments: {importResult.created_assignments}
                            </li>
                            <li>Groups: {importResult.created_groups}</li>
                          </ul>
                        </div>
                        <div>
                          <h5 className="font-medium">Updated</h5>
                          <ul className="text-sm text-muted-foreground">
                            <li>Roles: {importResult.updated_roles}</li>
                            <li>
                              Permissions: {importResult.updated_permissions}
                            </li>
                            <li>
                              Assignments: {importResult.updated_assignments}
                            </li>
                            <li>Groups: {importResult.updated_groups}</li>
                          </ul>
                        </div>
                      </div>
                    )}

                    {importResult.errors.length > 0 && (
                      <div className="mt-4 space-y-2">
                        <h5 className="font-medium text-red-600">Errors</h5>
                        {importResult.errors.map((error, index) => (
                          <Alert key={index} variant="destructive">
                            <AlertDescription>{error}</AlertDescription>
                          </Alert>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="templates" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Configuration Templates</CardTitle>
              <CardDescription>
                Generate RBAC configurations from predefined templates
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="template-type">Template Type</Label>
                  <Select
                    value={selectedTemplate}
                    onValueChange={setSelectedTemplate}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select a template" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="basic">Basic Workspace</SelectItem>
                      <SelectItem value="advanced">
                        Advanced Workspace
                      </SelectItem>
                      <SelectItem value="enterprise">
                        Enterprise Workspace
                      </SelectItem>
                      <SelectItem value="service-account">
                        Service Account
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="template-workspace">Workspace Name</Label>
                  <Input
                    id="template-workspace"
                    placeholder="Enter workspace name"
                    value={templateWorkspace}
                    onChange={(e) => setTemplateWorkspace(e.target.value)}
                  />
                </div>
              </div>

              <Button
                onClick={handleGenerateTemplate}
                disabled={!selectedTemplate || !templateWorkspace || isLoading}
              >
                <FileText className="h-4 w-4 mr-2" />
                Generate Template
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="terraform" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Terraform Integration</CardTitle>
              <CardDescription>
                Manage RBAC policies using Terraform infrastructure-as-code
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  Terraform provider for LangBuilder is in development. You can
                  export configurations as Terraform HCL format using the Export
                  tab.
                </AlertDescription>
              </Alert>

              <div className="space-y-2">
                <Label>Terraform Provider Setup</Label>
                <Textarea
                  readOnly
                  value={`terraform {
  required_providers {
    langflow = {
      source  = "langflow/langflow"
      version = "~> 1.0"
    }
  }
}

provider "langflow" {
  api_url   = var.langflow_api_url
  api_token = var.langflow_api_token
}`}
                  className="font-mono text-sm"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};
