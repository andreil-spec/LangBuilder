// SSO Configuration Panel - Enterprise Integration Phase 2.1
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
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useGetAutoLogin } from "@/controllers/API/queries/auth";
import useAuthStore from "@/stores/authStore";
import AuthenticationModal from "../../../RBAC/components/AuthenticationModal";

// Types for SSO Configuration
interface SSOProvider {
  id: string;
  name: string;
  type: "oidc" | "saml";
  enabled: boolean;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

interface OIDCConfig {
  client_id: string;
  client_secret: string;
  discovery_url: string;
  scopes: string[];
  user_info_url?: string;
  jwks_uri?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
}

interface SAMLConfig {
  entity_id: string;
  sso_url: string;
  slo_url?: string;
  certificate: string;
  private_key?: string;
  name_id_format: string;
  sign_requests: boolean;
  encrypt_assertions: boolean;
}

interface GroupMapping {
  id: string;
  provider_group: string;
  langflow_role: string;
  workspace_id?: string;
  auto_provision: boolean;
}

export default function SSOConfiguration() {
  // Authentication state - following AccountMenu pattern
  const { isAdmin } = useAuthStore((state) => ({
    isAdmin: state.isAdmin,
  }));

  // Component state
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [activeProvider, setActiveProvider] = useState<string>("new");
  const [providerType, setProviderType] = useState<"oidc" | "saml">("oidc");
  const [isTestingConnection, setIsTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  // Mock data for demonstration (in real implementation, this would come from API)
  const [providers, setProviders] = useState<SSOProvider[]>([
    {
      id: "1",
      name: "Azure Active Directory",
      type: "oidc",
      enabled: true,
      metadata: {
        client_id: "azure-client-123",
        discovery_url:
          "https://login.microsoftonline.com/tenant/.well-known/openid_configuration",
      },
      created_at: "2024-01-15T10:00:00Z",
      updated_at: "2024-01-20T15:30:00Z",
    },
    {
      id: "2",
      name: "Okta SAML",
      type: "saml",
      enabled: false,
      metadata: {
        entity_id: "http://www.okta.com/exkexample",
        sso_url:
          "https://dev-123456.okta.com/app/dev-123456_langflow_1/exkexample/sso/saml",
      },
      created_at: "2024-01-10T08:00:00Z",
      updated_at: "2024-01-10T08:00:00Z",
    },
  ]);

  const [groupMappings, setGroupMappings] = useState<GroupMapping[]>([
    {
      id: "1",
      provider_group: "Langflow-Admins",
      langflow_role: "admin",
      workspace_id: "default",
      auto_provision: true,
    },
    {
      id: "2",
      provider_group: "Langflow-Users",
      langflow_role: "user",
      workspace_id: "default",
      auto_provision: true,
    },
  ]);

  // Form states for OIDC/SAML configuration
  const [oidcConfig, setOIDCConfig] = useState<Partial<OIDCConfig>>({
    client_id: "",
    client_secret: "",
    discovery_url: "",
    scopes: ["openid", "profile", "email"],
  });

  const [samlConfig, setSAMLConfig] = useState<Partial<SAMLConfig>>({
    entity_id: "",
    sso_url: "",
    slo_url: "",
    certificate: "",
    name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    sign_requests: true,
    encrypt_assertions: false,
  });

  // Auto-login query
  const { data: autoLoginData, isSuccess: autoLoginSuccess } = useGetAutoLogin({
    retry: 3,
    retryDelay: 1000,
  });

  const requireAuth = (action: string, callback: () => void) => {
    if (!isAdmin) {
      setShowAuthModal(true);
    } else {
      callback();
    }
  };

  const handleTestConnection = () => {
    requireAuth("test-sso-connection", async () => {
      setIsTestingConnection(true);

      // Simulate API call
      setTimeout(() => {
        const success = Math.random() > 0.3; // 70% success rate for demo
        setTestResult({
          success,
          message: success
            ? "✅ Connection successful! SSO provider is reachable and properly configured."
            : "❌ Connection failed. Please check your configuration and try again.",
        });
        setIsTestingConnection(false);
      }, 2000);
    });
  };

  const handleSaveProvider = () => {
    requireAuth("save-sso-provider", () => {
      // In real implementation, this would call the SSO configuration API
      console.log("Saving SSO provider configuration:", {
        type: providerType,
        oidc: oidcConfig,
        saml: samlConfig,
      });

      // Show success message
      setTestResult({
        success: true,
        message: "✅ SSO provider configuration saved successfully!",
      });
    });
  };

  const handleToggleProvider = (providerId: string) => {
    requireAuth("toggle-sso-provider", () => {
      setProviders((prev) =>
        prev.map((p) =>
          p.id === providerId ? { ...p, enabled: !p.enabled } : p,
        ),
      );
    });
  };

  const handleAddGroupMapping = () => {
    requireAuth("add-group-mapping", () => {
      const newMapping: GroupMapping = {
        id: Date.now().toString(),
        provider_group: "New-Group",
        langflow_role: "user",
        workspace_id: "default",
        auto_provision: true,
      };
      setGroupMappings((prev) => [...prev, newMapping]);
    });
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold flex items-center space-x-2">
            <IconComponent name="Shield" className="h-5 w-5" />
            <span>SSO Configuration</span>
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Configure OIDC and SAML identity providers for enterprise
            authentication
          </p>
        </div>
      </div>

      <Tabs
        value={activeProvider}
        onValueChange={setActiveProvider}
        className="space-y-4"
      >
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="providers">
            <IconComponent name="Building" className="h-4 w-4 mr-2" />
            Providers
          </TabsTrigger>
          <TabsTrigger value="new">
            <IconComponent name="Plus" className="h-4 w-4 mr-2" />
            New Provider
          </TabsTrigger>
          <TabsTrigger value="mappings">
            <IconComponent name="Users" className="h-4 w-4 mr-2" />
            Group Mappings
          </TabsTrigger>
          <TabsTrigger value="testing">
            <IconComponent name="TestTube" className="h-4 w-4 mr-2" />
            Test Connection
          </TabsTrigger>
        </TabsList>

        {/* Existing Providers */}
        <TabsContent value="providers" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Configured SSO Providers</CardTitle>
              <CardDescription>
                Manage your existing OIDC and SAML identity providers
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {providers.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <IconComponent
                    name="Building"
                    className="h-8 w-8 mx-auto mb-2"
                  />
                  <p>No SSO providers configured</p>
                  <Button
                    variant="outline"
                    onClick={() => setActiveProvider("new")}
                    className="mt-2"
                  >
                    Add First Provider
                  </Button>
                </div>
              ) : (
                providers.map((provider) => (
                  <div
                    key={provider.id}
                    className="flex items-center justify-between p-4 border rounded-lg"
                  >
                    <div className="flex items-center space-x-4">
                      <IconComponent
                        name={provider.type === "oidc" ? "Key" : "Certificate"}
                        className="h-5 w-5"
                      />
                      <div>
                        <h3 className="font-medium">{provider.name}</h3>
                        <div className="flex items-center space-x-2 text-sm text-gray-500">
                          <Badge variant="outline" className="text-xs">
                            {provider.type.toUpperCase()}
                          </Badge>
                          <span>
                            Updated{" "}
                            {new Date(provider.updated_at).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge
                        variant={provider.enabled ? "default" : "secondary"}
                        className="text-xs"
                      >
                        {provider.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleToggleProvider(provider.id)}
                        disabled={!isAdmin}
                      >
                        {provider.enabled ? "Disable" : "Enable"}
                      </Button>
                      <Button variant="ghost" size="sm">
                        <IconComponent name="Settings" className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* New Provider Configuration */}
        <TabsContent value="new" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Add New SSO Provider</CardTitle>
              <CardDescription>
                Configure a new OIDC or SAML identity provider
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Provider Type Selection */}
              <div className="space-y-2">
                <Label>Provider Type</Label>
                <Select
                  value={providerType}
                  onValueChange={(value: "oidc" | "saml") =>
                    setProviderType(value)
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="oidc">
                      <div className="flex items-center space-x-2">
                        <IconComponent name="Key" className="h-4 w-4" />
                        <span>OIDC (OpenID Connect)</span>
                      </div>
                    </SelectItem>
                    <SelectItem value="saml">
                      <div className="flex items-center space-x-2">
                        <IconComponent name="Certificate" className="h-4 w-4" />
                        <span>SAML 2.0</span>
                      </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Separator />

              {/* OIDC Configuration */}
              {providerType === "oidc" && (
                <div className="space-y-4">
                  <h3 className="text-lg font-medium">OIDC Configuration</h3>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="oidc-client-id">Client ID *</Label>
                      <Input
                        id="oidc-client-id"
                        value={oidcConfig.client_id || ""}
                        onChange={(e) =>
                          setOIDCConfig((prev) => ({
                            ...prev,
                            client_id: e.target.value,
                          }))
                        }
                        placeholder="your-client-id"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="oidc-client-secret">
                        Client Secret *
                      </Label>
                      <Input
                        id="oidc-client-secret"
                        type="password"
                        value={oidcConfig.client_secret || ""}
                        onChange={(e) =>
                          setOIDCConfig((prev) => ({
                            ...prev,
                            client_secret: e.target.value,
                          }))
                        }
                        placeholder="your-client-secret"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="oidc-discovery-url">Discovery URL *</Label>
                    <Input
                      id="oidc-discovery-url"
                      value={oidcConfig.discovery_url || ""}
                      onChange={(e) =>
                        setOIDCConfig((prev) => ({
                          ...prev,
                          discovery_url: e.target.value,
                        }))
                      }
                      placeholder="https://your-provider.com/.well-known/openid_configuration"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="oidc-scopes">Scopes</Label>
                    <Input
                      id="oidc-scopes"
                      value={oidcConfig.scopes?.join(" ") || ""}
                      onChange={(e) =>
                        setOIDCConfig((prev) => ({
                          ...prev,
                          scopes: e.target.value
                            .split(" ")
                            .filter((s) => s.trim()),
                        }))
                      }
                      placeholder="openid profile email"
                    />
                    <p className="text-xs text-gray-500">
                      Space-separated list of OAuth 2.0 scopes
                    </p>
                  </div>
                </div>
              )}

              {/* SAML Configuration */}
              {providerType === "saml" && (
                <div className="space-y-4">
                  <h3 className="text-lg font-medium">SAML Configuration</h3>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="saml-entity-id">Entity ID *</Label>
                      <Input
                        id="saml-entity-id"
                        value={samlConfig.entity_id || ""}
                        onChange={(e) =>
                          setSAMLConfig((prev) => ({
                            ...prev,
                            entity_id: e.target.value,
                          }))
                        }
                        placeholder="http://www.okta.com/exkexample"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="saml-name-id-format">
                        Name ID Format
                      </Label>
                      <Select
                        value={samlConfig.name_id_format}
                        onValueChange={(value) =>
                          setSAMLConfig((prev) => ({
                            ...prev,
                            name_id_format: value,
                          }))
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                            Email Address
                          </SelectItem>
                          <SelectItem value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
                            Persistent
                          </SelectItem>
                          <SelectItem value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
                            Transient
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="saml-sso-url">SSO URL *</Label>
                    <Input
                      id="saml-sso-url"
                      value={samlConfig.sso_url || ""}
                      onChange={(e) =>
                        setSAMLConfig((prev) => ({
                          ...prev,
                          sso_url: e.target.value,
                        }))
                      }
                      placeholder="https://your-provider.com/app/langflow/sso/saml"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="saml-slo-url">SLO URL (Optional)</Label>
                    <Input
                      id="saml-slo-url"
                      value={samlConfig.slo_url || ""}
                      onChange={(e) =>
                        setSAMLConfig((prev) => ({
                          ...prev,
                          slo_url: e.target.value,
                        }))
                      }
                      placeholder="https://your-provider.com/app/langflow/slo/saml"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="saml-certificate">
                      X.509 Certificate *
                    </Label>
                    <Textarea
                      id="saml-certificate"
                      value={samlConfig.certificate || ""}
                      onChange={(e) =>
                        setSAMLConfig((prev) => ({
                          ...prev,
                          certificate: e.target.value,
                        }))
                      }
                      placeholder="-----BEGIN CERTIFICATE-----&#10;MIIBXTCCAQOgAwIBAgIJALEtKXtl...&#10;-----END CERTIFICATE-----"
                      rows={6}
                    />
                  </div>
                </div>
              )}

              <div className="flex space-x-2">
                <Button
                  onClick={handleSaveProvider}
                  disabled={!isAdmin}
                  className="flex-1"
                >
                  <IconComponent name="Save" className="h-4 w-4 mr-2" />
                  Save Provider
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setActiveProvider("testing")}
                  disabled={!isAdmin}
                >
                  <IconComponent name="TestTube" className="h-4 w-4 mr-2" />
                  Test Configuration
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Group Mappings */}
        <TabsContent value="mappings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Group Mappings</CardTitle>
              <CardDescription>
                Map identity provider groups to Langflow roles and workspaces
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between items-center">
                <p className="text-sm text-gray-600">
                  Configure automatic role assignment based on user groups from
                  your identity provider
                </p>
                <Button
                  onClick={handleAddGroupMapping}
                  disabled={!isAdmin}
                  size="sm"
                >
                  <IconComponent name="Plus" className="h-4 w-4 mr-2" />
                  Add Mapping
                </Button>
              </div>

              <div className="space-y-3">
                {groupMappings.map((mapping) => (
                  <div
                    key={mapping.id}
                    className="grid grid-cols-5 gap-4 p-3 border rounded-lg items-center"
                  >
                    <div>
                      <Label className="text-xs text-gray-500">
                        Provider Group
                      </Label>
                      <p className="font-medium">{mapping.provider_group}</p>
                    </div>
                    <div>
                      <Label className="text-xs text-gray-500">
                        Langflow Role
                      </Label>
                      <Badge variant="secondary">{mapping.langflow_role}</Badge>
                    </div>
                    <div>
                      <Label className="text-xs text-gray-500">Workspace</Label>
                      <p className="text-sm">{mapping.workspace_id}</p>
                    </div>
                    <div>
                      <Label className="text-xs text-gray-500">
                        Auto Provision
                      </Label>
                      <Badge
                        variant={mapping.auto_provision ? "default" : "outline"}
                        className="text-xs"
                      >
                        {mapping.auto_provision ? "Yes" : "No"}
                      </Badge>
                    </div>
                    <div className="flex space-x-1">
                      <Button variant="ghost" size="sm">
                        <IconComponent name="Edit" className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="sm">
                        <IconComponent name="Trash" className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Test Connection */}
        <TabsContent value="testing" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Test SSO Connection</CardTitle>
              <CardDescription>
                Validate your SSO configuration and test the connection
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="text-center space-y-4">
                <div className="p-6 border-2 border-dashed rounded-lg">
                  <IconComponent
                    name={isTestingConnection ? "Loader2" : "TestTube"}
                    className={`h-8 w-8 mx-auto mb-3 ${
                      isTestingConnection ? "animate-spin" : ""
                    }`}
                  />
                  <h3 className="text-lg font-medium mb-2">
                    {isTestingConnection
                      ? "Testing Connection..."
                      : "Ready to Test"}
                  </h3>
                  <p className="text-gray-600 mb-4">
                    {isTestingConnection
                      ? "Validating SSO provider configuration and connectivity"
                      : "Click the button below to test your SSO configuration"}
                  </p>

                  <Button
                    onClick={handleTestConnection}
                    disabled={!isAdmin || isTestingConnection}
                    size="lg"
                  >
                    {isTestingConnection ? (
                      <>
                        <IconComponent
                          name="Loader2"
                          className="h-4 w-4 mr-2 animate-spin"
                        />
                        Testing...
                      </>
                    ) : (
                      <>
                        <IconComponent name="Play" className="h-4 w-4 mr-2" />
                        Test Connection
                      </>
                    )}
                  </Button>
                </div>

                {testResult && (
                  <div
                    className={`p-4 rounded-lg ${
                      testResult.success
                        ? "bg-green-50 border border-green-200"
                        : "bg-red-50 border border-red-200"
                    }`}
                  >
                    <p
                      className={`${
                        testResult.success ? "text-green-800" : "text-red-800"
                      }`}
                    >
                      {testResult.message}
                    </p>
                  </div>
                )}
              </div>

              <Separator />

              <div className="space-y-3">
                <h4 className="font-medium">Test Checklist</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center space-x-2">
                    <IconComponent
                      name="Check"
                      className="h-4 w-4 text-green-500"
                    />
                    <span>Provider configuration validation</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <IconComponent
                      name="Check"
                      className="h-4 w-4 text-green-500"
                    />
                    <span>Network connectivity test</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <IconComponent
                      name="Check"
                      className="h-4 w-4 text-green-500"
                    />
                    <span>Certificate/metadata validation</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <IconComponent
                      name="Check"
                      className="h-4 w-4 text-green-500"
                    />
                    <span>Group mapping verification</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Authentication Modal */}
      <AuthenticationModal
        open={showAuthModal}
        onOpenChange={setShowAuthModal}
        onSuccess={() => {
          // Refresh any data if needed
        }}
      />
    </div>
  );
}
