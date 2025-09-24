import { useState, useEffect } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Permission } from "../../types/rbac";

const AVAILABLE_ACTIONS = [
  "create",
  "read",
  "update",
  "delete",
  "export_flow",
  "deploy_environment",
  "invite_users",
  "modify_component_settings",
  "manage_tokens",
];

const AVAILABLE_RESOURCE_TYPES = [
  "flow",
  "component",
  "environment",
  "workspace",
  "project",
  "user",
  "api_key",
];

// Mapping of extended actions to their required resource types (PRD Story 1.1)
const EXTENDED_ACTION_RESOURCE_MAPPING: Record<string, string> = {
  export_flow: "flow",
  deploy_environment: "environment",
  invite_users: "user",
  modify_component_settings: "component",
  manage_tokens: "api_key",
};

// CRUD actions that can work with any resource type
const CRUD_ACTIONS = ["create", "read", "update", "delete"];

interface PermissionEditModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  permission: Permission | null;
  onSave: (permission: Permission) => void;
  mode: "edit" | "create";
}

export default function PermissionEditModal({
  open,
  onOpenChange,
  permission,
  onSave,
  mode,
}: PermissionEditModalProps) {
  const [formData, setFormData] = useState({
    action: permission?.action || "",
    resource_type: permission?.resource_type || "",
    description: permission?.description || "",
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [resourceTypeDisabled, setResourceTypeDisabled] = useState(false);

  // Auto-select resource type when extended action is chosen
  useEffect(() => {
    if (formData.action && EXTENDED_ACTION_RESOURCE_MAPPING[formData.action]) {
      const requiredResourceType = EXTENDED_ACTION_RESOURCE_MAPPING[formData.action];
      setFormData(prev => ({ ...prev, resource_type: requiredResourceType }));
      setResourceTypeDisabled(true);
    } else if (CRUD_ACTIONS.includes(formData.action)) {
      setResourceTypeDisabled(false);
    }
  }, [formData.action]);

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.action) {
      newErrors.action = "Action is required";
    }

    if (!formData.resource_type) {
      newErrors.resource_type = "Resource type is required";
    }

    // Validate extended action-resource type combinations
    if (formData.action && formData.resource_type && EXTENDED_ACTION_RESOURCE_MAPPING[formData.action]) {
      const requiredResourceType = EXTENDED_ACTION_RESOURCE_MAPPING[formData.action];
      if (formData.resource_type !== requiredResourceType) {
        newErrors.resource_type = `Action "${formData.action}" can only be used with resource type "${requiredResourceType}"`;
      }
    }

    if (!formData.description.trim()) {
      newErrors.description = "Description is required";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = async () => {
    if (!validateForm()) return;

    setLoading(true);

    try {
      const updatedPermission: Permission = {
        id: permission?.id || `perm-${Date.now()}`,
        action: formData.action as any,
        resource_type: formData.resource_type,
        description: formData.description.trim(),
        created_at: permission?.created_at || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      onSave(updatedPermission);
      onOpenChange(false);
    } catch (error) {
      console.error("Failed to save permission:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleFieldChange = (field: string, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors((prev) => ({ ...prev, [field]: "" }));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <IconComponent
              name={mode === "create" ? "Plus" : "Edit"}
              className="h-5 w-5"
            />
            <span>
              {mode === "create" ? "Add New Permission" : "Edit Permission"}
            </span>
          </DialogTitle>
          <DialogDescription>
            {mode === "create"
              ? "Create a new permission for the RBAC system. Extended actions will auto-select their required resource type."
              : "Modify the selected permission details."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="action">Action *</Label>
            <Select
              value={formData.action}
              onValueChange={(value) => handleFieldChange("action", value)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select an action" />
              </SelectTrigger>
              <SelectContent>
                {AVAILABLE_ACTIONS.map((action) => (
                  <SelectItem key={action} value={action}>
                    {action}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.action && (
              <p className="text-sm text-red-600">{errors.action}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="resource_type">Resource Type *</Label>
            <Select
              value={formData.resource_type}
              onValueChange={(value) =>
                handleFieldChange("resource_type", value)
              }
              disabled={resourceTypeDisabled}
            >
              <SelectTrigger className={resourceTypeDisabled ? "opacity-50 cursor-not-allowed" : ""}>
                <SelectValue placeholder="Select a resource type" />
              </SelectTrigger>
              <SelectContent>
                {AVAILABLE_RESOURCE_TYPES.map((type) => (
                  <SelectItem key={type} value={type}>
                    {type}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {resourceTypeDisabled && formData.action && EXTENDED_ACTION_RESOURCE_MAPPING[formData.action] && (
              <p className="text-sm text-blue-600 flex items-center">
                <IconComponent name="Info" className="h-4 w-4 mr-1" />
                Action "{formData.action}" requires resource type "{EXTENDED_ACTION_RESOURCE_MAPPING[formData.action]}"
              </p>
            )}
            {errors.resource_type && (
              <p className="text-sm text-red-600">{errors.resource_type}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">Description *</Label>
            <Textarea
              id="description"
              placeholder="Enter permission description"
              value={formData.description}
              onChange={(e) => handleFieldChange("description", e.target.value)}
              rows={3}
            />
            {errors.description && (
              <p className="text-sm text-red-600">{errors.description}</p>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={loading}
          >
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={loading}>
            {loading ? (
              <>
                <IconComponent
                  name="Loader2"
                  className="h-4 w-4 mr-2 animate-spin"
                />
                Saving...
              </>
            ) : (
              <>
                <IconComponent name="Save" className="h-4 w-4 mr-2" />
                {mode === "create" ? "Create Permission" : "Save Changes"}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
