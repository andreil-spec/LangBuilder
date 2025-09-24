import { useState } from "react";
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
import { Permission } from "../../types/rbac";

interface ConfirmDeleteModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  permission: Permission | null;
  onConfirm: () => void;
}

export default function ConfirmDeleteModal({
  open,
  onOpenChange,
  permission,
  onConfirm,
}: ConfirmDeleteModalProps) {
  const [loading, setLoading] = useState(false);

  const handleConfirm = async () => {
    setLoading(true);
    try {
      onConfirm();
      onOpenChange(false);
    } catch (error) {
      console.error("Failed to delete permission:", error);
    } finally {
      setLoading(false);
    }
  };

  if (!permission) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <IconComponent
              name="AlertTriangle"
              className="h-5 w-5 text-red-500"
            />
            <span>Delete Permission</span>
          </DialogTitle>
          <DialogDescription>
            Are you sure you want to delete this permission? This action cannot
            be undone.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-4">
          <div className="bg-muted/50 p-3 rounded-lg">
            <div className="flex items-center space-x-2 mb-2">
              <code className="text-sm bg-muted px-2 py-1 rounded">
                {permission.action}
              </code>
              <span className="text-sm text-muted-foreground">on</span>
              <code className="text-sm bg-muted px-2 py-1 rounded">
                {permission.resource_type}
              </code>
            </div>
            <p className="text-sm text-muted-foreground">
              {permission.description}
            </p>
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
          <Button
            variant="destructive"
            onClick={handleConfirm}
            disabled={loading}
          >
            {loading ? (
              <>
                <IconComponent
                  name="Loader2"
                  className="h-4 w-4 mr-2 animate-spin"
                />
                Deleting...
              </>
            ) : (
              <>
                <IconComponent name="Trash2" className="h-4 w-4 mr-2" />
                Delete Permission
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
