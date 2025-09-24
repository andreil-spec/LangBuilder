import React from "react";
import { useRBAC } from "@/contexts/rbacContext";

interface PermissionGuardProps {
  resource: string;
  action: string;
  resourceId?: string;
  children: React.ReactNode;
  fallback?: React.ReactNode;
  hideIfNoPermission?: boolean;
}

export function PermissionGuard({
  resource,
  action,
  resourceId,
  children,
  fallback = null,
  hideIfNoPermission = true,
}: PermissionGuardProps) {
  const { hasPermission, isLoading } = useRBAC();

  if (isLoading) {
    return null; // or a loading spinner
  }

  const hasAccess = hasPermission(resource, action, resourceId);

  if (!hasAccess) {
    if (hideIfNoPermission) {
      return null;
    }
    return fallback as React.ReactElement;
  }

  return children as React.ReactElement;
}

interface ConditionalPermissionProps {
  resource: string;
  action: string;
  resourceId?: string;
  children: (hasPermission: boolean) => React.ReactNode;
}

export function ConditionalPermission({
  resource,
  action,
  resourceId,
  children,
}: ConditionalPermissionProps) {
  const { hasPermission, isLoading } = useRBAC();

  if (isLoading) {
    return children(false);
  }

  const hasAccess = hasPermission(resource, action, resourceId);
  return children(hasAccess) as React.ReactElement;
}
