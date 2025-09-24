import { useEffect, useState } from "react";
import { useRBAC } from "../../../contexts/rbacContext";

interface PermissionGuardProps {
  permission: string;
  scope_type?: string;
  scope_id?: string;
  resource_type?: string;
  resource_id?: string;
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

export default function PermissionGuard({
  permission,
  scope_type,
  scope_id,
  resource_type,
  resource_id,
  fallback = null,
  children,
}: PermissionGuardProps) {
  const { hasPermission: checkPermission, isLoading } = useRBAC();

  // Use the hasPermission function directly
  const hasAccess = checkPermission(
    resource_type || "global",
    permission,
    resource_id,
  );

  if (isLoading) {
    return <div className="opacity-50">{children}</div>;
  }

  if (!hasAccess) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}
