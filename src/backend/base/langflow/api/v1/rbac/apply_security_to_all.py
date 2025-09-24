#!/usr/bin/env python3
"""Script to apply security middleware to all RBAC endpoints."""

import os
import re
import sys
from pathlib import Path

# Security decorator configurations for each endpoint type
SECURITY_CONFIGS = {
    # Audit endpoints
    "list_audit_logs": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="audit_log",
        action="read",
        require_workspace_access=True,
        audit_action="read_audit_logs",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    # Environment endpoints
    "create_environment": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="environment",
        action="create",
        require_workspace_access=True,
        audit_action="create_environment",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_project_exists=True,
    ),
    audit_enabled=True,
)""",

    "list_environments": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="environment",
        action="read",
        require_workspace_access=True,
        audit_action="list_environments",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "get_environment": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="environment",
        action="read",
        require_workspace_access=True,
        audit_action="read_environment",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "update_environment": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="environment",
        action="update",
        require_workspace_access=True,
        audit_action="update_environment",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "delete_environment": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="environment",
        action="delete",
        require_workspace_access=True,
        audit_action="delete_environment",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    # Permission endpoints
    "list_permissions": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="permission",
        action="read",
        require_workspace_access=True,
        audit_action="list_permissions",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "get_permission": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="permission",
        action="read",
        require_workspace_access=True,
        audit_action="read_permission",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "check_permission": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="permission",
        action="read",
        require_workspace_access=True,
        audit_action="check_permission",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_user_exists=True,
    ),
    audit_enabled=True,
)""",

    # Role assignment endpoints
    "create_role_assignment": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="create",
        require_workspace_access=True,
        audit_action="create_role_assignment",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_role_exists=True,
        validate_user_exists=True,
    ),
    audit_enabled=True,
)""",

    "list_role_assignments": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="read",
        require_workspace_access=True,
        audit_action="list_role_assignments",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "get_role_assignment": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="read",
        require_workspace_access=True,
        audit_action="read_role_assignment",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "update_role_assignment": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="update",
        require_workspace_access=True,
        audit_action="update_role_assignment",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "revoke_role_assignment": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="delete",
        require_workspace_access=True,
        audit_action="revoke_role_assignment",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    # Service account endpoints
    "create_service_account": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="service_account",
        action="create",
        require_workspace_access=True,
        audit_action="create_service_account",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "list_service_accounts": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="service_account",
        action="read",
        require_workspace_access=True,
        audit_action="list_service_accounts",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "get_service_account": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="service_account",
        action="read",
        require_workspace_access=True,
        audit_action="read_service_account",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "update_service_account": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="service_account",
        action="update",
        require_workspace_access=True,
        audit_action="update_service_account",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "delete_service_account": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="service_account",
        action="delete",
        require_workspace_access=True,
        audit_action="delete_service_account",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "rotate_service_account_token": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="service_account",
        action="update",
        require_workspace_access=True,
        audit_action="rotate_service_account_token",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    # User group endpoints
    "create_user_group": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="user_group",
        action="create",
        require_workspace_access=True,
        audit_action="create_user_group",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "list_user_groups": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="user_group",
        action="read",
        require_workspace_access=True,
        audit_action="list_user_groups",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "get_user_group": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="user_group",
        action="read",
        require_workspace_access=True,
        audit_action="read_user_group",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "update_user_group": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="user_group",
        action="update",
        require_workspace_access=True,
        audit_action="update_user_group",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "delete_user_group": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="user_group",
        action="delete",
        require_workspace_access=True,
        audit_action="delete_user_group",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "add_user_to_group": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="user_group",
        action="update",
        require_workspace_access=True,
        audit_action="add_user_to_group",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_user_exists=True,
    ),
    audit_enabled=True,
)""",

    "remove_user_from_group": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="user_group",
        action="update",
        require_workspace_access=True,
        audit_action="remove_user_from_group",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_user_exists=True,
    ),
    audit_enabled=True,
)""",

    # IAC endpoints - most need authentication
    "export_infrastructure": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="export",
        require_workspace_access=True,
        audit_action="export_infrastructure",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "import_infrastructure": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="import",
        require_workspace_access=True,
        audit_action="import_infrastructure",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "validate_infrastructure": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="read",
        require_workspace_access=True,
        audit_action="validate_infrastructure",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "apply_infrastructure": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="infrastructure",
        action="update",
        require_workspace_access=True,
        audit_action="apply_infrastructure",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",
}

# Generic security decorator for any remaining endpoints
GENERIC_SECURITY = """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="read",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)"""

def apply_security_to_file(filepath: Path) -> int:
    """Apply security decorators to a single file."""
    with open(filepath, 'r') as f:
        content = f.read()

    # Skip if file already has many @secure_endpoint decorators
    existing_count = content.count("@secure_endpoint")
    endpoint_count = content.count("@router.")

    # Force processing for files that need complete security coverage
    force_process_files = ["service_accounts.py", "role_assignments.py", "environments.py", "permissions.py", "user_groups.py"]

    if filepath.name in force_process_files:
        print(f"  🔄 {filepath.name}: Processing {endpoint_count} endpoints ({existing_count} already secured)")
    elif existing_count >= 3:
        print(f"  ✅ {filepath.name} already has {existing_count} @secure_endpoint decorators")
        return existing_count

    # Find all function definitions with @router decorators
    pattern = r'(@router\.\w+\([^)]*\))\s*\n\s*(async def (\w+)\([^)]*\)):'

    modified_content = content
    modifications = 0

    for match in re.finditer(pattern, content):
        router_decorator = match.group(1)
        function_def = match.group(2)
        function_name = match.group(3)

        # Check if this function already has @secure_endpoint
        if "@secure_endpoint" in content[max(0, match.start()-500):match.start()]:
            continue

        # Get the appropriate security config
        security_config = SECURITY_CONFIGS.get(function_name, GENERIC_SECURITY)

        # Replace with router decorator + security decorator
        replacement = f"{router_decorator}\n{security_config}\n{function_def}:"

        # Only apply if not already present
        if security_config not in modified_content:
            modified_content = modified_content.replace(match.group(0), replacement)
            modifications += 1

    if modifications > 0:
        # Update imports if needed
        if "from langflow.api.v1.rbac.security_middleware import" not in modified_content:
            import_statement = """from langflow.api.v1.rbac.security_middleware import (
    SecurityRequirement,
    ValidationRequirement,
    get_authenticated_user,
    secure_endpoint,
)
from langflow.services.auth.authorization_patterns import get_enhanced_enforcement_context
from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext
"""
            # Add imports after the other imports
            modified_content = modified_content.replace(
                "from langflow.api.utils import",
                import_statement + "from langflow.api.utils import"
            )

        # Add Request import if needed
        if "Request," not in modified_content:
            modified_content = modified_content.replace(
                "from fastapi import",
                "from fastapi import Request, "
            ).replace("Request, Request,", "Request,")

        # Write the modified content back
        with open(filepath, 'w') as f:
            f.write(modified_content)

        print(f"  ✅ {filepath.name}: Applied {modifications} security decorators")
        return existing_count + modifications

    print(f"  ℹ️ {filepath.name}: No modifications needed (already secure)")
    return existing_count

def main():
    """Apply security to all RBAC endpoint files."""
    print("🔒 Applying Security Middleware to All RBAC Endpoints")
    print("=" * 60)

    rbac_path = Path(__file__).parent

    # Files to update (excluding security_middleware.py itself and non-endpoint files)
    endpoint_files = [
        "audit.py",
        "environments.py",
        "iac.py",
        "permissions.py",
        "role_assignments.py",
        "service_accounts.py",
        "user_groups.py",
    ]

    total_decorators = 0

    for filename in endpoint_files:
        filepath = rbac_path / filename
        if filepath.exists():
            print(f"\n📁 Processing {filename}...")
            count = apply_security_to_file(filepath)
            total_decorators += count
        else:
            print(f"  ❌ {filename} not found")

    print("\n" + "=" * 60)
    print(f"✅ Security middleware application complete!")
    print(f"📊 Total @secure_endpoint decorators applied: {total_decorators}")
    print("=" * 60)

if __name__ == "__main__":
    main()
