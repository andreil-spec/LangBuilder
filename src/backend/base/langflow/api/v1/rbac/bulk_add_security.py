#!/usr/bin/env python3
"""Bulk add @secure_endpoint decorators to all remaining RBAC endpoint files."""

import re
from pathlib import Path

# Define security configurations for different endpoint types
SECURITY_CONFIGS = {
    # Role assignment endpoints
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

    "list_user_assignments": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="read",
        require_workspace_access=True,
        audit_action="list_user_assignments",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_user_exists=True,
    ),
    audit_enabled=True,
)""",

    "get_user_effective_permissions": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="read",
        require_workspace_access=True,
        audit_action="get_user_effective_permissions",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_user_exists=True,
    ),
    audit_enabled=True,
)""",

    "bulk_assign_roles": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="create",
        require_workspace_access=True,
        audit_action="bulk_assign_roles",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)""",

    "check_user_role": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="read",
        require_workspace_access=True,
        audit_action="check_user_role",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_user_exists=True,
    ),
    audit_enabled=True,
)""",

    "get_role_members": """@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="role_assignment",
        action="read",
        require_workspace_access=True,
        audit_action="get_role_members",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
        validate_role_exists=True,
    ),
    audit_enabled=True,
)""",
}

def add_security_to_endpoint(content: str, router_line: str, function_name: str) -> str:
    """Add @secure_endpoint decorator to a specific endpoint."""
    # Get the security config for this function
    security_config = SECURITY_CONFIGS.get(function_name)
    if not security_config:
        # Use a generic security config
        security_config = """@secure_endpoint(
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

    # Replace the @router line with @router + security decorator
    new_content = content.replace(router_line, f"{router_line}\n{security_config}")
    return new_content

def update_function_signature(content: str, function_name: str) -> str:
    """Update function signature to include Request and security dependencies."""
    # Pattern to match function definition
    pattern = rf"async def {function_name}\(\s*([^)]*)\s*\)"

    def replace_signature(match):
        params = match.group(1).strip()

        # Check if Request is already in params
        if "request: Request" in params or "http_request: Request" in params:
            return match.group(0)  # Already has Request

        # Check if it has enhanced authentication
        if "Annotated[User, Depends(get_authenticated_user)]" in params:
            return match.group(0)  # Already enhanced

        # Add request parameter at the beginning if not empty
        if params:
            new_params = f"request: Request,\n    {params}"
        else:
            new_params = "request: Request"

        # Update CurrentActiveUser to use enhanced authentication
        new_params = re.sub(
            r"current_user:\s*CurrentActiveUser",
            "current_user: Annotated[User, Depends(get_authenticated_user)]",
            new_params
        )

        # Add RuntimeEnforcementContext if not present
        if "RuntimeEnforcementContext" not in new_params:
            # Find where to insert context parameter (after current_user)
            if "current_user:" in new_params:
                new_params = re.sub(
                    r"(current_user: Annotated\[User, Depends\(get_authenticated_user\)\]),",
                    r"\1,\n    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],",
                    new_params
                )

        return f"async def {function_name}(\n    {new_params}\n)"

    return re.sub(pattern, replace_signature, content, flags=re.DOTALL)

def process_file(filepath: Path) -> int:
    """Process a single file to add security decorators."""
    print(f"📁 Processing {filepath.name}...")

    with open(filepath, 'r') as f:
        content = f.read()

    # Find all @router decorators and their corresponding functions
    router_pattern = r"(@router\.\w+\([^)]*\))\s*\n\s*async def (\w+)\("
    matches = list(re.finditer(router_pattern, content))

    if not matches:
        print(f"   ❌ No router endpoints found in {filepath.name}")
        return 0

    modified_content = content
    modifications = 0
    needs_user_import = False

    # Process matches in reverse order to avoid offset issues
    for match in reversed(matches):
        router_line = match.group(1)
        function_name = match.group(2)

        # Check if this function already has @secure_endpoint
        # Look backwards from the match position for @secure_endpoint
        before_match = content[:match.start()]
        if "@secure_endpoint" in before_match[-500:]:  # Check last 500 chars before match
            continue

        print(f"   🔒 Adding security to {function_name}")

        # Add security decorator
        modified_content = add_security_to_endpoint(modified_content, router_line, function_name)

        # Update function signature
        modified_content = update_function_signature(modified_content, function_name)

        # Check if we're replacing CurrentActiveUser with User
        if "CurrentActiveUser" in content and "Annotated[User, Depends(get_authenticated_user)]" in modified_content:
            needs_user_import = True

        modifications += 1

    # Add User import if needed
    if needs_user_import and modifications > 0:
        # Check if User is already imported
        if "from langflow.services.database.models.user.model import User" not in modified_content:
            # Find the import section for langflow.api.utils
            import_pattern = r"(from langflow\.api\.utils import [^\n]+)"
            import_match = re.search(import_pattern, modified_content)
            if import_match:
                # Add User import after the langflow.api.utils import
                old_import = import_match.group(0)
                new_import = old_import + "\nfrom langflow.services.database.models.user.model import User"
                modified_content = modified_content.replace(old_import, new_import)
                print(f"   📦 Added User import to {filepath.name}")

    if modifications > 0:
        # Write the updated content
        with open(filepath, 'w') as f:
            f.write(modified_content)
        print(f"   ✅ Added {modifications} security decorators to {filepath.name}")
    else:
        print(f"   ℹ️ {filepath.name} already has security decorators")

    return modifications

def main():
    """Add security decorators to all endpoints in remaining files."""
    print("🔒 Bulk Adding Security Decorators to RBAC Endpoints")
    print("=" * 60)

    # Files that need security decorators
    rbac_path = Path(__file__).parent
    files_to_process = [
        "role_assignments.py",
        "environments.py",
        "permissions.py",
        "user_groups.py"
    ]

    total_modifications = 0

    for filename in files_to_process:
        filepath = rbac_path / filename
        if filepath.exists():
            modifications = process_file(filepath)
            total_modifications += modifications
        else:
            print(f"❌ {filename} not found")

    print("\n" + "=" * 60)
    print(f"✅ Bulk security addition complete!")
    print(f"📊 Total security decorators added: {total_modifications}")
    print("=" * 60)

if __name__ == "__main__":
    main()
