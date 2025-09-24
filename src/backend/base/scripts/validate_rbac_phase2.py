#!/usr/bin/env python3
"""Validation script for RBAC Phase 2 implementation.

This script validates that all Phase 2 deliverables have been properly implemented
according to the requirements in RBAC_IMPLEMENTATION_PLAN.md.
"""

import ast
import sys
from pathlib import Path


# Color codes for output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"

def print_success(message: str):
    print(f"{Colors.GREEN}✓{Colors.END} {message}")

def print_error(message: str):
    print(f"{Colors.RED}✗{Colors.END} {message}")

def print_warning(message: str):
    print(f"{Colors.YELLOW}⚠{Colors.END} {message}")

def print_info(message: str):
    print(f"{Colors.BLUE}ℹ{Colors.END} {message}")

def print_header(message: str):
    print(f"\n{Colors.BOLD}{message}{Colors.END}")
    print("=" * len(message))

class RBACPhase2Validator:
    """Validator for RBAC Phase 2 implementation."""

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.api_path = base_path / "langflow" / "api" / "v1" / "rbac"
        self.services_path = base_path / "langflow" / "services" / "rbac"
        self.models_path = base_path / "langflow" / "services" / "database" / "models" / "rbac"
        self.test_path = base_path / "tests" / "unit" / "api" / "v1" / "rbac"

        self.validation_results = {
            "api_endpoints": [],
            "permission_engine": [],
            "data_models": [],
            "router_integration": [],
            "dependency_consistency": [],
            "test_coverage": [],
            "documentation": []
        }

    def validate_all(self) -> bool:
        """Run all validation checks."""
        print_header("RBAC Phase 2 Implementation Validation")
        print_info(f"Base path: {self.base_path}")

        checks = [
            ("API Endpoints", self.validate_api_endpoints),
            ("Permission Engine", self.validate_permission_engine),
            ("Data Models", self.validate_data_models),
            ("Router Integration", self.validate_router_integration),
            ("Dependency Consistency", self.validate_dependency_consistency),
            ("Test Coverage", self.validate_test_coverage),
            ("Documentation", self.validate_documentation)
        ]

        all_passed = True
        for check_name, check_func in checks:
            print_header(f"Validating {check_name}")
            try:
                passed = check_func()
                if not passed:
                    all_passed = False
            except Exception as e:
                print_error(f"Validation failed with error: {e}")
                all_passed = False

        self.print_summary()
        return all_passed

    def validate_api_endpoints(self) -> bool:
        """Validate API endpoint implementations."""
        required_files = {
            "workspaces.py": [
                "create_workspace", "list_workspaces", "get_workspace",
                "update_workspace", "delete_workspace", "invite_user_to_workspace",
                "list_workspace_users", "list_workspace_projects", "get_workspace_statistics"
            ],
            "projects.py": [
                "create_project", "list_projects", "get_project", "update_project",
                "delete_project", "list_project_environments", "list_project_flows",
                "get_project_statistics"
            ],
            "roles.py": [
                "create_role", "list_roles", "get_role", "update_role", "delete_role",
                "list_role_permissions", "assign_permission_to_role",
                "remove_permission_from_role", "initialize_system_roles"
            ],
            "permissions.py": [
                "list_permissions", "get_permission", "check_permission",
                "batch_check_permissions", "initialize_system_permissions",
                "list_resource_types", "list_actions"
            ]
        }

        all_passed = True
        for filename, expected_functions in required_files.items():
            file_path = self.api_path / filename
            if not file_path.exists():
                print_error(f"Missing API file: {filename}")
                self.validation_results["api_endpoints"].append(f"Missing file: {filename}")
                all_passed = False
                continue

            # Parse the Python file to extract function names
            try:
                with open(file_path) as f:
                    content = f.read()

                tree = ast.parse(content)
                defined_functions = []

                for node in ast.walk(tree):
                    if isinstance(node, ast.AsyncFunctionDef):
                        defined_functions.append(node.name)

                # Check for required functions
                missing_functions = []
                for func_name in expected_functions:
                    if func_name not in defined_functions:
                        missing_functions.append(func_name)

                if missing_functions:
                    print_error(f"{filename}: Missing functions: {missing_functions}")
                    self.validation_results["api_endpoints"].append(
                        f"{filename}: Missing {missing_functions}"
                    )
                    all_passed = False
                else:
                    print_success(f"{filename}: All {len(expected_functions)} endpoints implemented")

                # Check for proper router tags and metadata
                if 'tags=["RBAC"' in content:
                    print_success(f"{filename}: Router has proper RBAC tags")
                else:
                    print_warning(f"{filename}: Router missing RBAC tags")

                # Check for response models
                if "responses={" in content:
                    print_success(f"{filename}: Router has response metadata")
                else:
                    print_warning(f"{filename}: Router missing response metadata")

            except Exception as e:
                print_error(f"Error parsing {filename}: {e}")
                all_passed = False

        return all_passed

    def validate_permission_engine(self) -> bool:
        """Validate permission engine implementation."""
        engine_file = self.services_path / "permission_engine.py"

        if not engine_file.exists():
            print_error("Permission engine file not found")
            return False

        try:
            with open(engine_file) as f:
                content = f.read()

            tree = ast.parse(content)

            # Check for PermissionEngine class
            engine_class_found = False
            required_methods = [
                "check_permission", "batch_check_permissions",
                "_resolve_hierarchical_permissions", "_get_user_roles",
                "_get_role_permissions", "_check_cached_permission"
            ]
            found_methods = []

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "PermissionEngine":
                    engine_class_found = True
                    for method_node in node.body:
                        if isinstance(method_node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                            found_methods.append(method_node.name)

            if engine_class_found:
                print_success("PermissionEngine class found")

                missing_methods = [method for method in required_methods if method not in found_methods]
                if missing_methods:
                    print_error(f"PermissionEngine missing methods: {missing_methods}")
                    return False
                print_success("All required PermissionEngine methods implemented")

                # Check for caching implementation
                if "redis" in content.lower() or "cache" in content.lower():
                    print_success("Caching implementation detected")
                else:
                    print_warning("No caching implementation detected")

                # Check for performance optimizations
                if "batch" in content.lower():
                    print_success("Batch processing capabilities detected")
                else:
                    print_warning("No batch processing detected")

            else:
                print_error("PermissionEngine class not found")
                return False

        except Exception as e:
            print_error(f"Error validating permission engine: {e}")
            return False

        return True

    def validate_data_models(self) -> bool:
        """Validate data model implementations."""
        required_models = {
            "permission.py": ["Permission", "PermissionRead", "RolePermission"],
            "role.py": ["Role", "RoleCreate", "RoleRead", "RoleUpdate"],
            "workspace.py": ["Workspace", "WorkspaceCreate", "WorkspaceRead", "WorkspaceUpdate"],
            "project.py": ["Project", "ProjectCreate", "ProjectRead", "ProjectUpdate"],
            "environment.py": ["Environment", "EnvironmentCreate", "EnvironmentRead"],
            "role_assignment.py": ["RoleAssignment"],
            "user_group.py": ["UserGroup"]
        }

        all_passed = True
        for filename, expected_classes in required_models.items():
            file_path = self.models_path / filename
            if not file_path.exists():
                print_error(f"Missing model file: {filename}")
                all_passed = False
                continue

            try:
                with open(file_path) as f:
                    content = f.read()

                tree = ast.parse(content)
                defined_classes = []

                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        defined_classes.append(node.name)

                missing_classes = [cls for cls in expected_classes if cls not in defined_classes]
                if missing_classes:
                    print_error(f"{filename}: Missing classes: {missing_classes}")
                    all_passed = False
                else:
                    print_success(f"{filename}: All required classes implemented")

                # Check for SQLModel inheritance
                if "SQLModel" in content:
                    print_success(f"{filename}: Uses SQLModel")
                else:
                    print_warning(f"{filename}: May not use SQLModel")

            except Exception as e:
                print_error(f"Error parsing {filename}: {e}")
                all_passed = False

        return all_passed

    def validate_router_integration(self) -> bool:
        """Validate router integration with main application."""
        main_router_file = self.base_path / "langflow" / "api" / "router.py"

        if not main_router_file.exists():
            print_error("Main router file not found")
            return False

        try:
            with open(main_router_file) as f:
                content = f.read()

            required_routers = [
                "workspaces_router", "rbac_projects_router",
                "roles_router", "permissions_router"
            ]

            all_included = True
            for router_name in required_routers:
                if router_name in content:
                    print_success(f"Router {router_name} included in main application")
                else:
                    print_error(f"Router {router_name} not included in main application")
                    all_included = False

            # Check for include_router calls
            include_count = content.count("include_router")
            if include_count >= len(required_routers):
                print_success(f"Found {include_count} include_router calls")
            else:
                print_warning(f"Only found {include_count} include_router calls, expected at least {len(required_routers)}")

            return all_included

        except Exception as e:
            print_error(f"Error validating router integration: {e}")
            return False

    def validate_dependency_consistency(self) -> bool:
        """Validate consistent use of LangBuilder type aliases."""
        api_files = list(self.api_path.glob("*.py"))

        all_consistent = True
        for file_path in api_files:
            if file_path.name.startswith("__") or file_path.name in ["openapi_schemas.py"]:
                continue

            try:
                with open(file_path) as f:
                    content = f.read()

                # Check for LangBuilder type aliases import
                if "CurrentActiveUser" in content and "DbSession" in content:
                    print_success(f"{file_path.name}: Uses LangBuilder type aliases")
                else:
                    print_error(f"{file_path.name}: Missing LangBuilder type aliases")
                    all_consistent = False

                # Check for deprecated patterns (excluding dependencies.py which needs these)
                if file_path.name != "dependencies.py":
                    deprecated_patterns = [
                        "User = Depends(get_current_user)",
                        "AsyncSession = Depends(get_session)"
                    ]

                    for pattern in deprecated_patterns:
                        if pattern in content:
                            print_error(f"{file_path.name}: Uses deprecated pattern: {pattern}")
                            all_consistent = False
                else:
                    # dependencies.py is allowed to use these patterns for dependency injection
                    print_success(f"{file_path.name}: Dependency injection patterns are appropriate")

                # Check for proper imports (dependencies.py has different import patterns)
                if file_path.name == "dependencies.py":
                    if "from langflow.api.utils import" in content:
                        print_success(f"{file_path.name}: Proper imports detected")
                    else:
                        print_warning(f"{file_path.name}: May have import issues")
                elif "from langflow.api.utils import CurrentActiveUser, DbSession" in content:
                    print_success(f"{file_path.name}: Proper imports detected")
                else:
                    print_warning(f"{file_path.name}: May have import issues")

            except Exception as e:
                print_error(f"Error checking {file_path.name}: {e}")
                all_consistent = False

        return all_consistent

    def validate_test_coverage(self) -> bool:
        """Validate test coverage for RBAC implementation."""
        if not self.test_path.exists():
            print_error("RBAC test directory not found")
            return False

        test_files = list(self.test_path.glob("test_*.py"))

        if not test_files:
            print_error("No test files found")
            return False

        print_success(f"Found {len(test_files)} test files")

        required_test_files = [
            "test_workspaces.py", "test_projects.py",
            "test_roles.py", "test_permissions.py"
        ]

        all_covered = True
        for test_file in required_test_files:
            test_path = self.test_path / test_file
            if test_path.exists():
                try:
                    with open(test_path) as f:
                        content = f.read()

                    # Count test methods
                    test_method_count = content.count("def test_")
                    async_test_count = content.count("async def test_")

                    if test_method_count > 0 or async_test_count > 0:
                        print_success(f"{test_file}: {test_method_count + async_test_count} test methods")
                    else:
                        print_warning(f"{test_file}: No test methods found")

                    # Check for pytest fixtures
                    if "@pytest.fixture" in content:
                        print_success(f"{test_file}: Uses pytest fixtures")

                    # Check for mocking
                    if "mock" in content.lower() or "Mock" in content:
                        print_success(f"{test_file}: Uses mocking")

                except Exception as e:
                    print_error(f"Error reading {test_file}: {e}")
                    all_covered = False
            else:
                print_error(f"Missing test file: {test_file}")
                all_covered = False

        return all_covered

    def validate_documentation(self) -> bool:
        """Validate documentation completeness."""
        # Check for docstrings in API files
        api_files = list(self.api_path.glob("*.py"))

        documented_files = 0
        for file_path in api_files:
            if file_path.name.startswith("__"):
                continue

            try:
                with open(file_path) as f:
                    content = f.read()

                # Count docstrings
                docstring_count = content.count('"""')
                if docstring_count >= 4:  # Module docstring + some function docstrings
                    print_success(f"{file_path.name}: Well documented")
                    documented_files += 1
                else:
                    print_warning(f"{file_path.name}: Limited documentation")

            except Exception as e:
                print_error(f"Error checking documentation in {file_path.name}: {e}")

        documentation_score = documented_files / len(api_files) if api_files else 0
        if documentation_score >= 0.8:
            print_success(f"Documentation coverage: {documentation_score:.1%}")
            return True
        print_warning(f"Documentation coverage: {documentation_score:.1%} (needs improvement)")
        return False

    def print_summary(self):
        """Print validation summary."""
        print_header("Validation Summary")

        total_checks = 0
        passed_checks = 0

        for category, results in self.validation_results.items():
            if results:
                total_checks += len(results)
                print_info(f"{category.replace('_', ' ').title()}: {len(results)} issues found")
                for result in results:
                    print(f"  - {result}")
            else:
                passed_checks += 1

        if not any(self.validation_results.values()):
            print_success("All validation checks passed!")
            print_info("RBAC Phase 2 implementation is compliant with requirements")
        else:
            print_warning(f"Found issues in {sum(len(v) for v in self.validation_results.values())} areas")
            print_info("Review the issues above and make necessary corrections")

    def run_syntax_checks(self) -> bool:
        """Run Python syntax validation on all RBAC files."""
        print_header("Python Syntax Validation")

        all_files = []
        all_files.extend(self.api_path.glob("*.py"))
        all_files.extend(self.services_path.glob("*.py"))
        all_files.extend(self.models_path.glob("*.py"))

        syntax_errors = []
        for file_path in all_files:
            if file_path.name.startswith("__"):
                continue

            try:
                with open(file_path) as f:
                    content = f.read()

                ast.parse(content)
                print_success(f"{file_path.relative_to(self.base_path)}: Syntax OK")

            except SyntaxError as e:
                error_msg = f"{file_path.relative_to(self.base_path)}: {e}"
                print_error(error_msg)
                syntax_errors.append(error_msg)
            except Exception as e:
                error_msg = f"{file_path.relative_to(self.base_path)}: {e}"
                print_error(error_msg)
                syntax_errors.append(error_msg)

        if not syntax_errors:
            print_success("All Python files have valid syntax")
            return True
        print_error(f"Found {len(syntax_errors)} syntax errors")
        return False


def main():
    """Main validation function."""
    # Get the base path (assuming script is in src/backend/base/scripts/)
    script_dir = Path(__file__).parent
    base_path = script_dir.parent

    print_info("RBAC Phase 2 Validation Script")
    print_info(f"Script location: {script_dir}")
    print_info(f"Base path: {base_path}")

    validator = RBACPhase2Validator(base_path)

    # Run syntax checks first
    syntax_ok = validator.run_syntax_checks()

    # Run all validation checks
    validation_ok = validator.validate_all()

    # Final result
    print_header("Final Result")
    if syntax_ok and validation_ok:
        print_success("RBAC Phase 2 implementation validation PASSED")
        return 0
    print_error("RBAC Phase 2 implementation validation FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
