#!/usr/bin/env python3
"""Validation script for RBAC Phase 4: Integration & Middleware.

This script validates the implementation of Phase 4 deliverables:
- RBAC middleware integration with existing patterns
- Authentication enhancement and dependency injection
- Flow execution permission integration
- Backward compatibility maintenance
- Performance optimization with caching
- Integration test coverage

Usage:
    python validate_rbac_phase4.py [--verbose] [--fix-imports]
"""

# NO future annotations per Phase 1 requirements
import ast
import importlib.util
import sys
from pathlib import Path


def validate_syntax(file_path: Path) -> tuple[bool, str]:
    """Validate Python syntax of a file.

    Args:
        file_path: Path to Python file

    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        # Parse AST to check syntax
        ast.parse(content)
        return True, ""
    except SyntaxError as e:
        return False, f"Syntax error: {e}"
    except Exception as e:
        return False, f"Error reading file: {e}"


def validate_imports(file_path: Path) -> tuple[bool, list[str]]:
    """Validate that all imports in a file are resolvable.

    Args:
        file_path: Path to Python file

    Returns:
        tuple: (all_imports_valid, list_of_issues)
    """
    issues = []

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    try:
                        importlib.import_module(alias.name)
                    except ImportError:
                        # Skip LangBuilder specific imports that might not be available
                        if not alias.name.startswith("langflow"):
                            issues.append(f"Cannot import {alias.name}")

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    try:
                        importlib.import_module(node.module)
                    except ImportError:
                        # Skip LangBuilder specific imports
                        if not node.module.startswith("langflow"):
                            issues.append(f"Cannot import from {node.module}")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error validating imports: {e}"]


def check_phase1_compliance(file_path: Path) -> tuple[bool, list[str]]:
    """Check Phase 1 compliance (no future annotations).

    Args:
        file_path: Path to Python file

    Returns:
        tuple: (is_compliant, list_of_issues)
    """
    issues = []

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        # Check for future annotations import
        if "from __future__ import annotations" in content:
            issues.append("Found future annotations import (violates Phase 1 compliance)")

        # Check for TYPE_CHECKING pattern
        if "TYPE_CHECKING" in content and "from typing import TYPE_CHECKING" not in content:
            issues.append("Uses TYPE_CHECKING but doesn't import it")

        # Check for proper commenting about Phase 1 compliance
        if "# NO future annotations per Phase 1 requirements" not in content:
            issues.append("Missing Phase 1 compliance comment")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error checking Phase 1 compliance: {e}"]


def validate_langbuilder_patterns(file_path: Path) -> tuple[bool, list[str]]:
    """Validate LangBuilder service patterns compliance.

    Args:
        file_path: Path to Python file

    Returns:
        tuple: (is_compliant, list_of_issues)
    """
    issues = []

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content)

        # Check for Service base class usage
        service_classes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id == "Service":
                        service_classes.append(node.name)

        # Check async patterns
        has_async_methods = False
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                has_async_methods = True
                break

        # Validate service patterns
        if service_classes:
            for service_class in service_classes:
                if not service_class.endswith("Service"):
                    issues.append(f"Service class {service_class} should end with 'Service'")

        # Check for proper logging usage
        if "logger" in content and "from loguru import logger" not in content:
            issues.append("Uses logger but doesn't import from loguru")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error validating LangBuilder patterns: {e}"]


def validate_middleware_implementation() -> tuple[bool, list[str]]:
    """Validate RBAC middleware implementation.

    Returns:
        tuple: (is_valid, list_of_issues)
    """
    issues = []

    # Check core middleware file
    middleware_path = Path("src/backend/base/langflow/services/rbac/middleware.py")
    if not middleware_path.exists():
        issues.append("RBAC middleware file not found")
        return False, issues

    # Validate middleware class
    try:
        with open(middleware_path, encoding="utf-8") as f:
            content = f.read()

        # Check for required classes
        required_classes = ["RBACMiddleware", "RBACContext", "RBACMiddlewareService"]
        for class_name in required_classes:
            if f"class {class_name}" not in content:
                issues.append(f"Missing required class: {class_name}")

        # Check for FastAPI middleware pattern
        if "BaseHTTPMiddleware" not in content:
            issues.append("Middleware doesn't extend BaseHTTPMiddleware")

        # Check for async dispatch method
        if "async def dispatch" not in content:
            issues.append("Middleware missing async dispatch method")

        # Check performance tracking
        if "_request_count" not in content or "get_metrics" not in content:
            issues.append("Middleware missing performance tracking")

    except Exception as e:
        issues.append(f"Error validating middleware: {e}")

    return len(issues) == 0, issues


def validate_dependency_injection() -> tuple[bool, list[str]]:
    """Validate RBAC dependency injection implementation.

    Returns:
        tuple: (is_valid, list_of_issues)
    """
    issues = []

    # Check dependencies file
    deps_path = Path("src/backend/base/langflow/services/rbac/dependencies.py")
    if not deps_path.exists():
        issues.append("RBAC dependencies file not found")
        return False, issues

    try:
        with open(deps_path, encoding="utf-8") as f:
            content = f.read()

        # Check for required classes and functions
        required_items = [
            "RBACPermissionChecker",
            "check_custom_permission",
            "require_permission",
            "RequireFlowRead",
            "RequireFlowWrite",
            "RequireFlowExecute"
        ]

        for item in required_items:
            if item not in content:
                issues.append(f"Missing required item: {item}")

        # Check for FastAPI Depends integration
        if "from fastapi import Depends" not in content:
            issues.append("Missing FastAPI Depends import")

        # Check for typed annotations
        if "Annotated" not in content:
            issues.append("Missing typed annotations for dependencies")

    except Exception as e:
        issues.append(f"Error validating dependencies: {e}")

    return len(issues) == 0, issues


def validate_flow_integration() -> tuple[bool, list[str]]:
    """Validate Flow execution integration.

    Returns:
        tuple: (is_valid, list_of_issues)
    """
    issues = []

    # Check Flow integration file
    flow_path = Path("src/backend/base/langflow/services/rbac/flow_integration.py")
    if not flow_path.exists():
        issues.append("RBAC Flow integration file not found")
        return False, issues

    try:
        with open(flow_path, encoding="utf-8") as f:
            content = f.read()

        # Check for required classes
        required_classes = [
            "FlowExecutionContext",
            "RBACFlowExecutionGuard",
            "RBACFlowIntegrationService"
        ]

        for class_name in required_classes:
            if f"class {class_name}" not in content:
                issues.append(f"Missing required class: {class_name}")

        # Check for key methods
        required_methods = [
            "check_execution_permission",
            "execute_flow_with_rbac"
        ]

        for method in required_methods:
            if f"def {method}" not in content and f"async def {method}" not in content:
                issues.append(f"Missing required method: {method}")

        # Check for permission caching
        if "_permission_cache" not in content:
            issues.append("Missing permission caching implementation")

    except Exception as e:
        issues.append(f"Error validating Flow integration: {e}")

    return len(issues) == 0, issues


def validate_integration_service() -> tuple[bool, list[str]]:
    """Validate RBAC integration service for backward compatibility.

    Returns:
        tuple: (is_valid, list_of_issues)
    """
    issues = []

    # Check integration file
    integration_path = Path("src/backend/base/langflow/services/rbac/integration.py")
    if not integration_path.exists():
        issues.append("RBAC integration service file not found")
        return False, issues

    try:
        with open(integration_path, encoding="utf-8") as f:
            content = f.read()

        # Check for required classes
        required_classes = [
            "RBACIntegrationConfig",
            "RBACIntegrationService"
        ]

        for class_name in required_classes:
            if f"class {class_name}" not in content:
                issues.append(f"Missing required class: {class_name}")

        # Check for backward compatibility functions
        backward_compat_functions = [
            "check_user_access_to_flow",
            "get_user_accessible_flows"
        ]

        for func in backward_compat_functions:
            if f"def {func}" not in content and f"async def {func}" not in content:
                issues.append(f"Missing backward compatibility function: {func}")

        # Check for environment configuration
        if "from_environment" not in content:
            issues.append("Missing environment configuration support")

    except Exception as e:
        issues.append(f"Error validating integration service: {e}")

    return len(issues) == 0, issues


def validate_test_coverage() -> tuple[bool, list[str]]:
    """Validate integration test coverage for Phase 4.

    Returns:
        tuple: (is_valid, list_of_issues)
    """
    issues = []

    # Check test file
    test_path = Path("tests/integration/services/rbac/test_phase4_integration.py")
    if not test_path.exists():
        issues.append("Phase 4 integration test file not found")
        return False, issues

    try:
        with open(test_path, encoding="utf-8") as f:
            content = f.read()

        # Check for required test classes
        required_test_classes = [
            "TestRBACMiddlewareIntegration",
            "TestRBACDependencies",
            "TestFlowExecutionIntegration",
            "TestRBACIntegrationService",
            "TestEndToEndIntegration"
        ]

        for test_class in required_test_classes:
            if f"class {test_class}" not in content:
                issues.append(f"Missing test class: {test_class}")

        # Check for pytest usage
        if "import pytest" not in content:
            issues.append("Tests not using pytest framework")

        # Check for async test support
        if "@pytest.mark.asyncio" not in content:
            issues.append("Missing async test support")

        # Count test methods
        test_method_count = content.count("def test_")
        if test_method_count < 15:
            issues.append(f"Insufficient test coverage: only {test_method_count} test methods")

    except Exception as e:
        issues.append(f"Error validating test coverage: {e}")

    return len(issues) == 0, issues


def validate_performance_requirements() -> tuple[bool, list[str]]:
    """Validate performance requirements for Phase 4.

    Returns:
        tuple: (is_valid, list_of_issues)
    """
    issues = []

    # Check middleware performance tracking
    middleware_path = Path("src/backend/base/langflow/services/rbac/middleware.py")
    if middleware_path.exists():
        try:
            with open(middleware_path, encoding="utf-8") as f:
                content = f.read()

            # Check for performance metrics
            performance_items = [
                "_request_count",
                "_total_processing_time",
                "_cache_hits",
                "_cache_misses",
                "get_metrics"
            ]

            for item in performance_items:
                if item not in content:
                    issues.append(f"Missing performance tracking: {item}")

        except Exception as e:
            issues.append(f"Error checking middleware performance: {e}")

    # Check Flow integration caching
    flow_path = Path("src/backend/base/langflow/services/rbac/flow_integration.py")
    if flow_path.exists():
        try:
            with open(flow_path, encoding="utf-8") as f:
                content = f.read()

            # Check for caching implementation
            cache_items = [
                "_permission_cache",
                "_cache_ttl",
                "_get_cached_permission",
                "_cache_permission"
            ]

            for item in cache_items:
                if item not in content:
                    issues.append(f"Missing Flow permission caching: {item}")

        except Exception as e:
            issues.append(f"Error checking Flow integration performance: {e}")

    return len(issues) == 0, issues


def main():
    """Main validation function."""
    print("🔍 RBAC Phase 4 Implementation Validation")
    print("=" * 50)

    # Get arguments
    verbose = "--verbose" in sys.argv
    fix_imports = "--fix-imports" in sys.argv

    validation_results = []
    total_issues = 0

    # Core implementation files to validate
    core_files = [
        "src/backend/base/langflow/services/rbac/middleware.py",
        "src/backend/base/langflow/services/rbac/dependencies.py",
        "src/backend/base/langflow/services/rbac/flow_integration.py",
        "src/backend/base/langflow/services/rbac/integration.py"
    ]

    print("📁 Validating core implementation files...")
    for file_path in core_files:
        path = Path(file_path)
        if not path.exists():
            print(f"❌ {file_path} - File not found")
            total_issues += 1
            continue

        # Syntax validation
        is_valid, error = validate_syntax(path)
        if not is_valid:
            print(f"❌ {file_path} - Syntax error: {error}")
            total_issues += 1
            continue

        # Import validation
        imports_valid, import_issues = validate_imports(path)
        if not imports_valid and not fix_imports:
            if verbose:
                for issue in import_issues:
                    print(f"⚠️  {file_path} - {issue}")
            total_issues += len(import_issues)

        # Phase 1 compliance
        phase1_valid, phase1_issues = check_phase1_compliance(path)
        if not phase1_valid:
            if verbose:
                for issue in phase1_issues:
                    print(f"⚠️  {file_path} - {issue}")
            total_issues += len(phase1_issues)

        # LangBuilder patterns
        patterns_valid, pattern_issues = validate_langbuilder_patterns(path)
        if not patterns_valid:
            if verbose:
                for issue in pattern_issues:
                    print(f"⚠️  {file_path} - {issue}")
            total_issues += len(pattern_issues)

        if is_valid and (imports_valid or fix_imports) and phase1_valid and patterns_valid:
            print(f"✅ {file_path} - Valid")
        else:
            print(f"⚠️  {file_path} - Issues found")

    print("\n🔧 Validating component implementations...")

    # Validate middleware implementation
    middleware_valid, middleware_issues = validate_middleware_implementation()
    validation_results.append(("RBAC Middleware", middleware_valid, middleware_issues))

    # Validate dependency injection
    deps_valid, deps_issues = validate_dependency_injection()
    validation_results.append(("Dependency Injection", deps_valid, deps_issues))

    # Validate Flow integration
    flow_valid, flow_issues = validate_flow_integration()
    validation_results.append(("Flow Integration", flow_valid, flow_issues))

    # Validate integration service
    integration_valid, integration_issues = validate_integration_service()
    validation_results.append(("Integration Service", integration_valid, integration_issues))

    # Validate test coverage
    test_valid, test_issues = validate_test_coverage()
    validation_results.append(("Test Coverage", test_valid, test_issues))

    # Validate performance requirements
    perf_valid, perf_issues = validate_performance_requirements()
    validation_results.append(("Performance Requirements", perf_valid, perf_issues))

    # Print component validation results
    for component, is_valid, issues in validation_results:
        if is_valid:
            print(f"✅ {component} - Valid")
        else:
            print(f"❌ {component} - Issues found:")
            for issue in issues:
                print(f"   • {issue}")
            total_issues += len(issues)

    print("\n📊 Validation Summary:")
    print(f"   Total issues found: {total_issues}")

    if total_issues == 0:
        print("✅ All Phase 4 requirements validated successfully!")
        print("\n🎯 Phase 4 Implementation Status: READY FOR DEPLOYMENT")
        return True
    print("❌ Issues found in Phase 4 implementation")
    print("\n🔧 Please address the issues above before deployment")
    return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
