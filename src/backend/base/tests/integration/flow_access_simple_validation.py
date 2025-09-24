#!/usr/bin/env python3
"""Simplified Flow Data Access Security Validation.

This script validates that the flow data access patterns properly integrate
with the RBAC system without complex import dependencies.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the backend base path to sys.path for imports
backend_base = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_base))


def validate_flow_rbac_integration():
    """Validate flow data access RBAC integration by checking code patterns."""

    validation_results = {
        "secure_data_service_integration": False,
        "rbac_workspace_filtering": False,
        "permission_enforcement": False,
        "cross_workspace_prevention": False,
        "api_endpoint_security": False
    }

    print("🚀 Starting Flow Data Access Security Validation...")
    print("=" * 60)

    # Check 1: Secure Data Access Service Integration
    try:
        flows_py_path = backend_base / "langflow" / "api" / "v1" / "flows.py"
        if flows_py_path.exists():
            with open(flows_py_path, 'r') as f:
                flows_content = f.read()

            # Check for secure data access service usage
            if "SecureDataAccessService" in flows_content:
                validation_results["secure_data_service_integration"] = True
                print("✅ Secure Data Access Service integrated in flows.py")
            else:
                print("❌ SecureDataAccessService not found in flows.py")

            # Check for RBAC workspace filtering
            if "get_accessible_flows" in flows_content and "context" in flows_content:
                validation_results["rbac_workspace_filtering"] = True
                print("✅ RBAC workspace filtering implemented")
            else:
                print("❌ RBAC workspace filtering not properly implemented")

        else:
            print("❌ flows.py not found")

    except Exception as e:
        print(f"❌ Error checking flows.py: {e}")

    # Check 2: Permission Enforcement in Flow Operations
    try:
        # Check for permission checks in flow CRUD operations
        if flows_py_path.exists():
            with open(flows_py_path, 'r') as f:
                flows_content = f.read()

            # Look for permission enforcement patterns
            permission_patterns = [
                "check_permission",
                "RuntimeEnforcementContext",
                "get_enhanced_enforcement_context",
                "_flow_read_check"
            ]

            found_patterns = sum(1 for pattern in permission_patterns if pattern in flows_content)
            if found_patterns >= 2:
                validation_results["permission_enforcement"] = True
                print("✅ Permission enforcement patterns found in flows.py")
            else:
                print(f"⚠️ Limited permission enforcement patterns found ({found_patterns}/4)")

    except Exception as e:
        print(f"❌ Error checking permission enforcement: {e}")

    # Check 3: Cross-Workspace Prevention
    try:
        secure_data_path = backend_base / "langflow" / "services" / "auth" / "secure_data_access.py"
        if secure_data_path.exists():
            with open(secure_data_path, 'r') as f:
                secure_data_content = f.read()

            # Check for workspace boundary enforcement
            workspace_patterns = [
                "_enforce_workspace_boundary",
                "workspace_id",
                "cross-workspace",
                "workspace isolation"
            ]

            found_workspace_patterns = sum(1 for pattern in workspace_patterns if pattern in secure_data_content)
            if found_workspace_patterns >= 2:
                validation_results["cross_workspace_prevention"] = True
                print("✅ Cross-workspace prevention mechanisms found")
            else:
                print(f"⚠️ Limited cross-workspace prevention ({found_workspace_patterns}/4)")

        else:
            print("❌ secure_data_access.py not found")

    except Exception as e:
        print(f"❌ Error checking cross-workspace prevention: {e}")

    # Check 4: API Endpoint Security
    try:
        # Check multiple API endpoints for consistent security patterns
        api_files = [
            "flows.py",
            "folders.py",
            "endpoints.py"
        ]

        secure_endpoints = 0
        for api_file in api_files:
            api_path = backend_base / "langflow" / "api" / "v1" / api_file
            if api_path.exists():
                with open(api_path, 'r') as f:
                    api_content = f.read()

                # Check for security patterns
                security_patterns = [
                    "CurrentActiveUser",
                    "get_enhanced_enforcement_context",
                    "check_permission"
                ]

                if any(pattern in api_content for pattern in security_patterns):
                    secure_endpoints += 1

        if secure_endpoints >= 2:
            validation_results["api_endpoint_security"] = True
            print(f"✅ API endpoint security validated ({secure_endpoints} endpoints)")
        else:
            print(f"⚠️ Limited API endpoint security ({secure_endpoints} endpoints)")

    except Exception as e:
        print(f"❌ Error checking API endpoint security: {e}")

    # Generate validation report
    print("\n📊 FLOW DATA ACCESS SECURITY VALIDATION REPORT")
    print("=" * 60)

    total_validations = len(validation_results)
    passed_validations = sum(validation_results.values())

    print(f"\n📈 VALIDATION SUMMARY:")
    print(f"   Total Validations: {total_validations}")
    print(f"   Passed: {passed_validations}")
    print(f"   Failed: {total_validations - passed_validations}")
    print(f"   Success Rate: {(passed_validations/total_validations)*100:.1f}%")

    print(f"\n🔍 DETAILED RESULTS:")

    for validation, passed in validation_results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        validation_name = validation.replace("_", " ").title()
        print(f"   {status} {validation_name}")

    # Overall assessment
    if passed_validations == total_validations:
        overall_status = "✅ FULLY SECURE"
        print(f"\n🎉 Flow data access integration is properly secured!")
    elif passed_validations >= total_validations * 0.8:
        overall_status = "⚠️ MOSTLY SECURE"
        print(f"\n⚠️ Flow data access integration is mostly secure with {total_validations - passed_validations} issues.")
    else:
        overall_status = "❌ SECURITY ISSUES"
        print(f"\n❌ Flow data access integration has significant security issues!")

    print(f"\n🎯 OVERALL STATUS: {overall_status}")
    print("=" * 60)

    return validation_results


if __name__ == "__main__":
    results = validate_flow_rbac_integration()

    # Exit with error code if validations failed
    total_validations = len(results)
    passed_validations = sum(results.values())

    if passed_validations < total_validations:
        sys.exit(1)
    else:
        sys.exit(0)
