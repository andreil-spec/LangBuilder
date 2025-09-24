#!/usr/bin/env python3
"""Simple API Security Validation.

This script validates security patterns in RBAC API endpoints
using text-based analysis.
"""

import sys
from pathlib import Path

# Add backend base to path
backend_base = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_base))


def validate_api_security():
    """Validate API security implementation."""
    print("🔒 API Security Standardization Validation")
    print("=" * 50)

    api_path = backend_base / "langflow" / "api" / "v1" / "rbac"

    if not api_path.exists():
        print("❌ RBAC API directory not found")
        return False

    # Find Python files (excluding __init__.py)
    api_files = [f for f in api_path.glob("*.py") if f.name != "__init__.py"]

    results = {
        "total_files": len(api_files),
        "files_with_security": 0,
        "files_with_auth": 0,
        "files_with_validation": 0,
        "files_with_middleware": 0,
        "security_details": []
    }

    for api_file in api_files:
        print(f"\n📁 Analyzing {api_file.name}...")

        try:
            with open(api_file, 'r') as f:
                content = f.read()

            file_analysis = analyze_file_security(api_file.name, content)
            results["security_details"].append(file_analysis)

            # Count security implementations
            if file_analysis["has_security_middleware"]:
                results["files_with_middleware"] += 1
            if file_analysis["has_authentication"]:
                results["files_with_auth"] += 1
            if file_analysis["has_validation"]:
                results["files_with_validation"] += 1
            if file_analysis["overall_secure"]:
                results["files_with_security"] += 1

            # Display file results
            display_file_results(file_analysis)

        except Exception as e:
            print(f"   ❌ Error analyzing {api_file.name}: {e}")

    # Display overall results
    display_overall_results(results)

    # Calculate success rate
    security_rate = (results["files_with_security"] / results["total_files"]) * 100 if results["total_files"] > 0 else 0

    return security_rate >= 70  # 70% threshold for success


def analyze_file_security(filename: str, content: str) -> dict:
    """Analyze security patterns in a single file."""
    analysis = {
        "filename": filename,
        "has_endpoints": False,
        "has_security_middleware": False,
        "has_authentication": False,
        "has_authorization": False,
        "has_validation": False,
        "has_audit": False,
        "endpoint_count": 0,
        "security_patterns": [],
        "issues": [],
        "overall_secure": False
    }

    # Check for API endpoints
    endpoint_patterns = ["@router.", "async def", "-> ", "HTTPException"]
    analysis["has_endpoints"] = any(pattern in content for pattern in endpoint_patterns)

    if analysis["has_endpoints"]:
        # Count potential endpoints
        analysis["endpoint_count"] = content.count("@router.")

        # Check for security middleware
        middleware_patterns = [
            "security_middleware",
            "@secure_endpoint",
            "SecurityRequirement",
            "ValidationRequirement"
        ]
        analysis["has_security_middleware"] = any(pattern in content for pattern in middleware_patterns)
        if analysis["has_security_middleware"]:
            analysis["security_patterns"].append("Security Middleware")

        # Check for authentication
        auth_patterns = [
            "get_authenticated_user",
            "CurrentActiveUser",
            "authentication",
            "token"
        ]
        analysis["has_authentication"] = any(pattern in content for pattern in auth_patterns)
        if analysis["has_authentication"]:
            analysis["security_patterns"].append("Authentication")

        # Check for authorization
        authz_patterns = [
            "check_permission",
            "permission_engine",
            "authorization",
            "RuntimeEnforcementContext",
            "get_enhanced_enforcement_context"
        ]
        analysis["has_authorization"] = any(pattern in content for pattern in authz_patterns)
        if analysis["has_authorization"]:
            analysis["security_patterns"].append("Authorization")

        # Check for validation
        validation_patterns = [
            "ValidationRequirement",
            "validate_",
            "Pydantic",
            "HTTPException",
            "Field("
        ]
        analysis["has_validation"] = any(pattern in content for pattern in validation_patterns)
        if analysis["has_validation"]:
            analysis["security_patterns"].append("Input Validation")

        # Check for audit logging
        audit_patterns = [
            "audit_service",
            "AuditService",
            "audit_enabled",
            "log_audit"
        ]
        analysis["has_audit"] = any(pattern in content for pattern in audit_patterns)
        if analysis["has_audit"]:
            analysis["security_patterns"].append("Audit Logging")

        # Assess overall security
        security_components = [
            analysis["has_security_middleware"],
            analysis["has_authentication"],
            analysis["has_authorization"],
            analysis["has_validation"]
        ]
        security_score = sum(security_components)
        analysis["overall_secure"] = security_score >= 3  # At least 3/4 components

        # Identify issues
        if not analysis["has_security_middleware"]:
            analysis["issues"].append("Missing security middleware")
        if not analysis["has_authentication"]:
            analysis["issues"].append("Missing authentication")
        if not analysis["has_authorization"]:
            analysis["issues"].append("Missing authorization")
        if not analysis["has_validation"]:
            analysis["issues"].append("Limited input validation")

    return analysis


def display_file_results(analysis: dict):
    """Display results for a single file."""
    if not analysis["has_endpoints"]:
        print("   ℹ️ No API endpoints detected")
        return

    print(f"   📊 Endpoints found: {analysis['endpoint_count']}")

    # Security status
    if analysis["overall_secure"]:
        print("   ✅ Security: GOOD")
    else:
        print("   ⚠️ Security: NEEDS IMPROVEMENT")

    # Security patterns found
    if analysis["security_patterns"]:
        print(f"   🔒 Security patterns: {', '.join(analysis['security_patterns'])}")

    # Issues
    if analysis["issues"]:
        print(f"   ❌ Issues: {', '.join(analysis['issues'])}")


def display_overall_results(results: dict):
    """Display overall validation results."""
    print("\n" + "=" * 50)
    print("📊 OVERALL API SECURITY ASSESSMENT")
    print("=" * 50)

    total = results["total_files"]
    secure = results["files_with_security"]
    auth = results["files_with_auth"]
    validation = results["files_with_validation"]
    middleware = results["files_with_middleware"]

    print(f"\n📈 IMPLEMENTATION STATUS:")
    print(f"   Total API Files: {total}")
    print(f"   Files with Security: {secure}/{total} ({(secure/total*100):.1f}%)")
    print(f"   Files with Authentication: {auth}/{total} ({(auth/total*100):.1f}%)")
    print(f"   Files with Validation: {validation}/{total} ({(validation/total*100):.1f}%)")
    print(f"   Files with Security Middleware: {middleware}/{total} ({(middleware/total*100):.1f}%)")

    # Overall assessment
    security_rate = (secure / total) * 100 if total > 0 else 0

    if security_rate >= 90:
        status = "✅ EXCELLENT"
        message = "API security standardization is excellent!"
    elif security_rate >= 70:
        status = "✅ GOOD"
        message = "API security standardization is good with minor improvements needed."
    elif security_rate >= 50:
        status = "⚠️ NEEDS IMPROVEMENT"
        message = "API security standardization needs significant improvement."
    else:
        status = "❌ POOR"
        message = "API security standardization requires immediate attention!"

    print(f"\n🎯 OVERALL ASSESSMENT:")
    print(f"   Security Rate: {security_rate:.1f}%")
    print(f"   Status: {status}")
    print(f"   Assessment: {message}")

    # Detailed breakdown
    print(f"\n🔍 DETAILED BREAKDOWN:")
    for detail in results["security_details"]:
        if detail["has_endpoints"]:
            status_icon = "✅" if detail["overall_secure"] else "⚠️"
            patterns_count = len(detail["security_patterns"])
            issues_count = len(detail["issues"])

            print(f"   {status_icon} {detail['filename']}: {patterns_count} patterns, {issues_count} issues")

    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")

    all_issues = []
    for detail in results["security_details"]:
        all_issues.extend(detail["issues"])

    # Count most common issues
    issue_counts = {}
    for issue in all_issues:
        issue_counts[issue] = issue_counts.get(issue, 0) + 1

    # Sort by frequency
    sorted_issues = sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)

    for i, (issue, count) in enumerate(sorted_issues[:5], 1):
        print(f"   {i}. {issue} (affects {count} files)")

    if not sorted_issues:
        print("   ✅ No common security issues found!")

    print("\n" + "=" * 50)


if __name__ == "__main__":
    success = validate_api_security()
    sys.exit(0 if success else 1)
