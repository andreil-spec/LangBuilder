#!/usr/bin/env python3
"""API Security Middleware Validation Tests.

This module validates that the standardized security middleware is properly
implemented across all RBAC API endpoints.
"""

import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Set
import ast
import re

# Add backend base to path
backend_base = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_base))


class APISecurityValidator:
    """Validator for API security middleware implementation."""

    def __init__(self):
        self.api_path = backend_base / "langflow" / "api" / "v1" / "rbac"
        self.validation_results = {
            "authentication_middleware": {},
            "authorization_checks": {},
            "input_validation": {},
            "audit_logging": {},
            "security_decorators": {},
            "overall_security": {}
        }
        self.findings = []

    def add_finding(self, category: str, endpoint_file: str, endpoint_function: str,
                    severity: str, issue: str, recommendation: str):
        """Add a security finding."""
        finding = {
            "category": category,
            "endpoint_file": endpoint_file,
            "endpoint_function": endpoint_function,
            "severity": severity,
            "issue": issue,
            "recommendation": recommendation
        }
        self.findings.append(finding)

    def validate_endpoint_file(self, file_path: Path) -> Dict:
        """Validate security implementation in a single endpoint file."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()

            results = {
                "file_name": file_path.name,
                "endpoints_found": 0,
                "secure_endpoints": 0,
                "authentication_patterns": [],
                "authorization_patterns": [],
                "validation_patterns": [],
                "issues": []
            }

            # Parse AST to find endpoint functions
            try:
                tree = ast.parse(content)
                endpoints = self._extract_endpoints(tree, content)
                results["endpoints_found"] = len(endpoints)

                for endpoint in endpoints:
                    self._validate_endpoint_security(file_path, endpoint, content, results)

            except SyntaxError as e:
                results["issues"].append(f"Syntax error: {e}")

            return results

        except Exception as e:
            return {
                "file_name": file_path.name,
                "error": str(e),
                "endpoints_found": 0,
                "secure_endpoints": 0,
                "issues": [f"Failed to validate file: {e}"]
            }

    def _extract_endpoints(self, tree: ast.AST, content: str) -> List[Dict]:
        """Extract API endpoint functions from AST."""
        endpoints = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check if function has router decorator
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Attribute) and hasattr(decorator.value, 'id'):
                        if decorator.value.id == 'router':
                            endpoints.append({
                                "name": node.name,
                                "line": node.lineno,
                                "decorators": [self._get_decorator_name(d) for d in node.decorator_list],
                                "args": [arg.arg for arg in node.args.args]
                            })

        return endpoints

    def _get_decorator_name(self, decorator: ast.AST) -> str:
        """Get decorator name from AST node."""
        if isinstance(decorator, ast.Attribute):
            return f"{decorator.value.id}.{decorator.attr}"
        elif isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                return f"{decorator.func.value.id}.{decorator.func.attr}"
            elif isinstance(decorator.func, ast.Name):
                return decorator.func.id
        return "unknown"

    def _validate_endpoint_security(self, file_path: Path, endpoint: Dict, content: str, results: Dict):
        """Validate security implementation for a specific endpoint."""
        endpoint_name = endpoint["name"]

        # Check for security decorator
        has_secure_decorator = any("secure_endpoint" in dec for dec in endpoint["decorators"])

        # Check for authentication patterns
        auth_patterns = [
            "get_authenticated_user",
            "CurrentActiveUser",
            "Depends(get_authenticated_user)",
        ]
        has_auth = any(pattern in content for pattern in auth_patterns)

        # Check for authorization patterns
        authz_patterns = [
            "secure_endpoint",
            "check_permission",
            "permission_engine",
            "RuntimeEnforcementContext",
        ]
        has_authz = any(pattern in content for pattern in authz_patterns)

        # Check for input validation patterns
        validation_patterns = [
            "ValidationRequirement",
            "validate_",
            "Pydantic",
            "Field(",
        ]
        has_validation = any(pattern in content for pattern in validation_patterns)

        # Check for audit logging
        audit_patterns = [
            "audit_enabled=True",
            "audit_service",
            "AuditService",
            "log_audit",
        ]
        has_audit = any(pattern in content for pattern in audit_patterns)

        # Evaluate security completeness
        security_score = 0
        if has_secure_decorator:
            security_score += 3
        if has_auth:
            security_score += 2
        if has_authz:
            security_score += 2
        if has_validation:
            security_score += 1
        if has_audit:
            security_score += 1

        # Maximum score is 9 (all patterns)
        is_secure = security_score >= 6  # At least 6/9 for basic security

        if is_secure:
            results["secure_endpoints"] += 1

        # Record patterns found
        if has_auth:
            results["authentication_patterns"].append(endpoint_name)
        if has_authz:
            results["authorization_patterns"].append(endpoint_name)
        if has_validation:
            results["validation_patterns"].append(endpoint_name)

        # Add findings for missing security
        if not has_secure_decorator:
            self.add_finding(
                "security_decorators",
                file_path.name,
                endpoint_name,
                "HIGH",
                "Missing @secure_endpoint decorator",
                "Add @secure_endpoint decorator with appropriate security requirements"
            )

        if not has_auth:
            self.add_finding(
                "authentication_middleware",
                file_path.name,
                endpoint_name,
                "HIGH",
                "Missing authentication middleware",
                "Add CurrentActiveUser dependency with get_authenticated_user"
            )

        if not has_authz:
            self.add_finding(
                "authorization_checks",
                file_path.name,
                endpoint_name,
                "HIGH",
                "Missing authorization checks",
                "Add authorization patterns with permission checking"
            )

        if not has_validation:
            self.add_finding(
                "input_validation",
                file_path.name,
                endpoint_name,
                "MEDIUM",
                "Limited input validation",
                "Add comprehensive input validation patterns"
            )

        if not has_audit:
            self.add_finding(
                "audit_logging",
                file_path.name,
                endpoint_name,
                "MEDIUM",
                "Missing audit logging",
                "Add audit logging for security events"
            )

    def validate_security_middleware_framework(self):
        """Validate the security middleware framework itself."""
        middleware_path = self.api_path / "security_middleware.py"

        if not middleware_path.exists():
            self.add_finding(
                "security_middleware",
                "N/A",
                "N/A",
                "CRITICAL",
                "Security middleware framework missing",
                "Create unified security middleware framework"
            )
            return False

        try:
            with open(middleware_path, 'r') as f:
                content = f.read()

            # Check for essential components
            required_components = [
                "secure_endpoint",
                "enhanced_authentication",
                "enhanced_authorization",
                "enhanced_validation",
                "SecurityRequirement",
                "ValidationRequirement",
            ]

            missing_components = []
            for component in required_components:
                if component not in content:
                    missing_components.append(component)

            if missing_components:
                self.add_finding(
                    "security_middleware",
                    "security_middleware.py",
                    "N/A",
                    "HIGH",
                    f"Missing components: {', '.join(missing_components)}",
                    "Implement all required security middleware components"
                )
                return False

            return True

        except Exception as e:
            self.add_finding(
                "security_middleware",
                "security_middleware.py",
                "N/A",
                "HIGH",
                f"Error validating middleware: {e}",
                "Fix security middleware implementation"
            )
            return False

    def run_comprehensive_validation(self):
        """Run comprehensive validation of API security middleware."""
        print("🔒 Starting API Security Middleware Validation...")
        print("=" * 60)

        # Validate security middleware framework
        framework_valid = self.validate_security_middleware_framework()

        if not framework_valid:
            print("❌ Security middleware framework validation failed")
            self.generate_validation_report()
            return False

        # Validate each RBAC endpoint file
        if not self.api_path.exists():
            print("❌ RBAC API directory not found")
            return False

        endpoint_files = list(self.api_path.glob("*.py"))
        endpoint_files = [f for f in endpoint_files if f.name not in ["__init__.py", "security_middleware.py"]]

        total_endpoints = 0
        total_secure = 0
        file_results = []

        for endpoint_file in endpoint_files:
            print(f"📁 Validating {endpoint_file.name}...")

            result = self.validate_endpoint_file(endpoint_file)
            file_results.append(result)

            total_endpoints += result["endpoints_found"]
            total_secure += result["secure_endpoints"]

            if result["endpoints_found"] > 0:
                security_rate = (result["secure_endpoints"] / result["endpoints_found"]) * 100
                status = "✅" if security_rate >= 80 else "⚠️" if security_rate >= 50 else "❌"
                print(f"   {status} {result['secure_endpoints']}/{result['endpoints_found']} endpoints secured ({security_rate:.1f}%)")
            else:
                print(f"   ℹ️ No endpoints found")

        # Store results
        self.validation_results["overall_security"] = {
            "total_endpoints": total_endpoints,
            "secure_endpoints": total_secure,
            "security_rate": (total_secure / total_endpoints * 100) if total_endpoints > 0 else 0,
            "file_results": file_results
        }

        # Generate report
        self.generate_validation_report()

        # Return success if security rate is acceptable
        security_rate = self.validation_results["overall_security"]["security_rate"]
        return security_rate >= 80  # 80% threshold for success

    def generate_validation_report(self):
        """Generate comprehensive validation report."""
        print("\n📊 API Security Middleware Validation Report")
        print("=" * 60)

        overall = self.validation_results["overall_security"]

        if overall:
            print(f"\n📈 OVERALL RESULTS:")
            print(f"   Total Endpoints: {overall['total_endpoints']}")
            print(f"   Secured Endpoints: {overall['secure_endpoints']}")
            print(f"   Security Rate: {overall['security_rate']:.1f}%")

            # Security assessment
            security_rate = overall['security_rate']
            if security_rate >= 90:
                status = "✅ EXCELLENT"
            elif security_rate >= 80:
                status = "✅ GOOD"
            elif security_rate >= 60:
                status = "⚠️ NEEDS IMPROVEMENT"
            else:
                status = "❌ POOR"

            print(f"   Security Status: {status}")

        # Findings by category
        print(f"\n🔍 FINDINGS BY CATEGORY:")
        categories = {}
        for finding in self.findings:
            category = finding['category']
            if category not in categories:
                categories[category] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            categories[category][finding['severity']] += 1

        for category, counts in categories.items():
            total = sum(counts.values())
            critical = counts.get('CRITICAL', 0)
            high = counts.get('HIGH', 0)

            if critical > 0:
                status = "🚨"
            elif high > 0:
                status = "⚠️"
            else:
                status = "✅"

            print(f"   {status} {category.replace('_', ' ').title()}: {total} issues")
            if total > 0:
                for severity, count in counts.items():
                    if count > 0:
                        print(f"      {severity}: {count}")

        # Recommendations
        print(f"\n💡 TOP RECOMMENDATIONS:")
        high_priority = [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]
        for i, finding in enumerate(high_priority[:5], 1):
            print(f"   {i}. {finding['recommendation']}")

        if not high_priority:
            print("   ✅ No high-priority security issues found!")

        print("\n" + "=" * 60)


def main():
    """Main validation execution."""
    validator = APISecurityValidator()
    success = validator.run_comprehensive_validation()

    return 0 if success else 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
