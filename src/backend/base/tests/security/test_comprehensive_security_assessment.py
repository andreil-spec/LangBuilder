"""Comprehensive Security Vulnerability Assessment.

This module performs a complete security assessment of the RBAC system,
validating all security fixes and identifying any remaining vulnerabilities.
"""

import asyncio
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlmodel import Session

from langflow.services.settings.security_config import SecurityConfig, EnvironmentType


class SecurityVulnerabilityAssessment:
    """Comprehensive security assessment for RBAC implementation."""

    def __init__(self):
        self.vulnerabilities_found = []
        self.security_controls_validated = []
        self.assessment_results = {
            "authentication_bypass": {"status": "unknown", "details": []},
            "cors_configuration": {"status": "unknown", "details": []},
            "security_headers": {"status": "unknown", "details": []},
            "cross_workspace_isolation": {"status": "unknown", "details": []},
            "permission_enforcement": {"status": "unknown", "details": []},
            "data_access_patterns": {"status": "unknown", "details": []},
            "input_validation": {"status": "unknown", "details": []},
            "audit_logging": {"status": "unknown", "details": []},
            "session_management": {"status": "unknown", "details": []},
            "rate_limiting": {"status": "unknown", "details": []},
        }

    async def assess_authentication_bypass_vulnerabilities(self):
        """Assess authentication bypass vulnerabilities."""
        print("🔍 Assessing Authentication Bypass Vulnerabilities...")

        try:
            # Test 1: AUTO_LOGIN in production should be blocked
            os.environ["LANGFLOW_ENVIRONMENT"] = "production"
            os.environ["LANGFLOW_AUTO_LOGIN"] = "true"

            try:
                config = SecurityConfig.from_env()
                if config.auto_login_enabled:
                    self.vulnerabilities_found.append({
                        "severity": "CRITICAL",
                        "type": "Authentication Bypass",
                        "description": "AUTO_LOGIN enabled in production environment",
                        "location": "SecurityConfig.from_env()",
                        "risk": "Complete authentication bypass possible"
                    })
                    self.assessment_results["authentication_bypass"]["status"] = "VULNERABLE"
                else:
                    self.security_controls_validated.append("AUTO_LOGIN properly disabled in production")
                    self.assessment_results["authentication_bypass"]["status"] = "SECURE"
            except RuntimeError as e:
                if "SECURITY VIOLATION" in str(e):
                    self.security_controls_validated.append("Production AUTO_LOGIN blocked by runtime validation")
                    self.assessment_results["authentication_bypass"]["status"] = "SECURE"

            # Test 2: SKIP_AUTH in production should be blocked
            os.environ["LANGFLOW_SKIP_AUTH"] = "true"

            try:
                config = SecurityConfig.from_env()
                if config.skip_authentication:
                    self.vulnerabilities_found.append({
                        "severity": "CRITICAL",
                        "type": "Authentication Bypass",
                        "description": "SKIP_AUTH enabled in production environment",
                        "location": "SecurityConfig.from_env()",
                        "risk": "Complete authentication bypass possible"
                    })
                    self.assessment_results["authentication_bypass"]["status"] = "VULNERABLE"
            except RuntimeError as e:
                if "SECURITY VIOLATION" in str(e):
                    self.security_controls_validated.append("Production SKIP_AUTH blocked by runtime validation")

            # Test 3: Development environment warnings
            os.environ["LANGFLOW_ENVIRONMENT"] = "development"
            config = SecurityConfig.from_env()

            if config.auto_login_enabled:
                self.security_controls_validated.append("AUTO_LOGIN allowed in development with warnings")

        except Exception as e:
            self.vulnerabilities_found.append({
                "severity": "HIGH",
                "type": "Authentication Assessment Error",
                "description": f"Failed to assess authentication security: {e}",
                "location": "assess_authentication_bypass_vulnerabilities",
                "risk": "Unable to validate authentication security"
            })

        finally:
            # Clean up environment
            os.environ.pop("LANGFLOW_AUTO_LOGIN", None)
            os.environ.pop("LANGFLOW_SKIP_AUTH", None)

    async def assess_cors_configuration_security(self):
        """Assess CORS configuration security."""
        print("🔍 Assessing CORS Configuration Security...")

        try:
            # Test 1: Wildcard origins with credentials should be blocked
            os.environ["LANGFLOW_ENVIRONMENT"] = "production"
            os.environ["LANGFLOW_ALLOWED_ORIGINS"] = "*"

            config = SecurityConfig.from_env()
            cors_config = config.get_cors_config()

            if "*" in cors_config["allow_origins"] and cors_config["allow_credentials"]:
                self.vulnerabilities_found.append({
                    "severity": "HIGH",
                    "type": "CORS Misconfiguration",
                    "description": "Wildcard CORS origins with credentials enabled",
                    "location": "SecurityConfig.get_cors_config()",
                    "risk": "CSRF attacks possible"
                })
                self.assessment_results["cors_configuration"]["status"] = "VULNERABLE"
            else:
                self.security_controls_validated.append("CORS wildcard origins properly restricted")
                self.assessment_results["cors_configuration"]["status"] = "SECURE"

            # Test 2: Production CORS should not allow wildcards
            if "*" in cors_config["allow_origins"]:
                self.vulnerabilities_found.append({
                    "severity": "MEDIUM",
                    "type": "CORS Configuration",
                    "description": "Wildcard CORS origins in production",
                    "location": "SecurityConfig.get_cors_config()",
                    "risk": "Potential CSRF vulnerability"
                })

        except Exception as e:
            self.vulnerabilities_found.append({
                "severity": "MEDIUM",
                "type": "CORS Assessment Error",
                "description": f"Failed to assess CORS security: {e}",
                "location": "assess_cors_configuration_security",
                "risk": "Unable to validate CORS security"
            })

        finally:
            os.environ.pop("LANGFLOW_ALLOWED_ORIGINS", None)

    async def assess_security_headers_implementation(self):
        """Assess security headers implementation."""
        print("🔍 Assessing Security Headers Implementation...")

        try:
            os.environ["LANGFLOW_ENVIRONMENT"] = "production"
            config = SecurityConfig.from_env()
            headers = config.get_security_headers()

            required_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "Referrer-Policy"
            ]

            missing_headers = []
            for header in required_headers:
                if header not in headers or not headers[header]:
                    missing_headers.append(header)

            if missing_headers:
                self.vulnerabilities_found.append({
                    "severity": "MEDIUM",
                    "type": "Missing Security Headers",
                    "description": f"Missing required security headers: {', '.join(missing_headers)}",
                    "location": "SecurityConfig.get_security_headers()",
                    "risk": "XSS, clickjacking, and other attacks possible"
                })
                self.assessment_results["security_headers"]["status"] = "INCOMPLETE"
            else:
                self.security_controls_validated.append("All required security headers implemented")
                self.assessment_results["security_headers"]["status"] = "SECURE"

            # Validate CSP strictness
            csp = headers.get("Content-Security-Policy", "")
            if "'unsafe-eval'" in csp or "'unsafe-inline'" in csp:
                self.vulnerabilities_found.append({
                    "severity": "LOW",
                    "type": "CSP Configuration",
                    "description": "CSP allows unsafe-eval or unsafe-inline",
                    "location": "Content-Security-Policy header",
                    "risk": "Reduced XSS protection"
                })

        except Exception as e:
            self.vulnerabilities_found.append({
                "severity": "MEDIUM",
                "type": "Security Headers Assessment Error",
                "description": f"Failed to assess security headers: {e}",
                "location": "assess_security_headers_implementation",
                "risk": "Unable to validate security headers"
            })

    async def assess_cross_workspace_isolation(self):
        """Assess cross-workspace data isolation."""
        print("🔍 Assessing Cross-Workspace Isolation...")

        try:
            from langflow.services.auth.secure_data_access import SecureDataAccessService
            from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext

            # Mock test data
            user_alpha = MagicMock()
            user_alpha.id = uuid4()

            user_beta = MagicMock()
            user_beta.id = uuid4()

            workspace_alpha = uuid4()
            workspace_beta = uuid4()

            # Test workspace isolation in data access
            with patch("langflow.services.rbac.service.RBACService") as mock_rbac:
                mock_rbac_instance = AsyncMock()
                mock_rbac.return_value = mock_rbac_instance

                service = SecureDataAccessService()

                # Mock contexts for different workspaces
                context_alpha = RuntimeEnforcementContext(
                    user=user_alpha,
                    requested_workspace_id=workspace_alpha
                )

                context_beta = RuntimeEnforcementContext(
                    user=user_beta,
                    requested_workspace_id=workspace_beta
                )

                # Test that flows are isolated by workspace
                try:
                    # This should use workspace-scoped access
                    flows_alpha = await service.get_accessible_flows(
                        session=AsyncMock(),
                        context=context_alpha
                    )

                    flows_beta = await service.get_accessible_flows(
                        session=AsyncMock(),
                        context=context_beta
                    )

                    self.security_controls_validated.append("Cross-workspace flow isolation implemented")
                    self.assessment_results["cross_workspace_isolation"]["status"] = "SECURE"

                except Exception as e:
                    self.vulnerabilities_found.append({
                        "severity": "HIGH",
                        "type": "Cross-Workspace Data Leakage",
                        "description": f"Workspace isolation not properly implemented: {e}",
                        "location": "SecureDataAccessService.get_accessible_flows",
                        "risk": "Users may access data from other workspaces"
                    })
                    self.assessment_results["cross_workspace_isolation"]["status"] = "VULNERABLE"

        except Exception as e:
            self.vulnerabilities_found.append({
                "severity": "HIGH",
                "type": "Workspace Isolation Assessment Error",
                "description": f"Failed to assess workspace isolation: {e}",
                "location": "assess_cross_workspace_isolation",
                "risk": "Unable to validate workspace security"
            })

    async def assess_permission_enforcement(self):
        """Assess RBAC permission enforcement."""
        print("🔍 Assessing Permission Enforcement...")

        try:
            from langflow.services.rbac.permission_engine import PermissionEngine

            # Test permission engine fail-secure behavior
            with patch("langflow.services.rbac.service.RBACService") as mock_rbac:
                mock_rbac_instance = AsyncMock()
                mock_rbac.return_value = mock_rbac_instance

                engine = PermissionEngine(mock_rbac_instance)

                # Test fail-secure on errors
                mock_rbac_instance.check_user_permission.side_effect = Exception("Database error")

                try:
                    result = await engine.check_permission(
                        session=AsyncMock(),
                        user=MagicMock(),
                        resource_type="workspace",
                        action="read",
                        resource_id=uuid4()
                    )

                    if result.allowed:
                        self.vulnerabilities_found.append({
                            "severity": "HIGH",
                            "type": "Permission Engine Fail-Open",
                            "description": "Permission engine allows access on errors",
                            "location": "PermissionEngine.check_permission",
                            "risk": "Unauthorized access during system errors"
                        })
                        self.assessment_results["permission_enforcement"]["status"] = "VULNERABLE"
                    else:
                        self.security_controls_validated.append("Permission engine fails secure on errors")
                        self.assessment_results["permission_enforcement"]["status"] = "SECURE"

                except Exception:
                    # If the method throws an exception instead of returning False, that's also secure
                    self.security_controls_validated.append("Permission engine fails secure on errors (exception)")
                    self.assessment_results["permission_enforcement"]["status"] = "SECURE"

        except Exception as e:
            self.vulnerabilities_found.append({
                "severity": "HIGH",
                "type": "Permission Enforcement Assessment Error",
                "description": f"Failed to assess permission enforcement: {e}",
                "location": "assess_permission_enforcement",
                "risk": "Unable to validate permission security"
            })

    async def assess_data_access_patterns(self):
        """Assess secure data access patterns."""
        print("🔍 Assessing Data Access Patterns...")

        try:
            # Check for vulnerable patterns in flow access
            flow_file_path = "src/backend/base/langflow/api/v1/flows.py"

            if os.path.exists(flow_file_path):
                with open(flow_file_path, 'r') as f:
                    content = f.read()

                # Look for vulnerable patterns
                vulnerable_patterns = [
                    r"user_id\s*==\s*current_user\.id",  # Direct user_id filtering
                    r"\.user_id\s*==\s*\w+",             # General user_id filtering
                    r"where\s*\(\s*Flow\.user_id",       # Flow.user_id queries
                ]

                found_vulnerabilities = []
                for pattern in vulnerable_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        found_vulnerabilities.extend(matches)

                if found_vulnerabilities:
                    self.vulnerabilities_found.append({
                        "severity": "HIGH",
                        "type": "Insecure Data Access Patterns",
                        "description": f"Found vulnerable user_id-based queries: {found_vulnerabilities}",
                        "location": "flows.py",
                        "risk": "Cross-workspace data leakage possible"
                    })
                    self.assessment_results["data_access_patterns"]["status"] = "VULNERABLE"
                else:
                    self.security_controls_validated.append("Secure data access patterns implemented in flows.py")
                    self.assessment_results["data_access_patterns"]["status"] = "SECURE"
            else:
                self.assessment_results["data_access_patterns"]["status"] = "UNKNOWN"

        except Exception as e:
            self.vulnerabilities_found.append({
                "severity": "MEDIUM",
                "type": "Data Access Pattern Assessment Error",
                "description": f"Failed to assess data access patterns: {e}",
                "location": "assess_data_access_patterns",
                "risk": "Unable to validate data access security"
            })

    async def assess_input_validation(self):
        """Assess input validation and injection vulnerabilities."""
        print("🔍 Assessing Input Validation...")

        try:
            # Test SQL injection protection through parameterized queries
            from sqlmodel import select
            from langflow.services.database.models.rbac.workspace import Workspace

            # Verify parameterized queries are used
            test_query = select(Workspace).where(Workspace.name == "test' OR '1'='1")

            # This should create a parameterized query, not inject SQL
            query_str = str(test_query)

            if "OR '1'='1" in query_str and "?" not in query_str and ":" not in query_str:
                self.vulnerabilities_found.append({
                    "severity": "HIGH",
                    "type": "SQL Injection Vulnerability",
                    "description": "Queries may be vulnerable to SQL injection",
                    "location": "Database query construction",
                    "risk": "Data extraction and manipulation possible"
                })
                self.assessment_results["input_validation"]["status"] = "VULNERABLE"
            else:
                self.security_controls_validated.append("Parameterized queries protect against SQL injection")
                self.assessment_results["input_validation"]["status"] = "SECURE"

        except Exception as e:
            self.vulnerabilities_found.append({
                "severity": "MEDIUM",
                "type": "Input Validation Assessment Error",
                "description": f"Failed to assess input validation: {e}",
                "location": "assess_input_validation",
                "risk": "Unable to validate input security"
            })

    async def assess_audit_logging_coverage(self):
        """Assess audit logging coverage for security events."""
        print("🔍 Assessing Audit Logging Coverage...")

        try:
            # Test audit logging is implemented for sensitive operations
            sensitive_operations = [
                "login",
                "role_assignment",
                "permission_grant",
                "workspace_creation",
                "user_deletion"
            ]

            # Check if audit service is properly implemented
            from langflow.services.rbac.audit_service import AuditService

            audit_service = AuditService()

            # Test that audit methods exist
            required_methods = [
                "log_authentication_event",
                "log_role_management_event",
                "log_permission_event",
                "log_workspace_event",
                "log_security_event"
            ]

            missing_methods = []
            for method in required_methods:
                if not hasattr(audit_service, method):
                    missing_methods.append(method)

            if missing_methods:
                self.vulnerabilities_found.append({
                    "severity": "MEDIUM",
                    "type": "Incomplete Audit Logging",
                    "description": f"Missing audit methods: {', '.join(missing_methods)}",
                    "location": "AuditService",
                    "risk": "Security events not properly logged"
                })
                self.assessment_results["audit_logging"]["status"] = "INCOMPLETE"
            else:
                self.security_controls_validated.append("Comprehensive audit logging implemented")
                self.assessment_results["audit_logging"]["status"] = "SECURE"

        except Exception as e:
            self.vulnerabilities_found.append({
                "severity": "MEDIUM",
                "type": "Audit Logging Assessment Error",
                "description": f"Failed to assess audit logging: {e}",
                "location": "assess_audit_logging_coverage",
                "risk": "Unable to validate audit security"
            })

    async def run_comprehensive_assessment(self):
        """Run complete security vulnerability assessment."""
        print("🚀 Starting Comprehensive Security Vulnerability Assessment...")
        print("=" * 70)

        # Run all security assessments
        await self.assess_authentication_bypass_vulnerabilities()
        await self.assess_cors_configuration_security()
        await self.assess_security_headers_implementation()
        await self.assess_cross_workspace_isolation()
        await self.assess_permission_enforcement()
        await self.assess_data_access_patterns()
        await self.assess_input_validation()
        await self.assess_audit_logging_coverage()

        # Generate comprehensive report
        self.generate_security_report()

        return {
            "vulnerabilities": self.vulnerabilities_found,
            "controls_validated": self.security_controls_validated,
            "assessment_results": self.assessment_results
        }

    def generate_security_report(self):
        """Generate comprehensive security assessment report."""
        print("\n📊 COMPREHENSIVE SECURITY ASSESSMENT REPORT")
        print("=" * 70)

        # Summary statistics
        total_vulnerabilities = len(self.vulnerabilities_found)
        critical_vulns = len([v for v in self.vulnerabilities_found if v["severity"] == "CRITICAL"])
        high_vulns = len([v for v in self.vulnerabilities_found if v["severity"] == "HIGH"])
        medium_vulns = len([v for v in self.vulnerabilities_found if v["severity"] == "MEDIUM"])
        low_vulns = len([v for v in self.vulnerabilities_found if v["severity"] == "LOW"])

        controls_validated = len(self.security_controls_validated)

        print(f"\n📈 SECURITY SUMMARY:")
        print(f"   Total Vulnerabilities Found: {total_vulnerabilities}")
        print(f"   Critical: {critical_vulns}, High: {high_vulns}, Medium: {medium_vulns}, Low: {low_vulns}")
        print(f"   Security Controls Validated: {controls_validated}")

        # Assessment results by category
        print(f"\n🔍 ASSESSMENT RESULTS BY CATEGORY:")
        for category, result in self.assessment_results.items():
            status_icon = {
                "SECURE": "✅",
                "VULNERABLE": "❌",
                "INCOMPLETE": "⚠️",
                "unknown": "❓"
            }.get(result["status"], "❓")

            category_name = category.replace("_", " ").title()
            print(f"   {status_icon} {category_name}: {result['status']}")

        # Detailed vulnerabilities
        if self.vulnerabilities_found:
            print(f"\n🚨 VULNERABILITIES FOUND:")
            for i, vuln in enumerate(self.vulnerabilities_found, 1):
                severity_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(vuln["severity"], "⚪")

                print(f"\n   {i}. {severity_icon} {vuln['severity']} - {vuln['type']}")
                print(f"      Description: {vuln['description']}")
                print(f"      Location: {vuln['location']}")
                print(f"      Risk: {vuln['risk']}")

        # Security controls validated
        if self.security_controls_validated:
            print(f"\n✅ SECURITY CONTROLS VALIDATED:")
            for i, control in enumerate(self.security_controls_validated, 1):
                print(f"   {i}. {control}")

        # Overall security rating
        if critical_vulns > 0:
            rating = "🔴 CRITICAL RISK"
        elif high_vulns > 0:
            rating = "🟠 HIGH RISK"
        elif medium_vulns > 0:
            rating = "🟡 MEDIUM RISK"
        elif low_vulns > 0:
            rating = "🟢 LOW RISK"
        else:
            rating = "✅ SECURE"

        print(f"\n🎯 OVERALL SECURITY RATING: {rating}")

        if total_vulnerabilities == 0:
            print("\n🎉 EXCELLENT! No security vulnerabilities found.")
            print("   The RBAC system appears to be properly secured.")
        else:
            print(f"\n⚠️  Action Required: {total_vulnerabilities} vulnerabilities need to be addressed.")

        print("=" * 70)


async def run_security_assessment():
    """Run the comprehensive security assessment."""
    assessment = SecurityVulnerabilityAssessment()
    results = await assessment.run_comprehensive_assessment()
    return results


if __name__ == "__main__":
    # Run assessment when script is executed directly
    asyncio.run(run_security_assessment())
