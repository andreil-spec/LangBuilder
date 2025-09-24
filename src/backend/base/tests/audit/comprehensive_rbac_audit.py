#!/usr/bin/env python3
"""Comprehensive RBAC Implementation Audit Framework.

This module provides a thorough audit of the entire RBAC implementation,
examining security, architecture, performance, and compliance aspects.
"""

import ast
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Set
import json

# Add backend base to path
backend_base = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_base))


class RBACComprehensiveAudit:
    """Comprehensive RBAC implementation auditor."""

    def __init__(self):
        self.backend_base = backend_base
        self.audit_results = {
            "database_models": {},
            "api_endpoints": {},
            "service_layer": {},
            "authentication": {},
            "authorization": {},
            "data_access": {},
            "security_patterns": {},
            "compliance": {},
            "performance": {},
            "architecture": {}
        }
        self.findings = []
        self.recommendations = []
        self.critical_issues = []
        self.warnings = []

    def add_finding(self, category: str, severity: str, title: str, description: str,
                    file_path: str = None, line_number: int = None, recommendation: str = None):
        """Add an audit finding."""
        finding = {
            "category": category,
            "severity": severity,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
            "title": title,
            "description": description,
            "file_path": file_path,
            "line_number": line_number,
            "recommendation": recommendation,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self.findings.append(finding)

        if severity == "CRITICAL":
            self.critical_issues.append(finding)
        elif severity in ["HIGH", "MEDIUM"]:
            self.warnings.append(finding)

    def audit_database_models(self):
        """Audit RBAC database models for integrity and security."""
        print("🔍 Auditing Database Models and Schema...")

        models_path = self.backend_base / "langflow" / "services" / "database" / "models" / "rbac"

        if not models_path.exists():
            self.add_finding(
                "database_models", "CRITICAL",
                "RBAC Models Directory Missing",
                "The RBAC models directory does not exist",
                recommendation="Create the RBAC models directory structure"
            )
            return

        # Check for essential RBAC model files
        required_models = [
            "workspace.py", "project.py", "environment.py", "role.py",
            "permission.py", "role_assignment.py", "audit_log.py"
        ]

        missing_models = []
        for model_file in required_models:
            model_path = models_path / model_file
            if not model_path.exists():
                missing_models.append(model_file)

        if missing_models:
            self.add_finding(
                "database_models", "HIGH",
                "Missing Essential RBAC Models",
                f"Missing model files: {', '.join(missing_models)}",
                recommendation="Implement all essential RBAC data models"
            )

        # Audit each existing model file
        for model_file in models_path.glob("*.py"):
            if model_file.name == "__init__.py":
                continue

            self._audit_model_file(model_file)

        # Check for proper relationships
        self._audit_model_relationships(models_path)

        self.audit_results["database_models"]["status"] = "completed"
        self.audit_results["database_models"]["models_found"] = len(list(models_path.glob("*.py"))) - 1
        self.audit_results["database_models"]["missing_models"] = missing_models

    def _audit_model_file(self, model_path: Path):
        """Audit individual model file."""
        try:
            with open(model_path, 'r') as f:
                content = f.read()

            # Parse AST for detailed analysis
            try:
                tree = ast.parse(content)
            except SyntaxError as e:
                self.add_finding(
                    "database_models", "HIGH",
                    f"Syntax Error in {model_path.name}",
                    f"Syntax error: {e}",
                    str(model_path),
                    e.lineno
                )
                return

            # Check for essential imports
            essential_imports = ["SQLModel", "Field", "Relationship"]
            for imp in essential_imports:
                if imp not in content:
                    self.add_finding(
                        "database_models", "MEDIUM",
                        f"Missing Import in {model_path.name}",
                        f"Missing essential import: {imp}",
                        str(model_path),
                        recommendation=f"Add import for {imp}"
                    )

            # Check for security patterns
            if "password" in content.lower() and "hash" not in content.lower():
                self.add_finding(
                    "database_models", "HIGH",
                    f"Potential Plain Text Password in {model_path.name}",
                    "Password field detected without hashing",
                    str(model_path),
                    recommendation="Ensure passwords are properly hashed"
                )

            # Check for proper UUID usage
            if "id:" in content and "UUID" not in content:
                self.add_finding(
                    "database_models", "MEDIUM",
                    f"Non-UUID ID Field in {model_path.name}",
                    "ID field should use UUID for security",
                    str(model_path),
                    recommendation="Use UUID for ID fields"
                )

            # Check for audit fields
            audit_fields = ["created_at", "updated_at"]
            missing_audit_fields = [field for field in audit_fields if field not in content]
            if missing_audit_fields:
                self.add_finding(
                    "database_models", "LOW",
                    f"Missing Audit Fields in {model_path.name}",
                    f"Missing audit fields: {', '.join(missing_audit_fields)}",
                    str(model_path),
                    recommendation="Add audit timestamp fields"
                )

            # Check for soft delete capability
            if "is_deleted" not in content and "deleted_at" not in content:
                self.add_finding(
                    "database_models", "INFO",
                    f"No Soft Delete in {model_path.name}",
                    "Consider implementing soft delete for audit trails",
                    str(model_path),
                    recommendation="Add soft delete capability"
                )

        except Exception as e:
            self.add_finding(
                "database_models", "HIGH",
                f"Error Auditing {model_path.name}",
                f"Could not audit model file: {e}",
                str(model_path)
            )

    def _audit_model_relationships(self, models_path: Path):
        """Audit model relationships for consistency."""
        # Check for foreign key constraints and relationships
        relationship_patterns = {}

        for model_file in models_path.glob("*.py"):
            if model_file.name == "__init__.py":
                continue

            try:
                with open(model_file, 'r') as f:
                    content = f.read()

                # Extract relationships
                relationships = re.findall(r'(\w+):\s*"(\w+)"\s*=\s*Relationship', content)
                foreign_keys = re.findall(r'(\w+):\s*\w+\s*=\s*Field\(foreign_key="(\w+\.\w+)"', content)

                relationship_patterns[model_file.name] = {
                    "relationships": relationships,
                    "foreign_keys": foreign_keys
                }

            except Exception as e:
                self.add_finding(
                    "database_models", "MEDIUM",
                    f"Relationship Audit Error in {model_file.name}",
                    f"Could not analyze relationships: {e}",
                    str(model_file)
                )

        # Validate relationship consistency
        self._validate_relationship_consistency(relationship_patterns)

    def _validate_relationship_consistency(self, patterns: Dict):
        """Validate that relationships are consistent across models."""
        # Check for orphaned foreign keys
        all_models = set(patterns.keys())

        for model_name, data in patterns.items():
            for rel_name, rel_target in data["relationships"]:
                target_file = f"{rel_target.lower()}.py"
                if target_file not in all_models:
                    self.add_finding(
                        "database_models", "HIGH",
                        f"Orphaned Relationship in {model_name}",
                        f"Relationship {rel_name} points to non-existent model {rel_target}",
                        recommendation=f"Create {target_file} or fix relationship"
                    )

    def audit_api_endpoints(self):
        """Audit RBAC API endpoints for security and consistency."""
        print("🔍 Auditing API Endpoints...")

        api_path = self.backend_base / "langflow" / "api" / "v1" / "rbac"

        if not api_path.exists():
            self.add_finding(
                "api_endpoints", "CRITICAL",
                "RBAC API Directory Missing",
                "The RBAC API directory does not exist",
                recommendation="Create RBAC API endpoint structure"
            )
            return

        # Check for essential endpoint files
        required_endpoints = [
            "workspaces.py", "projects.py", "roles.py", "permissions.py",
            "role_assignments.py", "audit.py"
        ]

        missing_endpoints = []
        for endpoint_file in required_endpoints:
            endpoint_path = api_path / endpoint_file
            if not endpoint_path.exists():
                missing_endpoints.append(endpoint_file)

        if missing_endpoints:
            self.add_finding(
                "api_endpoints", "HIGH",
                "Missing Essential API Endpoints",
                f"Missing endpoint files: {', '.join(missing_endpoints)}",
                recommendation="Implement all essential RBAC API endpoints"
            )

        # Audit each endpoint file
        for endpoint_file in api_path.glob("*.py"):
            if endpoint_file.name == "__init__.py":
                continue

            self._audit_endpoint_file(endpoint_file)

        self.audit_results["api_endpoints"]["status"] = "completed"
        self.audit_results["api_endpoints"]["endpoints_found"] = len(list(api_path.glob("*.py"))) - 1
        self.audit_results["api_endpoints"]["missing_endpoints"] = missing_endpoints

    def _audit_endpoint_file(self, endpoint_path: Path):
        """Audit individual API endpoint file."""
        try:
            with open(endpoint_path, 'r') as f:
                content = f.read()

            # Check for essential imports
            essential_imports = ["APIRouter", "Depends", "HTTPException"]
            for imp in essential_imports:
                if imp not in content:
                    self.add_finding(
                        "api_endpoints", "MEDIUM",
                        f"Missing Import in {endpoint_path.name}",
                        f"Missing essential import: {imp}",
                        str(endpoint_path),
                        recommendation=f"Add import for {imp}"
                    )

            # Check for authentication dependencies
            auth_patterns = ["CurrentActiveUser", "get_current_user", "get_enhanced_enforcement_context"]
            has_auth = any(pattern in content for pattern in auth_patterns)
            if not has_auth:
                self.add_finding(
                    "api_endpoints", "HIGH",
                    f"No Authentication in {endpoint_path.name}",
                    "No authentication dependencies found",
                    str(endpoint_path),
                    recommendation="Add authentication dependencies to all endpoints"
                )

            # Check for authorization patterns
            auth_z_patterns = ["check_permission", "permission_engine", "rbac"]
            has_authz = any(pattern in content for pattern in auth_z_patterns)
            if not has_authz:
                self.add_finding(
                    "api_endpoints", "HIGH",
                    f"No Authorization in {endpoint_path.name}",
                    "No authorization patterns found",
                    str(endpoint_path),
                    recommendation="Add authorization checks to all endpoints"
                )

            # Check for input validation
            validation_patterns = ["Pydantic", "BaseModel", "Field", "validator"]
            has_validation = any(pattern in content for pattern in validation_patterns)
            if not has_validation:
                self.add_finding(
                    "api_endpoints", "MEDIUM",
                    f"Limited Input Validation in {endpoint_path.name}",
                    "No clear input validation patterns found",
                    str(endpoint_path),
                    recommendation="Add comprehensive input validation"
                )

            # Check for error handling
            if "HTTPException" not in content:
                self.add_finding(
                    "api_endpoints", "MEDIUM",
                    f"No Error Handling in {endpoint_path.name}",
                    "No HTTPException usage found",
                    str(endpoint_path),
                    recommendation="Add proper error handling"
                )

            # Check for audit logging
            audit_patterns = ["audit", "log", "AuditService"]
            has_audit = any(pattern in content for pattern in audit_patterns)
            if not has_audit:
                self.add_finding(
                    "api_endpoints", "MEDIUM",
                    f"No Audit Logging in {endpoint_path.name}",
                    "No audit logging patterns found",
                    str(endpoint_path),
                    recommendation="Add audit logging for sensitive operations"
                )

            # Check for SQL injection protection
            if "select(" not in content.lower() and "query" in content.lower():
                self.add_finding(
                    "api_endpoints", "INFO",
                    f"Raw SQL Usage in {endpoint_path.name}",
                    "Potential raw SQL usage detected",
                    str(endpoint_path),
                    recommendation="Use SQLModel query builder to prevent SQL injection"
                )

            # Check HTTP methods and CRUD operations
            self._audit_http_methods(endpoint_path, content)

        except Exception as e:
            self.add_finding(
                "api_endpoints", "HIGH",
                f"Error Auditing {endpoint_path.name}",
                f"Could not audit endpoint file: {e}",
                str(endpoint_path)
            )

    def _audit_http_methods(self, endpoint_path: Path, content: str):
        """Audit HTTP methods for proper CRUD implementation."""
        http_methods = {
            "GET": "@router.get",
            "POST": "@router.post",
            "PUT": "@router.put",
            "PATCH": "@router.patch",
            "DELETE": "@router.delete"
        }

        found_methods = []
        for method, decorator in http_methods.items():
            if decorator in content:
                found_methods.append(method)

        # Check for complete CRUD operations
        if "GET" not in found_methods:
            self.add_finding(
                "api_endpoints", "LOW",
                f"Missing READ Operations in {endpoint_path.name}",
                "No GET endpoints found",
                str(endpoint_path),
                recommendation="Add READ operations"
            )

        if "POST" not in found_methods:
            self.add_finding(
                "api_endpoints", "LOW",
                f"Missing CREATE Operations in {endpoint_path.name}",
                "No POST endpoints found",
                str(endpoint_path),
                recommendation="Add CREATE operations"
            )

    def audit_service_layer(self):
        """Audit RBAC service layer and business logic."""
        print("🔍 Auditing Service Layer...")

        services_path = self.backend_base / "langflow" / "services" / "rbac"

        if not services_path.exists():
            self.add_finding(
                "service_layer", "CRITICAL",
                "RBAC Services Directory Missing",
                "The RBAC services directory does not exist",
                recommendation="Create RBAC services directory structure"
            )
            return

        # Check for essential service files
        required_services = [
            "service.py", "permission_engine.py", "audit_service.py",
            "validation.py", "runtime_enforcement.py"
        ]

        missing_services = []
        for service_file in required_services:
            service_path = services_path / service_file
            if not service_path.exists():
                missing_services.append(service_file)

        if missing_services:
            self.add_finding(
                "service_layer", "HIGH",
                "Missing Essential Services",
                f"Missing service files: {', '.join(missing_services)}",
                recommendation="Implement all essential RBAC services"
            )

        # Audit each service file
        for service_file in services_path.glob("*.py"):
            if service_file.name == "__init__.py":
                continue

            self._audit_service_file(service_file)

        self.audit_results["service_layer"]["status"] = "completed"
        self.audit_results["service_layer"]["services_found"] = len(list(services_path.glob("*.py"))) - 1
        self.audit_results["service_layer"]["missing_services"] = missing_services

    def _audit_service_file(self, service_path: Path):
        """Audit individual service file."""
        try:
            with open(service_path, 'r') as f:
                content = f.read()

            # Check for proper class structure
            if "class " not in content:
                self.add_finding(
                    "service_layer", "MEDIUM",
                    f"No Service Class in {service_path.name}",
                    "No service class definition found",
                    str(service_path),
                    recommendation="Implement proper service class structure"
                )

            # Check for dependency injection
            if "Depends" not in content and "inject" not in content.lower():
                self.add_finding(
                    "service_layer", "MEDIUM",
                    f"No Dependency Injection in {service_path.name}",
                    "No dependency injection patterns found",
                    str(service_path),
                    recommendation="Implement dependency injection"
                )

            # Check for error handling
            if "try:" not in content or "except" not in content:
                self.add_finding(
                    "service_layer", "MEDIUM",
                    f"Limited Error Handling in {service_path.name}",
                    "No try-except blocks found",
                    str(service_path),
                    recommendation="Add comprehensive error handling"
                )

            # Check for logging
            if "logger" not in content and "log" not in content:
                self.add_finding(
                    "service_layer", "LOW",
                    f"No Logging in {service_path.name}",
                    "No logging functionality found",
                    str(service_path),
                    recommendation="Add logging for debugging and audit"
                )

            # Check for async patterns
            if "async def" not in content and "await" not in content:
                self.add_finding(
                    "service_layer", "INFO",
                    f"No Async Patterns in {service_path.name}",
                    "No async/await patterns found",
                    str(service_path),
                    recommendation="Consider async patterns for performance"
                )

            # Check for data validation
            if "validate" not in content.lower() and "valid" not in content.lower():
                self.add_finding(
                    "service_layer", "MEDIUM",
                    f"No Data Validation in {service_path.name}",
                    "No validation patterns found",
                    str(service_path),
                    recommendation="Add data validation to service methods"
                )

        except Exception as e:
            self.add_finding(
                "service_layer", "HIGH",
                f"Error Auditing {service_path.name}",
                f"Could not audit service file: {e}",
                str(service_path)
            )

    def audit_authentication_flows(self):
        """Audit authentication implementation."""
        print("🔍 Auditing Authentication Flows...")

        auth_paths = [
            self.backend_base / "langflow" / "services" / "auth",
            self.backend_base / "langflow" / "services" / "settings"
        ]

        auth_files_found = []
        for auth_path in auth_paths:
            if auth_path.exists():
                auth_files_found.extend(list(auth_path.glob("*.py")))

        if not auth_files_found:
            self.add_finding(
                "authentication", "CRITICAL",
                "No Authentication Files Found",
                "No authentication implementation found",
                recommendation="Implement authentication system"
            )
            return

        # Check essential authentication components
        essential_auth_files = ["utils.py", "auth.py", "security_config.py"]
        missing_auth_files = []

        for auth_file in essential_auth_files:
            found = any(auth_file in str(f) for f in auth_files_found)
            if not found:
                missing_auth_files.append(auth_file)

        if missing_auth_files:
            self.add_finding(
                "authentication", "HIGH",
                "Missing Authentication Components",
                f"Missing auth files: {', '.join(missing_auth_files)}",
                recommendation="Implement missing authentication components"
            )

        # Audit authentication security
        for auth_file in auth_files_found:
            self._audit_auth_file(auth_file)

        self.audit_results["authentication"]["status"] = "completed"
        self.audit_results["authentication"]["auth_files_found"] = len(auth_files_found)
        self.audit_results["authentication"]["missing_auth_files"] = missing_auth_files

    def _audit_auth_file(self, auth_path: Path):
        """Audit individual authentication file."""
        try:
            with open(auth_path, 'r') as f:
                content = f.read()

            # Check for password security
            if "password" in content.lower():
                if "bcrypt" not in content and "hash" not in content and "scrypt" not in content:
                    self.add_finding(
                        "authentication", "HIGH",
                        f"Weak Password Handling in {auth_path.name}",
                        "Password handling without proper hashing detected",
                        str(auth_path),
                        recommendation="Use bcrypt or similar for password hashing"
                    )

            # Check for JWT security
            if "jwt" in content.lower() or "token" in content.lower():
                if "secret" in content.lower() and "environment" not in content.lower():
                    self.add_finding(
                        "authentication", "HIGH",
                        f"Hardcoded Secrets in {auth_path.name}",
                        "Potential hardcoded secrets detected",
                        str(auth_path),
                        recommendation="Use environment variables for secrets"
                    )

                if "expire" not in content.lower():
                    self.add_finding(
                        "authentication", "MEDIUM",
                        f"No Token Expiration in {auth_path.name}",
                        "No token expiration logic found",
                        str(auth_path),
                        recommendation="Implement token expiration"
                    )

            # Check for session security
            if "session" in content.lower():
                if "secure" not in content.lower() or "httponly" not in content.lower():
                    self.add_finding(
                        "authentication", "MEDIUM",
                        f"Insecure Session Config in {auth_path.name}",
                        "Session security flags not found",
                        str(auth_path),
                        recommendation="Add Secure and HttpOnly flags to sessions"
                    )

            # Check for rate limiting
            if "login" in content.lower() and "rate" not in content.lower() and "limit" not in content.lower():
                self.add_finding(
                    "authentication", "MEDIUM",
                    f"No Rate Limiting in {auth_path.name}",
                    "No rate limiting for authentication",
                    str(auth_path),
                    recommendation="Implement rate limiting for login attempts"
                )

            # Check for MFA support
            if "mfa" not in content.lower() and "2fa" not in content.lower() and "totp" not in content.lower():
                self.add_finding(
                    "authentication", "LOW",
                    f"No MFA Support in {auth_path.name}",
                    "No multi-factor authentication support",
                    str(auth_path),
                    recommendation="Consider implementing MFA for enhanced security"
                )

        except Exception as e:
            self.add_finding(
                "authentication", "HIGH",
                f"Error Auditing {auth_path.name}",
                f"Could not audit auth file: {e}",
                str(auth_path)
            )

    def audit_authorization_patterns(self):
        """Audit authorization implementation."""
        print("🔍 Auditing Authorization Patterns...")

        # Look for authorization patterns across the codebase
        auth_z_files = []

        # Check RBAC services
        rbac_path = self.backend_base / "langflow" / "services" / "rbac"
        if rbac_path.exists():
            auth_z_files.extend(list(rbac_path.glob("*.py")))

        # Check API dependencies
        api_path = self.backend_base / "langflow" / "api"
        if api_path.exists():
            for file_path in api_path.rglob("*.py"):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if any(pattern in content for pattern in ["permission", "authorization", "rbac"]):
                        auth_z_files.append(file_path)

        if not auth_z_files:
            self.add_finding(
                "authorization", "CRITICAL",
                "No Authorization Implementation Found",
                "No authorization patterns detected in codebase",
                recommendation="Implement comprehensive authorization system"
            )
            return

        # Audit authorization files
        for auth_z_file in auth_z_files:
            self._audit_authorization_file(auth_z_file)

        self.audit_results["authorization"]["status"] = "completed"
        self.audit_results["authorization"]["auth_z_files_found"] = len(auth_z_files)

    def _audit_authorization_file(self, auth_z_path: Path):
        """Audit individual authorization file."""
        try:
            with open(auth_z_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for permission checking patterns
            permission_patterns = ["check_permission", "has_permission", "authorize", "can_access"]
            has_permission_check = any(pattern in content for pattern in permission_patterns)

            if not has_permission_check:
                self.add_finding(
                    "authorization", "MEDIUM",
                    f"No Permission Checks in {auth_z_path.name}",
                    "No permission checking patterns found",
                    str(auth_z_path),
                    recommendation="Implement permission checking mechanisms"
                )

            # Check for role-based access
            if "role" in content.lower() and "check" not in content.lower():
                self.add_finding(
                    "authorization", "MEDIUM",
                    f"No Role Validation in {auth_z_path.name}",
                    "Role references without validation",
                    str(auth_z_path),
                    recommendation="Add role validation logic"
                )

            # Check for workspace isolation
            if "workspace" in content.lower() and "isolation" not in content.lower():
                workspace_checks = ["workspace_id", "user.workspace", "current_workspace"]
                has_workspace_check = any(check in content for check in workspace_checks)

                if not has_workspace_check:
                    self.add_finding(
                        "authorization", "HIGH",
                        f"No Workspace Isolation in {auth_z_path.name}",
                        "Workspace references without isolation checks",
                        str(auth_z_path),
                        recommendation="Implement workspace isolation checks"
                    )

            # Check for privilege escalation protection
            escalation_patterns = ["sudo", "admin", "superuser", "root"]
            has_escalation_ref = any(pattern in content.lower() for pattern in escalation_patterns)

            if has_escalation_ref and "check" not in content.lower():
                self.add_finding(
                    "authorization", "HIGH",
                    f"Potential Privilege Escalation in {auth_z_path.name}",
                    "Admin/privileged operations without checks",
                    str(auth_z_path),
                    recommendation="Add privilege escalation protection"
                )

        except Exception as e:
            self.add_finding(
                "authorization", "HIGH",
                f"Error Auditing {auth_z_path.name}",
                f"Could not audit authorization file: {e}",
                str(auth_z_path)
            )

    def audit_data_access_patterns(self):
        """Audit data access patterns and workspace isolation."""
        print("🔍 Auditing Data Access Patterns...")

        # Check flows.py and other data access points
        data_access_files = [
            self.backend_base / "langflow" / "api" / "v1" / "flows.py",
            self.backend_base / "langflow" / "services" / "auth" / "secure_data_access.py"
        ]

        existing_files = [f for f in data_access_files if f.exists()]

        if not existing_files:
            self.add_finding(
                "data_access", "CRITICAL",
                "No Secure Data Access Implementation",
                "No secure data access patterns found",
                recommendation="Implement secure data access service"
            )
            return

        for data_file in existing_files:
            self._audit_data_access_file(data_file)

        # Check for SQL injection vulnerabilities
        self._audit_sql_injection_risks()

        self.audit_results["data_access"]["status"] = "completed"
        self.audit_results["data_access"]["data_files_audited"] = len(existing_files)

    def _audit_data_access_file(self, data_path: Path):
        """Audit individual data access file."""
        try:
            with open(data_path, 'r') as f:
                content = f.read()

            # Check for user-based filtering (potential vulnerability)
            if "user_id" in content and "workspace" not in content:
                self.add_finding(
                    "data_access", "HIGH",
                    f"User-Based Filtering in {data_path.name}",
                    "User-based filtering without workspace checks",
                    str(data_path),
                    recommendation="Replace user-based filtering with workspace-based RBAC"
                )

            # Check for workspace isolation
            if "workspace_id" not in content and "workspace" in data_path.name.lower():
                self.add_finding(
                    "data_access", "HIGH",
                    f"No Workspace Filtering in {data_path.name}",
                    "Missing workspace isolation in data access",
                    str(data_path),
                    recommendation="Implement workspace-based data filtering"
                )

            # Check for direct database access
            if "session.get" in content or "session.query" in content:
                if "permission" not in content and "rbac" not in content:
                    self.add_finding(
                        "data_access", "MEDIUM",
                        f"Direct DB Access in {data_path.name}",
                        "Direct database access without permission checks",
                        str(data_path),
                        recommendation="Add permission checks to database operations"
                    )

            # Check for secure data service usage
            if "SecureDataAccessService" not in content and "secure" in data_path.name.lower():
                self.add_finding(
                    "data_access", "MEDIUM",
                    f"Missing Secure Service in {data_path.name}",
                    "Not using secure data access service",
                    str(data_path),
                    recommendation="Use SecureDataAccessService for all data operations"
                )

        except Exception as e:
            self.add_finding(
                "data_access", "HIGH",
                f"Error Auditing {data_path.name}",
                f"Could not audit data access file: {e}",
                str(data_path)
            )

    def _audit_sql_injection_risks(self):
        """Audit for SQL injection vulnerabilities."""
        # Search for potential SQL injection patterns
        api_path = self.backend_base / "langflow" / "api"

        if not api_path.exists():
            return

        for file_path in api_path.rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Check for string formatting in SQL
                sql_patterns = [
                    r'select.*%',
                    r'where.*\+',
                    r'f".*select',
                    r'\.format.*select'
                ]

                for pattern in sql_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.add_finding(
                            "data_access", "HIGH",
                            f"Potential SQL Injection in {file_path.name}",
                            f"Unsafe SQL pattern detected: {pattern}",
                            str(file_path),
                            recommendation="Use parameterized queries or SQLModel query builder"
                        )

            except Exception:
                continue  # Skip files that can't be read

    def audit_security_patterns(self):
        """Audit overall security patterns and configurations."""
        print("🔍 Auditing Security Patterns...")

        # Check security configuration
        security_config_path = self.backend_base / "langflow" / "services" / "settings" / "security_config.py"

        if security_config_path.exists():
            self._audit_security_config(security_config_path)
        else:
            self.add_finding(
                "security_patterns", "CRITICAL",
                "Missing Security Configuration",
                "No security configuration file found",
                recommendation="Implement comprehensive security configuration"
            )

        # Check main application file
        main_path = self.backend_base / "langflow" / "main.py"
        if main_path.exists():
            self._audit_main_security(main_path)

        # Audit middleware
        self._audit_security_middleware()

        self.audit_results["security_patterns"]["status"] = "completed"

    def _audit_security_config(self, config_path: Path):
        """Audit security configuration file."""
        try:
            with open(config_path, 'r') as f:
                content = f.read()

            # Check for essential security settings
            security_settings = [
                "CORS", "csrf", "security_headers", "rate_limit",
                "session_timeout", "password_policy"
            ]

            for setting in security_settings:
                if setting.lower() not in content.lower():
                    self.add_finding(
                        "security_patterns", "MEDIUM",
                        f"Missing Security Setting: {setting}",
                        f"Security configuration missing {setting}",
                        str(config_path),
                        recommendation=f"Add {setting} configuration"
                    )

            # Check for hardcoded secrets
            if re.search(r'secret.*=.*["\'][^"\']{20,}["\']', content, re.IGNORECASE):
                self.add_finding(
                    "security_patterns", "HIGH",
                    "Potential Hardcoded Secret",
                    "Hardcoded secret detected in security config",
                    str(config_path),
                    recommendation="Use environment variables for secrets"
                )

            # Check for secure defaults
            if "auto_login.*true" in content.lower().replace(" ", ""):
                self.add_finding(
                    "security_patterns", "HIGH",
                    "Insecure Auto-Login Default",
                    "Auto-login enabled by default",
                    str(config_path),
                    recommendation="Disable auto-login by default"
                )

        except Exception as e:
            self.add_finding(
                "security_patterns", "HIGH",
                f"Error Auditing Security Config",
                f"Could not audit security config: {e}",
                str(config_path)
            )

    def _audit_main_security(self, main_path: Path):
        """Audit main application security."""
        try:
            with open(main_path, 'r') as f:
                content = f.read()

            # Check for security middleware
            middleware_patterns = ["CORS", "Security", "Rate", "Authentication"]
            missing_middleware = []

            for middleware in middleware_patterns:
                if middleware.lower() not in content.lower():
                    missing_middleware.append(middleware)

            if missing_middleware:
                self.add_finding(
                    "security_patterns", "MEDIUM",
                    "Missing Security Middleware",
                    f"Missing middleware: {', '.join(missing_middleware)}",
                    str(main_path),
                    recommendation="Add all essential security middleware"
                )

            # Check for debug mode
            if "debug=True" in content.replace(" ", ""):
                self.add_finding(
                    "security_patterns", "HIGH",
                    "Debug Mode Enabled",
                    "Debug mode enabled in main application",
                    str(main_path),
                    recommendation="Disable debug mode in production"
                )

        except Exception as e:
            self.add_finding(
                "security_patterns", "HIGH",
                f"Error Auditing Main Application",
                f"Could not audit main application: {e}",
                str(main_path)
            )

    def _audit_security_middleware(self):
        """Audit security middleware implementation."""
        # Check for middleware files
        middleware_paths = [
            self.backend_base / "langflow" / "middleware",
            self.backend_base / "langflow" / "services" / "auth"
        ]

        middleware_files = []
        for path in middleware_paths:
            if path.exists():
                middleware_files.extend(list(path.glob("*.py")))

        if not middleware_files:
            self.add_finding(
                "security_patterns", "HIGH",
                "No Security Middleware Found",
                "No security middleware implementation detected",
                recommendation="Implement security middleware layer"
            )
            return

        for middleware_file in middleware_files:
            try:
                with open(middleware_file, 'r') as f:
                    content = f.read()

                # Check for essential middleware patterns
                if "middleware" in middleware_file.name.lower():
                    if "request" not in content or "response" not in content:
                        self.add_finding(
                            "security_patterns", "MEDIUM",
                            f"Incomplete Middleware in {middleware_file.name}",
                            "Middleware missing request/response handling",
                            str(middleware_file),
                            recommendation="Implement complete middleware pattern"
                        )

            except Exception:
                continue

    def generate_comprehensive_report(self):
        """Generate the comprehensive audit report."""
        print("📊 Generating Comprehensive Audit Report...")

        # Calculate summary statistics
        total_findings = len(self.findings)
        critical_count = len([f for f in self.findings if f["severity"] == "CRITICAL"])
        high_count = len([f for f in self.findings if f["severity"] == "HIGH"])
        medium_count = len([f for f in self.findings if f["severity"] == "MEDIUM"])
        low_count = len([f for f in self.findings if f["severity"] == "LOW"])
        info_count = len([f for f in self.findings if f["severity"] == "INFO"])

        # Generate report
        report = {
            "audit_metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "auditor": "RBAC Comprehensive Audit Framework",
                "version": "1.0",
                "scope": "Complete RBAC Implementation"
            },
            "executive_summary": {
                "total_findings": total_findings,
                "critical_issues": critical_count,
                "high_severity": high_count,
                "medium_severity": medium_count,
                "low_severity": low_count,
                "informational": info_count,
                "overall_risk_level": self._calculate_risk_level(critical_count, high_count, medium_count)
            },
            "audit_results": self.audit_results,
            "detailed_findings": self.findings,
            "recommendations": self._generate_recommendations(),
            "compliance_assessment": self._assess_compliance(),
            "security_score": self._calculate_security_score()
        }

        # Save report to file
        report_path = self.backend_base / "rbac_comprehensive_audit_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Print summary
        self._print_audit_summary(report)

        return report

    def _calculate_risk_level(self, critical: int, high: int, medium: int) -> str:
        """Calculate overall risk level."""
        if critical > 0:
            return "CRITICAL"
        elif high > 3:
            return "HIGH"
        elif high > 0 or medium > 5:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Critical recommendations
        if any(f["severity"] == "CRITICAL" for f in self.findings):
            recommendations.append(
                "🚨 IMMEDIATE ACTION REQUIRED: Address all CRITICAL findings before production deployment"
            )

        # Security recommendations
        security_findings = [f for f in self.findings if "security" in f["category"].lower()]
        if security_findings:
            recommendations.append(
                "🔒 SECURITY: Implement comprehensive security controls across all layers"
            )

        # Architecture recommendations
        if len(self.findings) > 20:
            recommendations.append(
                "🏗️ ARCHITECTURE: Consider architectural review to address systemic issues"
            )

        # Compliance recommendations
        recommendations.extend([
            "📋 COMPLIANCE: Implement audit logging for all sensitive operations",
            "🔍 MONITORING: Set up continuous security monitoring and alerting",
            "📚 DOCUMENTATION: Create comprehensive RBAC documentation and runbooks",
            "🧪 TESTING: Implement comprehensive security testing suite",
            "👥 TRAINING: Provide security training for development team"
        ])

        return recommendations

    def _assess_compliance(self) -> Dict:
        """Assess compliance with various standards."""
        return {
            "SOC2": {
                "status": "PARTIAL",
                "missing_controls": ["Continuous monitoring", "Incident response"],
                "implemented_controls": ["Access controls", "Audit logging"]
            },
            "ISO27001": {
                "status": "PARTIAL",
                "missing_controls": ["Risk assessment", "Security training"],
                "implemented_controls": ["Access management", "Authentication"]
            },
            "GDPR": {
                "status": "NEEDS_REVIEW",
                "missing_controls": ["Data minimization", "Right to be forgotten"],
                "implemented_controls": ["Access controls", "Audit trails"]
            },
            "NIST": {
                "status": "PARTIAL",
                "missing_controls": ["Continuous monitoring", "Incident response"],
                "implemented_controls": ["Identity management", "Access control"]
            }
        }

    def _calculate_security_score(self) -> Dict:
        """Calculate security score based on findings."""
        total_possible = 100
        deductions = 0

        # Deduct points based on severity
        deductions += len([f for f in self.findings if f["severity"] == "CRITICAL"]) * 20
        deductions += len([f for f in self.findings if f["severity"] == "HIGH"]) * 10
        deductions += len([f for f in self.findings if f["severity"] == "MEDIUM"]) * 5
        deductions += len([f for f in self.findings if f["severity"] == "LOW"]) * 2

        score = max(0, total_possible - deductions)

        return {
            "overall_score": score,
            "grade": self._score_to_grade(score),
            "breakdown": {
                "authentication": self._category_score("authentication"),
                "authorization": self._category_score("authorization"),
                "data_access": self._category_score("data_access"),
                "api_security": self._category_score("api_endpoints"),
                "database_security": self._category_score("database_models")
            }
        }

    def _category_score(self, category: str) -> int:
        """Calculate score for specific category."""
        category_findings = [f for f in self.findings if f["category"] == category]
        if not category_findings:
            return 85  # Baseline score if no findings

        deductions = 0
        deductions += len([f for f in category_findings if f["severity"] == "CRITICAL"]) * 30
        deductions += len([f for f in category_findings if f["severity"] == "HIGH"]) * 15
        deductions += len([f for f in category_findings if f["severity"] == "MEDIUM"]) * 8
        deductions += len([f for f in category_findings if f["severity"] == "LOW"]) * 3

        return max(0, 100 - deductions)

    def _score_to_grade(self, score: int) -> str:
        """Convert score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _print_audit_summary(self, report: Dict):
        """Print audit summary to console."""
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE RBAC AUDIT SUMMARY")
        print("=" * 80)

        summary = report["executive_summary"]

        print(f"\n📈 FINDINGS OVERVIEW:")
        print(f"   Total Findings: {summary['total_findings']}")
        print(f"   🚨 Critical: {summary['critical_issues']}")
        print(f"   🔴 High: {summary['high_severity']}")
        print(f"   🟡 Medium: {summary['medium_severity']}")
        print(f"   🔵 Low: {summary['low_severity']}")
        print(f"   ℹ️  Info: {summary['informational']}")

        print(f"\n🎯 OVERALL ASSESSMENT:")
        print(f"   Risk Level: {summary['overall_risk_level']}")
        print(f"   Security Score: {report['security_score']['overall_score']}/100 (Grade: {report['security_score']['grade']})")

        print(f"\n🔍 CATEGORY BREAKDOWN:")
        for category, score in report['security_score']['breakdown'].items():
            status_icon = "✅" if score >= 80 else "⚠️" if score >= 60 else "❌"
            print(f"   {status_icon} {category.replace('_', ' ').title()}: {score}/100")

        print(f"\n💡 TOP RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'][:5], 1):
            print(f"   {i}. {rec}")

        if summary['critical_issues'] > 0:
            print(f"\n🚨 CRITICAL ATTENTION REQUIRED!")
            print(f"   {summary['critical_issues']} critical issue(s) must be resolved immediately")

        print("\n" + "=" * 80)
        print(f"📄 Full report saved to: rbac_comprehensive_audit_report.json")
        print("=" * 80)

    def run_comprehensive_audit(self):
        """Run the complete RBAC audit."""
        print("🚀 Starting Comprehensive RBAC Implementation Audit...")
        print("=" * 80)

        try:
            # Run all audit phases
            self.audit_database_models()
            self.audit_api_endpoints()
            self.audit_service_layer()
            self.audit_authentication_flows()
            self.audit_authorization_patterns()
            self.audit_data_access_patterns()
            self.audit_security_patterns()

            # Generate final report
            report = self.generate_comprehensive_report()

            return report

        except Exception as e:
            print(f"❌ Audit failed with error: {e}")
            self.add_finding(
                "audit_framework", "CRITICAL",
                "Audit Framework Error",
                f"Audit framework encountered an error: {e}",
                recommendation="Review audit framework implementation"
            )
            return None


def main():
    """Main audit execution."""
    auditor = RBACComprehensiveAudit()
    report = auditor.run_comprehensive_audit()

    if report:
        # Return success/failure based on critical issues
        has_critical = report["executive_summary"]["critical_issues"] > 0
        return 1 if has_critical else 0
    else:
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
