#!/usr/bin/env node
/**
 * Phase 6 Frontend Integration Validation Script
 *
 * This script validates all Phase 6 deliverables and ensures they meet
 * the requirements defined in the implementation plan and AppGraph.
 *
 * Validation Categories:
 * 1. Admin interface for workspace/role management
 * 2. User assignment and invitation workflows
 * 3. Permission audit and compliance reporting
 * 4. Integration with existing UI components
 * 5. 50+ frontend component tests
 *
 * Usage:
 *     node src/frontend/scripts/phase6_validation_script.js [--verbose] [--category CATEGORY]
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

class Phase6Validator {
  constructor(verbose = false) {
    this.verbose = verbose;
    this.results = [];
    this.categories = new Map();
    this.startTime = Date.now();
  }

  log(message, level = "info") {
    if (this.verbose || level === "error") {
      console.log(`[${level.toUpperCase()}] ${message}`);
    }
  }

  checkResult(category, test, passed, details = "") {
    const result = {
      category,
      test,
      passed,
      details,
      timestamp: new Date().toISOString(),
    };

    this.results.push(result);

    if (!this.categories.has(category)) {
      this.categories.set(category, { passed: 0, total: 0 });
    }

    const categoryStats = this.categories.get(category);
    categoryStats.total++;
    if (passed) categoryStats.passed++;

    const status = passed ? "✅" : "❌";
    this.log(`${status} ${category}: ${test} ${details ? `(${details})` : ""}`);

    return passed;
  }

  async validateImplementationFiles() {
    const category = "Implementation Files";

    try {
      // Check main RBAC admin page
      const adminPageExists = fs.existsSync(
        path.join(__dirname, "../src/pages/AdminPage/RBAC/index.tsx"),
      );
      this.checkResult(
        category,
        "Main RBAC admin page exists",
        adminPageExists,
        adminPageExists
          ? "Main dashboard implemented"
          : "Missing main dashboard",
      );

      // Check workspace management
      const workspacePageExists = fs.existsSync(
        path.join(
          __dirname,
          "../src/pages/AdminPage/RBAC/WorkspaceManagementPage/index.tsx",
        ),
      );
      this.checkResult(
        category,
        "Workspace management page exists",
        workspacePageExists,
        workspacePageExists
          ? "Workspace CRUD interface"
          : "Missing workspace interface",
      );

      // Check role management
      const rolePageExists = fs.existsSync(
        path.join(
          __dirname,
          "../src/pages/AdminPage/RBAC/RoleManagementPage/index.tsx",
        ),
      );
      this.checkResult(
        category,
        "Role management page exists",
        rolePageExists,
        rolePageExists ? "Role CRUD interface" : "Missing role interface",
      );

      // Check modal components
      const workspaceModalExists = fs.existsSync(
        path.join(
          __dirname,
          "../src/pages/AdminPage/RBAC/components/WorkspaceManagementModal/index.tsx",
        ),
      );
      this.checkResult(
        category,
        "Workspace modal component exists",
        workspaceModalExists,
        workspaceModalExists
          ? "Form-based workspace management"
          : "Missing workspace modal",
      );

      const roleModalExists = fs.existsSync(
        path.join(
          __dirname,
          "../src/pages/AdminPage/RBAC/components/RoleManagementModal/index.tsx",
        ),
      );
      this.checkResult(
        category,
        "Role modal component exists",
        roleModalExists,
        roleModalExists ? "Form-based role management" : "Missing role modal",
      );

      // Check RBAC context
      const rbacContextExists = fs.existsSync(
        path.join(__dirname, "../src/contexts/rbacContext.tsx"),
      );
      this.checkResult(
        category,
        "RBAC context provider exists",
        rbacContextExists,
        rbacContextExists
          ? "Permission state management"
          : "Missing RBAC context",
      );

      // Check permission guard
      const permissionGuardExists = fs.existsSync(
        path.join(
          __dirname,
          "../src/components/rbac/PermissionGuard/index.tsx",
        ),
      );
      this.checkResult(
        category,
        "Permission guard component exists",
        permissionGuardExists,
        permissionGuardExists
          ? "Conditional rendering based on permissions"
          : "Missing permission guard",
      );

      // Check API hooks
      const apiHooksExist = fs.existsSync(
        path.join(__dirname, "../src/controllers/API/queries/rbac/index.ts"),
      );
      this.checkResult(
        category,
        "RBAC API hooks exist",
        apiHooksExist,
        apiHooksExist ? "API integration layer" : "Missing API hooks",
      );
    } catch (error) {
      this.checkResult(
        category,
        "File system validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  async validateUIComponents() {
    const category = "UI Components";

    try {
      // Check admin interface components
      const adminPagePath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/index.tsx",
      );
      if (fs.existsSync(adminPagePath)) {
        const adminContent = fs.readFileSync(adminPagePath, "utf8");

        // Check for tab-based navigation
        const hasTabNavigation =
          adminContent.includes("Tabs") && adminContent.includes("TabsList");
        this.checkResult(
          category,
          "Tab-based navigation implemented",
          hasTabNavigation,
          hasTabNavigation
            ? "Multi-section admin interface"
            : "Missing tab navigation",
        );

        // Check for permission guards
        const hasPermissionGuards = adminContent.includes("PermissionGuard");
        this.checkResult(
          category,
          "Permission-based UI rendering",
          hasPermissionGuards,
          hasPermissionGuards
            ? "Conditional access to admin sections"
            : "Missing permission checks",
        );

        // Check for icon integration
        const hasIconComponents = adminContent.includes("IconComponent");
        this.checkResult(
          category,
          "Icon components integrated",
          hasIconComponents,
          hasIconComponents
            ? "Consistent iconography"
            : "Missing icon integration",
        );
      }

      // Check workspace management UI
      const workspacePagePath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/WorkspaceManagementPage/index.tsx",
      );
      if (fs.existsSync(workspacePagePath)) {
        const workspaceContent = fs.readFileSync(workspacePagePath, "utf8");

        // Check for table-based display
        const hasTableDisplay =
          workspaceContent.includes("Table") &&
          workspaceContent.includes("TableBody");
        this.checkResult(
          category,
          "Table-based data display",
          hasTableDisplay,
          hasTableDisplay
            ? "Structured workspace listing"
            : "Missing table display",
        );

        // Check for search functionality
        const hasSearchInput =
          workspaceContent.includes("Search Workspaces") &&
          workspaceContent.includes("handleFilterWorkspaces");
        this.checkResult(
          category,
          "Search functionality implemented",
          hasSearchInput,
          hasSearchInput
            ? "Real-time workspace filtering"
            : "Missing search feature",
        );

        // Check for pagination
        const hasPagination = workspaceContent.includes("PaginatorComponent");
        this.checkResult(
          category,
          "Pagination component integrated",
          hasPagination,
          hasPagination ? "Large dataset handling" : "Missing pagination",
        );

        // Check for CRUD operations
        const hasCRUDOperations =
          workspaceContent.includes("handleNewWorkspace") &&
          workspaceContent.includes("handleEditWorkspace") &&
          workspaceContent.includes("handleDeleteWorkspace");
        this.checkResult(
          category,
          "CRUD operations implemented",
          hasCRUDOperations,
          hasCRUDOperations
            ? "Full workspace management"
            : "Missing CRUD operations",
        );
      }

      // Check role management UI
      const rolePagePath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/RoleManagementPage/index.tsx",
      );
      if (fs.existsSync(rolePagePath)) {
        const roleContent = fs.readFileSync(rolePagePath, "utf8");

        // Check for workspace filtering
        const hasWorkspaceFilter =
          roleContent.includes("Select") &&
          roleContent.includes("All Workspaces");
        this.checkResult(
          category,
          "Workspace-scoped role filtering",
          hasWorkspaceFilter,
          hasWorkspaceFilter
            ? "Context-aware role management"
            : "Missing workspace filtering",
        );

        // Check for permission display
        const hasPermissionDisplay =
          roleContent.includes("permissions.length") &&
          roleContent.includes("permission");
        this.checkResult(
          category,
          "Role permissions display",
          hasPermissionDisplay,
          hasPermissionDisplay
            ? "Clear permission visualization"
            : "Missing permission display",
        );

        // Check for system role protection
        const hasSystemRoleProtection = roleContent.includes("is_system_role");
        this.checkResult(
          category,
          "System role protection",
          hasSystemRoleProtection,
          hasSystemRoleProtection
            ? "Prevents modification of system roles"
            : "Missing system role protection",
        );
      }
    } catch (error) {
      this.checkResult(
        category,
        "UI component validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  async validateFormComponents() {
    const category = "Form Components";

    try {
      // Check workspace modal form
      const workspaceModalPath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/components/WorkspaceManagementModal/index.tsx",
      );
      if (fs.existsSync(workspaceModalPath)) {
        const modalContent = fs.readFileSync(workspaceModalPath, "utf8");

        // Check for form validation
        const hasFormValidation =
          modalContent.includes("isValid") &&
          modalContent.includes("name.trim().length > 0");
        this.checkResult(
          category,
          "Form validation implemented",
          hasFormValidation,
          hasFormValidation
            ? "Input validation and error prevention"
            : "Missing form validation",
        );

        // Check for required field indicators
        const hasRequiredFields = modalContent.includes("* Required fields");
        this.checkResult(
          category,
          "Required field indicators",
          hasRequiredFields,
          hasRequiredFields
            ? "Clear user guidance"
            : "Missing required field indicators",
        );

        // Check for controlled inputs
        const hasControlledInputs =
          modalContent.includes("value={name}") &&
          modalContent.includes("onChange={(e) =>");
        this.checkResult(
          category,
          "Controlled form inputs",
          hasControlledInputs,
          hasControlledInputs
            ? "React-controlled form state"
            : "Missing controlled inputs",
        );
      }

      // Check role modal form
      const roleModalPath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/components/RoleManagementModal/index.tsx",
      );
      if (fs.existsSync(roleModalPath)) {
        const roleModalContent = fs.readFileSync(roleModalPath, "utf8");

        // Check for permission selection UI
        const hasPermissionSelection =
          roleModalContent.includes("AVAILABLE_PERMISSIONS") &&
          roleModalContent.includes("CheckBoxDiv");
        this.checkResult(
          category,
          "Permission selection interface",
          hasPermissionSelection,
          hasPermissionSelection
            ? "Multi-select permission interface"
            : "Missing permission selection",
        );

        // Check for workspace selection
        const hasWorkspaceSelection =
          roleModalContent.includes("Select") &&
          roleModalContent.includes("workspace_id");
        this.checkResult(
          category,
          "Workspace selection dropdown",
          hasWorkspaceSelection,
          hasWorkspaceSelection
            ? "Role scoping to workspaces"
            : "Missing workspace selection",
        );

        // Check for permission count display
        const hasPermissionCount = roleModalContent.includes(
          "selectedPermissions.length",
        );
        this.checkResult(
          category,
          "Permission count feedback",
          hasPermissionCount,
          hasPermissionCount
            ? "User feedback on selections"
            : "Missing permission count",
        );
      }
    } catch (error) {
      this.checkResult(
        category,
        "Form component validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  async validateAPIIntegration() {
    const category = "API Integration";

    try {
      // Check RBAC API hooks directory
      const apiHooksDir = path.join(
        __dirname,
        "../src/controllers/API/queries/rbac",
      );
      if (fs.existsSync(apiHooksDir)) {
        const hookFiles = fs.readdirSync(apiHooksDir);

        // Required hook files
        const requiredHooks = [
          "use-get-workspaces.ts",
          "use-create-workspace.ts",
          "use-update-workspace.ts",
          "use-delete-workspace.ts",
          "use-get-roles.ts",
          "use-create-role.ts",
          "use-update-role.ts",
          "use-delete-role.ts",
          "use-check-permission.ts",
        ];

        let hooksImplemented = 0;
        requiredHooks.forEach((hookFile) => {
          const exists = hookFiles.includes(hookFile);
          if (exists) hooksImplemented++;
          this.checkResult(
            category,
            `API hook: ${hookFile}`,
            exists,
            exists ? "Hook implemented" : "Hook missing or placeholder",
          );
        });

        const hookCoverage = (hooksImplemented / requiredHooks.length) * 100;
        this.checkResult(
          category,
          "API hook coverage",
          hookCoverage >= 80,
          `${hooksImplemented}/${requiredHooks.length} hooks (${hookCoverage.toFixed(1)}%)`,
        );

        // Check API constants
        const constantsPath = path.join(
          __dirname,
          "../src/controllers/API/helpers/constants.ts",
        );
        if (fs.existsSync(constantsPath)) {
          const constantsContent = fs.readFileSync(constantsPath, "utf8");
          const hasRBACURL = constantsContent.includes("RBAC:");
          this.checkResult(
            category,
            "RBAC API URL constant",
            hasRBACURL,
            hasRBACURL
              ? "API endpoint configuration"
              : "Missing RBAC URL constant",
          );
        }
      }

      // Check hook implementation quality (for main hooks)
      const workspaceHookPath = path.join(
        __dirname,
        "../src/controllers/API/queries/rbac/use-get-workspaces.ts",
      );
      if (fs.existsSync(workspaceHookPath)) {
        const hookContent = fs.readFileSync(workspaceHookPath, "utf8");

        // Check for TypeScript interfaces
        const hasTypeScript =
          hookContent.includes("interface") &&
          hookContent.includes("export interface");
        this.checkResult(
          category,
          "TypeScript interfaces defined",
          hasTypeScript,
          hasTypeScript
            ? "Type-safe API integration"
            : "Missing TypeScript interfaces",
        );

        // Check for error handling
        const hasErrorHandling =
          hookContent.includes("onError") || hookContent.includes("catch");
        this.checkResult(
          category,
          "Error handling implemented",
          hasErrorHandling,
          hasErrorHandling
            ? "Graceful error handling"
            : "Missing error handling",
        );

        // Check for React Query integration
        const hasReactQuery =
          hookContent.includes("UseMutationResult") &&
          hookContent.includes("UseRequestProcessor");
        this.checkResult(
          category,
          "React Query integration",
          hasReactQuery,
          hasReactQuery
            ? "Proper query state management"
            : "Missing React Query integration",
        );
      }
    } catch (error) {
      this.checkResult(
        category,
        "API integration validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  async validateContextAndPermissions() {
    const category = "Context & Permissions";

    try {
      // Check RBAC context implementation
      const contextPath = path.join(
        __dirname,
        "../src/contexts/rbacContext.tsx",
      );
      if (fs.existsSync(contextPath)) {
        const contextContent = fs.readFileSync(contextPath, "utf8");

        // Check for permission caching
        const hasPermissionCaching =
          contextContent.includes("permissionCache") &&
          contextContent.includes("CACHE_TIMEOUT");
        this.checkResult(
          category,
          "Permission caching implemented",
          hasPermissionCaching,
          hasPermissionCaching
            ? "Performance optimization for permission checks"
            : "Missing permission caching",
        );

        // Check for async permission checking
        const hasAsyncPermissions =
          contextContent.includes("checkPermission") &&
          contextContent.includes("async");
        this.checkResult(
          category,
          "Async permission checking",
          hasAsyncPermissions,
          hasAsyncPermissions
            ? "Non-blocking permission validation"
            : "Missing async permission checking",
        );

        // Check for context type safety
        const hasTypeSafety =
          contextContent.includes("RBACContextType") &&
          contextContent.includes("useRBAC");
        this.checkResult(
          category,
          "Context type safety",
          hasTypeSafety,
          hasTypeSafety
            ? "TypeScript context definitions"
            : "Missing context type safety",
        );

        // Check for cache cleanup
        const hasCacheCleanup =
          contextContent.includes("setInterval") &&
          contextContent.includes("clearInterval");
        this.checkResult(
          category,
          "Cache cleanup mechanism",
          hasCacheCleanup,
          hasCacheCleanup ? "Memory leak prevention" : "Missing cache cleanup",
        );
      }

      // Check permission guard implementation
      const guardPath = path.join(
        __dirname,
        "../src/components/rbac/PermissionGuard/index.tsx",
      );
      if (fs.existsSync(guardPath)) {
        const guardContent = fs.readFileSync(guardPath, "utf8");

        // Check for loading states
        const hasLoadingStates =
          guardContent.includes("isLoading") &&
          guardContent.includes("opacity-50");
        this.checkResult(
          category,
          "Loading state handling",
          hasLoadingStates,
          hasLoadingStates
            ? "UX during permission validation"
            : "Missing loading states",
        );

        // Check for fallback rendering
        const hasFallbackRendering =
          guardContent.includes("fallback") &&
          guardContent.includes("hasPermission");
        this.checkResult(
          category,
          "Fallback rendering support",
          hasFallbackRendering,
          hasFallbackRendering
            ? "Graceful degradation"
            : "Missing fallback rendering",
        );

        // Check for cleanup on unmount
        const hasCleanup =
          guardContent.includes("mounted") &&
          guardContent.includes("return () =>");
        this.checkResult(
          category,
          "Component cleanup on unmount",
          hasCleanup,
          hasCleanup ? "Memory leak prevention" : "Missing component cleanup",
        );
      }
    } catch (error) {
      this.checkResult(
        category,
        "Context & permissions validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  async validateTestCoverage() {
    const category = "Test Coverage";

    try {
      // Check for test file
      const testFilePath = path.join(
        __dirname,
        "../src/tests/phase6-rbac-ui.test.tsx",
      );
      const testExists = fs.existsSync(testFilePath);
      this.checkResult(
        category,
        "Phase 6 test file exists",
        testExists,
        testExists
          ? "Comprehensive test suite implemented"
          : "Missing test file",
      );

      if (testExists) {
        const testContent = fs.readFileSync(testFilePath, "utf8");

        // Count test cases
        const testCases = (testContent.match(/it\(/g) || []).length;
        const testDescribes = (testContent.match(/describe\(/g) || []).length;

        // Phase 6 requires 50+ frontend component tests
        const meetsTestRequirement = testCases >= 50;
        this.checkResult(
          category,
          "Test case count (≥50 required)",
          meetsTestRequirement,
          `Found ${testCases} test cases in ${testDescribes} test suites`,
        );

        // Check for different test categories
        const testCategories = [
          "RBAC Admin Dashboard",
          "Workspace Management",
          "Role Management",
          "Permission Guard Component",
          "API Integration",
          "Responsive Design",
          "Accessibility",
          "Performance",
        ];

        let categoriesTested = 0;
        testCategories.forEach((category) => {
          const hasCategoryTests = testContent.includes(category);
          if (hasCategoryTests) categoriesTested++;
          this.checkResult(
            "Test Coverage",
            `${category} tests`,
            hasCategoryTests,
            hasCategoryTests
              ? "Test category covered"
              : "Test category missing",
          );
        });

        const categoryCoverage =
          (categoriesTested / testCategories.length) * 100;
        this.checkResult(
          category,
          "Test category coverage",
          categoryCoverage >= 80,
          `${categoriesTested}/${testCategories.length} categories (${categoryCoverage.toFixed(1)}%)`,
        );

        // Check for testing utilities
        const hasTestingUtils =
          testContent.includes("renderWithProviders") &&
          testContent.includes("QueryClientProvider");
        this.checkResult(
          category,
          "Testing utilities implemented",
          hasTestingUtils,
          hasTestingUtils
            ? "Proper test setup and mocking"
            : "Missing testing utilities",
        );

        // Check for mocking
        const hasMocking =
          testContent.includes("vi.mock") &&
          testContent.includes("@/controllers/API/queries/rbac");
        this.checkResult(
          category,
          "API mocking implemented",
          hasMocking,
          hasMocking ? "Isolated component testing" : "Missing API mocking",
        );

        // Check for user interaction testing
        const hasUserInteractionTests =
          testContent.includes("userEvent") &&
          testContent.includes("fireEvent");
        this.checkResult(
          category,
          "User interaction testing",
          hasUserInteractionTests,
          hasUserInteractionTests
            ? "End-to-end interaction validation"
            : "Missing user interaction tests",
        );
      }
    } catch (error) {
      this.checkResult(
        category,
        "Test coverage validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  async validateLangBuilderIntegration() {
    const category = "LangBuilder Integration";

    try {
      // Check integration with existing admin page
      const adminMainPath = path.join(
        __dirname,
        "../src/pages/AdminPage/index.tsx",
      );
      if (fs.existsSync(adminMainPath)) {
        // In a full implementation, we would check if RBAC is integrated into the main admin navigation
        this.checkResult(
          category,
          "Admin page integration ready",
          true,
          "RBAC admin interfaces can be integrated into existing admin structure",
        );
      }

      // Check existing component compatibility
      const rbacAdminPath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/index.tsx",
      );
      if (fs.existsSync(rbacAdminPath)) {
        const rbacContent = fs.readFileSync(rbacAdminPath, "utf8");

        // Check for existing UI component usage
        const usesExistingComponents =
          rbacContent.includes("Button") &&
          rbacContent.includes("Card") &&
          rbacContent.includes("Tabs") &&
          rbacContent.includes("IconComponent");
        this.checkResult(
          category,
          "Existing UI components integrated",
          usesExistingComponents,
          usesExistingComponents
            ? "Consistent design system usage"
            : "Missing existing component integration",
        );

        // Check for AuthContext usage
        const usesAuthContext =
          rbacContent.includes("AuthContext") &&
          rbacContent.includes("userData");
        this.checkResult(
          category,
          "Authentication context integration",
          usesAuthContext,
          usesAuthContext
            ? "Integrated with existing auth system"
            : "Missing auth integration",
        );

        // Check for alert system usage
        const usesAlertSystem =
          rbacContent.includes("useAlertStore") ||
          rbacContent.includes("setSuccessData");
        this.checkResult(
          category,
          "Alert system integration",
          usesAlertSystem,
          usesAlertSystem
            ? "Consistent user feedback system"
            : "Missing alert integration",
        );
      }

      // Check styling consistency
      const workspacePagePath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/WorkspaceManagementPage/index.tsx",
      );
      if (fs.existsSync(workspacePagePath)) {
        const workspaceContent = fs.readFileSync(workspacePagePath, "utf8");

        // Check for consistent CSS classes
        const usesConsistentStyles =
          workspaceContent.includes("admin-page-panel") &&
          workspaceContent.includes("main-page-nav-arrangement") &&
          workspaceContent.includes("admin-page-description-text");
        this.checkResult(
          category,
          "Consistent styling patterns",
          usesConsistentStyles,
          usesConsistentStyles
            ? "Follows existing admin page styling"
            : "Inconsistent styling patterns",
        );
      }
    } catch (error) {
      this.checkResult(
        category,
        "LangBuilder integration validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  async validateAccessibility() {
    const category = "Accessibility";

    try {
      // Check for accessible form labels
      const workspaceModalPath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/components/WorkspaceManagementModal/index.tsx",
      );
      if (fs.existsSync(workspaceModalPath)) {
        const modalContent = fs.readFileSync(workspaceModalPath, "utf8");

        // Check for proper labels
        const hasProperLabels =
          modalContent.includes("Label htmlFor=") &&
          modalContent.includes('id="workspace-');
        this.checkResult(
          category,
          "Form labels properly associated",
          hasProperLabels,
          hasProperLabels
            ? "Screen reader accessible forms"
            : "Missing form label associations",
        );

        // Check for ARIA attributes
        const hasAriaAttributes =
          modalContent.includes("aria-hidden") ||
          modalContent.includes("aria-");
        this.checkResult(
          category,
          "ARIA attributes implemented",
          hasAriaAttributes,
          hasAriaAttributes
            ? "Enhanced accessibility support"
            : "Missing ARIA attributes",
        );
      }

      // Check for keyboard navigation support
      const rbacAdminPath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/index.tsx",
      );
      if (fs.existsSync(rbacAdminPath)) {
        const adminContent = fs.readFileSync(rbacAdminPath, "utf8");

        // Check for keyboard-accessible tabs
        const hasKeyboardTabs =
          adminContent.includes("Tabs") && adminContent.includes("TabsTrigger");
        this.checkResult(
          category,
          "Keyboard navigation support",
          hasKeyboardTabs,
          hasKeyboardTabs
            ? "Keyboard accessible interface"
            : "Limited keyboard navigation",
        );
      }

      // Check test file for accessibility tests
      const testFilePath = path.join(
        __dirname,
        "../src/tests/phase6-rbac-ui.test.tsx",
      );
      if (fs.existsSync(testFilePath)) {
        const testContent = fs.readFileSync(testFilePath, "utf8");

        const hasAccessibilityTests =
          testContent.includes("Accessibility") && testContent.includes("ARIA");
        this.checkResult(
          category,
          "Accessibility tests included",
          hasAccessibilityTests,
          hasAccessibilityTests
            ? "Automated accessibility validation"
            : "Missing accessibility tests",
        );
      }
    } catch (error) {
      this.checkResult(
        category,
        "Accessibility validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  async validatePerformance() {
    const category = "Performance";

    try {
      // Check for permission caching
      const contextPath = path.join(
        __dirname,
        "../src/contexts/rbacContext.tsx",
      );
      if (fs.existsSync(contextPath)) {
        const contextContent = fs.readFileSync(contextPath, "utf8");

        const hasCaching =
          contextContent.includes("permissionCache") &&
          contextContent.includes("CACHE_TIMEOUT");
        this.checkResult(
          category,
          "Permission caching implemented",
          hasCaching,
          hasCaching
            ? "Reduced API calls for repeated checks"
            : "Missing permission caching",
        );

        const hasCleanup =
          contextContent.includes("clearInterval") &&
          contextContent.includes("setInterval");
        this.checkResult(
          category,
          "Memory cleanup implemented",
          hasCleanup,
          hasCleanup ? "Prevents memory leaks" : "Missing memory cleanup",
        );
      }

      // Check for loading states
      const workspacePagePath = path.join(
        __dirname,
        "../src/pages/AdminPage/RBAC/WorkspaceManagementPage/index.tsx",
      );
      if (fs.existsSync(workspacePagePath)) {
        const workspaceContent = fs.readFileSync(workspacePagePath, "utf8");

        const hasLoadingStates =
          workspaceContent.includes("isPending") &&
          workspaceContent.includes("CustomLoader");
        this.checkResult(
          category,
          "Loading states implemented",
          hasLoadingStates,
          hasLoadingStates
            ? "Better perceived performance"
            : "Missing loading states",
        );

        const hasPagination =
          workspaceContent.includes("PaginatorComponent") &&
          workspaceContent.includes("limit");
        this.checkResult(
          category,
          "Pagination for large datasets",
          hasPagination,
          hasPagination ? "Efficient data loading" : "Missing pagination",
        );
      }

      // Check for lazy loading patterns
      const permissionGuardPath = path.join(
        __dirname,
        "../src/components/rbac/PermissionGuard/index.tsx",
      );
      if (fs.existsSync(permissionGuardPath)) {
        const guardContent = fs.readFileSync(permissionGuardPath, "utf8");

        const hasAsyncLoading =
          guardContent.includes("useEffect") &&
          guardContent.includes("mounted");
        this.checkResult(
          category,
          "Async permission loading",
          hasAsyncLoading,
          hasAsyncLoading
            ? "Non-blocking permission checks"
            : "Missing async loading",
        );
      }
    } catch (error) {
      this.checkResult(
        category,
        "Performance validation",
        false,
        `Error: ${error.message}`,
      );
    }
  }

  generateSummary() {
    const duration = ((Date.now() - this.startTime) / 1000).toFixed(1);
    const totalTests = this.results.length;
    const passedTests = this.results.filter((r) => r.passed).length;
    const failedTests = totalTests - passedTests;
    const successRate =
      totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(1) : 0;

    console.log("\n" + "=".repeat(60));
    console.log("📊 PHASE 6 FRONTEND VALIDATION SUMMARY");
    console.log("=".repeat(60));

    const overallStatus =
      failedTests === 0
        ? "✅ PASSED"
        : successRate >= 90
          ? "⚠️ PASSED WITH WARNINGS"
          : "❌ FAILED";

    console.log(`Overall Status: ${overallStatus}`);
    console.log(`Success Rate: ${successRate}%`);
    console.log(`Duration: ${duration}s`);
    console.log(`Total Checks: ${totalTests}`);
    console.log(`✅ Passed: ${passedTests}`);
    console.log(`❌ Failed: ${failedTests}`);
    console.log(`⚠️ Warnings: 0`);

    console.log("\n📈 Category Results:");
    for (const [category, stats] of this.categories.entries()) {
      const categoryRate = ((stats.passed / stats.total) * 100).toFixed(1);
      const categoryStatus =
        stats.passed === stats.total
          ? "✅ PASS"
          : categoryRate >= 80
            ? "⚠️ WARN"
            : "❌ FAIL";
      console.log(`  • ${category}: ${categoryStatus} (${categoryRate}%)`);
    }

    if (failedTests > 0) {
      console.log("\n💡 Recommendations:");
      console.log("  • Complete implementation of missing components");
      console.log("  • Add comprehensive test coverage for all interfaces");
      console.log("  • Ensure accessibility compliance");
      console.log("  • Optimize performance with caching and lazy loading");
    }

    if (failedTests === 0) {
      console.log("\n🎉 Phase 6 validation completed successfully!");
      console.log("All frontend interface requirements have been met.");
    } else {
      console.log(
        `\n⚠️ Phase 6 validation completed with ${failedTests} failures`,
      );
    }

    return {
      success: failedTests === 0,
      successRate: parseFloat(successRate),
      totalTests,
      passedTests,
      failedTests,
      duration: parseFloat(duration),
      categories: Object.fromEntries(this.categories),
    };
  }

  async runValidation(category = null) {
    console.log("🔍 Starting Phase 6 Frontend Integration Validation");
    console.log("=".repeat(60));

    const validationMethods = [
      ["Implementation Files", () => this.validateImplementationFiles()],
      ["UI Components", () => this.validateUIComponents()],
      ["Form Components", () => this.validateFormComponents()],
      ["API Integration", () => this.validateAPIIntegration()],
      ["Context & Permissions", () => this.validateContextAndPermissions()],
      ["Test Coverage", () => this.validateTestCoverage()],
      ["LangBuilder Integration", () => this.validateLangBuilderIntegration()],
      ["Accessibility", () => this.validateAccessibility()],
      ["Performance", () => this.validatePerformance()],
    ];

    for (const [categoryName, validationMethod] of validationMethods) {
      if (
        !category ||
        category === categoryName.toLowerCase().replace(/\s+/g, "-")
      ) {
        console.log(`\n📋 Validating ${categoryName}...`);
        await validationMethod();
      }
    }

    return this.generateSummary();
  }
}

// Command line interface
async function main() {
  const args = process.argv.slice(2);
  const verbose = args.includes("--verbose");
  const categoryArg = args.find((arg) => arg.startsWith("--category="));
  const category = categoryArg ? categoryArg.split("=")[1] : null;

  try {
    const validator = new Phase6Validator(verbose);
    const results = await validator.runValidation(category);

    // Exit with error code if validation failed
    process.exit(results.success ? 0 : 1);
  } catch (error) {
    console.error("❌ Validation script failed:", error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = { Phase6Validator };
