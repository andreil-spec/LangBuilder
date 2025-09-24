/**
 * Centralized error handling for RBAC API operations
 * Provides consistent error responses and logging across all RBAC endpoints
 */

export interface RBACError extends Error {
  status?: number;
  code?: string;
  details?: any;
}

export interface RBACErrorResponse {
  success: false;
  error: {
    message: string;
    status: number;
    code: string;
    details?: any;
  };
}

/**
 * Standardized error handler for RBAC API calls
 * @param error - The error object from the API call
 * @param context - Context information for logging
 * @returns Formatted error response
 */
export function handleRBACError(error: any, context: string): never {
  // Log specific error types for debugging
  if (error.response?.status === 401) {
    console.error(
      `RBAC ${context} failed: Unauthorized - user may need to re-authenticate`,
    );
    throw new Error("Authentication required");
  } else if (error.response?.status === 403) {
    console.error(
      `RBAC ${context} failed: Forbidden - insufficient permissions`,
    );
    throw new Error("Access denied - insufficient permissions");
  } else if (error.response?.status === 404) {
    console.error(`RBAC ${context} failed: Resource not found`);
    throw new Error("Resource not found");
  } else if (error.response?.status === 422) {
    console.error(`🚨 RBAC ${context} failed: Invalid request data (422)`, {
      url: error.config?.url,
      method: error.config?.method,
      data: error.response?.data,
      requestHeaders: error.config?.headers,
      params: error.config?.params,
      fullError: error,
    });
    throw new Error("Invalid request data");
  } else if (error.response?.status >= 500) {
    console.error(
      `RBAC ${context} failed: Server error`,
      error.response?.status,
      error.response?.data,
    );
    throw new Error("Server error - please try again later");
  } else {
    console.error(`RBAC ${context} failed:`, error);
    throw error;
  }
}

/**
 * Creates a default empty response for RBAC list operations
 * @param page - Current page number
 * @param page_size - Page size
 * @returns Empty paginated response
 */
export function createEmptyListResponse<T>(
  page: number = 1,
  page_size: number = 50,
): {
  items: T[];
  total_count: number;
  page: number;
  page_size: number;
  has_next: boolean;
  has_previous: boolean;
} {
  return {
    items: [],
    total_count: 0,
    page,
    page_size,
    has_next: false,
    has_previous: false,
  };
}

/**
 * Validates API response structure and provides fallback
 * @param response - API response
 * @param expectedArrayField - Expected field name containing the array
 * @param page - Current page number
 * @param page_size - Page size
 * @returns Normalized response structure
 */
export function normalizeListResponse<T>(
  response: any,
  expectedArrayField: string,
  page: number,
  page_size: number,
): {
  items: T[];
  total_count: number;
  page: number;
  page_size: number;
  has_next: boolean;
  has_previous: boolean;
} {
  // Handle new paginated response format
  if (
    response[expectedArrayField] &&
    Array.isArray(response[expectedArrayField])
  ) {
    return {
      items: response[expectedArrayField],
      total_count: response.total_count || response[expectedArrayField].length,
      page: response.page || page,
      page_size: response.page_size || page_size,
      has_next: response.has_next || false,
      has_previous: response.has_previous || false,
    };
  }

  // Fallback for legacy array response
  const items = Array.isArray(response) ? response : [];
  return {
    items,
    total_count: items.length,
    page,
    page_size,
    has_next: false,
    has_previous: false,
  };
}
