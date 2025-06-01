// frontend/src/services/api.js - Updated for consolidated compliance structure

import axios from "axios";
import { clearTokens, getToken } from "../utils/storage";

// Create axios instance
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || "http://localhost:8000/api/",
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor for adding the auth token
api.interceptors.request.use(
  (config) => {
    const token = getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    console.log("API Request:", {
      url: config.baseURL + config.url,
      method: config.method,
      headers: config.headers,
      token: token ? "Present" : "Missing",
    });
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for handling errors
api.interceptors.response.use(
  (response) => {
    console.log("API Response Success:", {
      url: response.config.url,
      status: response.status,
      data: response.data,
    });
    return response;
  },
  (error) => {
    console.error("API Response Error:", {
      url: error.config?.url,
      status: error.response?.status,
      statusText: error.response?.statusText,
      data: error.response?.data,
      message: error.message,
    });

    // Handle authentication errors
    if (error.response && error.response.status === 401) {
      // Clear tokens from storage and redirect to login
      clearTokens();
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

// Helper function to handle API errors consistently
const handleApiError = (error, defaultMessage) => {
  console.error("Handling API Error:", error);

  if (error.response?.data?.error) {
    throw new Error(error.response.data.error);
  }
  if (error.response?.data?.message) {
    throw new Error(error.response.data.message);
  }
  if (error.response?.data?.detail) {
    throw new Error(error.response.data.detail);
  }
  if (error.message) {
    throw new Error(`${defaultMessage}: ${error.message}`);
  }
  throw new Error(defaultMessage);
};

// ========== COMPLIANCE API FUNCTIONS ==========

export const checkComplianceStatus = async () => {
  try {
    console.log("Checking compliance status...");
    const response = await api.get("compliance/status/");
    console.log("Compliance status response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Compliance status check failed:", error);
    handleApiError(error, "Failed to check compliance status");
  }
};

export const acceptAgreement = async (
  agreementType,
  agreementVersion = "1.0"
) => {
  try {
    console.log("Accepting agreement:", agreementType);
    const response = await api.post("compliance/accept/", {
      agreement_type: agreementType,
      agreement_version: agreementVersion,
    });
    console.log("Agreement acceptance response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Agreement acceptance failed:", error);
    handleApiError(error, `Failed to accept ${agreementType}`);
  }
};

export const getComplianceStatus = async () => {
  try {
    console.log("Getting full compliance status...");
    const response = await api.get("compliance/status/");
    console.log("Full compliance status response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Full compliance status failed:", error);
    handleApiError(error, "Failed to get compliance status");
  }
};

export const checkUrlAuthorization = async (url) => {
  try {
    console.log("Checking URL authorization:", url);
    const response = await api.post("compliance/check-url/", { url });
    console.log("URL authorization response:", response.data);
    return response.data;
  } catch (error) {
    console.error("URL authorization check failed:", error);
    handleApiError(error, "Failed to check URL authorization");
  }
};

export const getLegalNotices = async () => {
  try {
    const response = await api.get("compliance/legal-notices/");
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to fetch legal notices");
  }
};

export const getScanModes = async () => {
  try {
    const response = await api.get("compliance/scan-modes/");
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to fetch scan modes");
  }
};

// ========== DOMAIN AUTHORIZATION API FUNCTIONS ==========

export const requestDomainAuthorization = async (authorizationData) => {
  try {
    console.log("Requesting domain authorization:", authorizationData);

    const response = await api.post("compliance/request-domain/", {
      domain: authorizationData.domain,
      verification_method: authorizationData.verification_method || "dns_txt",
      notes: authorizationData.notes || authorizationData.justification,
    });

    console.log("Domain authorization response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Domain authorization request failed:", error);
    handleApiError(error, "Failed to request domain authorization");
  }
};

export const verifyDomainAuthorization = async (domainId) => {
  try {
    console.log("Verifying domain authorization:", domainId);
    const response = await api.post("compliance/verify-domain/", {
      domain_id: domainId,
    });
    console.log("Domain verification response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Domain verification failed:", error);
    handleApiError(error, "Failed to verify domain authorization");
  }
};

export const getAuthorizations = async () => {
  try {
    const response = await api.get("compliance/domain-authorizations/");
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to fetch authorizations");
  }
};

export const getAdminAuthorizations = async () => {
  try {
    const response = await api.get("compliance/admin/domain-authorizations/");
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to fetch admin authorizations");
  }
};

export const revokeAuthorization = async (authorizationId) => {
  try {
    const response = await api.post(
      `compliance/domain-authorizations/${authorizationId}/revoke/`
    );
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to revoke authorization");
  }
};

export const approveAuthorization = async (authorizationId) => {
  try {
    const response = await api.post(
      `compliance/domain-authorizations/${authorizationId}/approve/`
    );
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to approve authorization");
  }
};

export const updateAuthorization = async (authorizationId, updateData) => {
  try {
    const response = await api.patch(
      `compliance/domain-authorizations/${authorizationId}/`,
      updateData
    );
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to update authorization");
  }
};

export const getAuthorizationDetails = async (authorizationId) => {
  try {
    const response = await api.get(
      `compliance/domain-authorizations/${authorizationId}/`
    );
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to fetch authorization details");
  }
};

export const deleteAuthorization = async (authorizationId) => {
  try {
    const response = await api.delete(
      `compliance/domain-authorizations/${authorizationId}/`
    );
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to delete authorization");
  }
};

// ========== SCAN API FUNCTIONS ==========

export const createScan = async (scanData) => {
  try {
    console.log("Creating scan:", scanData);
    const response = await api.post("scanner/scans/", scanData);
    console.log("Scan creation response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Scan creation failed:", error);
    handleApiError(error, "Failed to create scan");
  }
};

export const getScans = async () => {
  try {
    const response = await api.get("scanner/scans/");
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to fetch scans");
  }
};

export const getScan = async (scanId) => {
  try {
    const response = await api.get(`scanner/scans/${scanId}/`);
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to fetch scan details");
  }
};

export const cancelScan = async (scanId) => {
  try {
    const response = await api.post(`scanner/scans/${scanId}/cancel/`);
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to cancel scan");
  }
};

export const deleteScanHistory = async () => {
  try {
    const response = await api.delete("scanner/scans/history/");
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to delete scan history");
  }
};

export const generatePDFReport = async (scanId) => {
  try {
    const response = await api.get(`scanner/scans/${scanId}/pdf/`, {
      responseType: "blob",
    });
    return response.data;
  } catch (error) {
    handleApiError(error, "Failed to generate PDF report");
  }
};

// ========== UTILITY FUNCTIONS ==========

export const getAuthorizationStats = async () => {
  try {
    const auths = await getAuthorizations();
    const stats = {
      total: auths.length || auths.count || 0,
      pending: 0,
      verified: 0,
      expired: 0,
    };

    if (auths.results || Array.isArray(auths)) {
      const authList = auths.results || auths;
      const now = new Date();

      authList.forEach((auth) => {
        if (auth.status === "pending") stats.pending++;
        else if (auth.status === "verified" && auth.is_active) stats.verified++;
        else if (
          !auth.is_active ||
          (auth.expires_at && new Date(auth.expires_at) < now)
        )
          stats.expired++;
      });
    }

    return stats;
  } catch (error) {
    console.error("API Error - Get Authorization Stats:", error);
    handleApiError(error, "Failed to get authorization statistics");
  }
};

// ========== LEGACY COMPATIBILITY FUNCTIONS ==========

// Maintain backward compatibility with old function names
export const createAuthorization = async (authData) => {
  console.warn(
    "createAuthorization is deprecated. Use requestDomainAuthorization instead."
  );
  return requestDomainAuthorization(authData);
};

export default api;
