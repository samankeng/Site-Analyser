// frontend/src/App.js - Fixed admin route implementation

import {
  Navigate,
  Route,
  BrowserRouter as Router,
  Routes,
} from "react-router-dom";
import Footer from "./components/common/Footer";
import Navbar from "./components/common/Navbar";
import { AuthProvider, useAuth } from "./contexts/AuthContext";

// Page components
import HomePage from "./pages/HomePage";
import NotFound from "./pages/NotFound";
import ForgotPassword from "./pages/auth/ForgotPassword";
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import ResetPassword from "./pages/auth/ResetPassword";
import DomainAuthorizations from "./pages/compliance/DomainAuthorizations";
import Dashboard from "./pages/dashboard/Dashboard";
import ReportListPage from "./pages/reports/ReportListPage";
import SecurityReport from "./pages/reports/SecurityReport";
import NewScan from "./pages/scans/NewScan";
import ScanStatus from "./pages/scans/ScanStatus";
import Settings from "./pages/settings/Settings";
// OAuth callback components
import GitHubCallback from "./components/auth/GitHubCallback";
import MicrosoftCallback from "./components/auth/MicrosoftCallback";

// Email verification components
import EmailVerification from "./components/auth/EmailVerification";
import EmailVerificationRequired from "./components/auth/EmailVerificationRequired";

import AdminAuthorizationPanel from "./components/admin/AdminAuthorizationPanel";
import AdminRoute from "./components/common/AdminRoute";
import CompliancePage from "./pages/compliance/Compliance";

import ApiReference from "./pages/docs/ApiReference";
import Documentation from "./pages/docs/Documentation";
import PrivacyPolicy from "./pages/docs/PrivacyPolicy";
import TermsOfService from "./pages/docs/TermsOfService";

import "./App.css";

// Protected auth routes component (redirects to dashboard if authenticated)
const AuthRoute = ({ children }) => {
  const { isAuthenticated } = useAuth();

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

// Enhanced PrivateRoute with email verification check
const EnhancedPrivateRoute = ({ children, requireAdmin = false }) => {
  const { user, loading, isAuthenticated } = useAuth();

  if (loading) {
    return (
      <div className="container py-5">
        <div className="row justify-content-center">
          <div className="col-auto">
            <div className="d-flex align-items-center">
              <div className="spinner-border text-primary me-3" role="status">
                <span className="visually-hidden">Loading...</span>
              </div>
              <span>Loading...</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Check if admin access is required
  if (requireAdmin && (!user || !user.is_staff)) {
    return (
      <div className="container py-5">
        <div className="row justify-content-center">
          <div className="col-md-6">
            <div className="card shadow">
              <div className="card-body text-center p-5">
                <div className="text-danger mb-3">
                  <i className="fas fa-exclamation-triangle fa-3x"></i>
                </div>
                <h4 className="text-danger">Access Denied</h4>
                <p className="text-muted mb-3">
                  You need administrator privileges to access this page.
                </p>
                <div className="mt-4">
                  <a href="/dashboard" className="btn btn-primary me-2">
                    <i className="fas fa-tachometer-alt me-1"></i>
                    Go to Dashboard
                  </a>
                  <a href="/" className="btn btn-outline-secondary">
                    <i className="fas fa-home me-1"></i>
                    Go Home
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Check if email verification is required
  if (user && !user.is_email_verified && !user.is_social_account) {
    return <EmailVerificationRequired email={user.email} />;
  }

  return children;
};

function AppContent() {
  return (
    <Router>
      <div className="d-flex flex-column min-vh-100">
        <Navbar />
        <main className="flex-grow-1">
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<HomePage />} />

            {/* Auth routes - redirect to dashboard if already authenticated */}
            <Route
              path="/login"
              element={
                <AuthRoute>
                  <Login />
                </AuthRoute>
              }
            />
            <Route
              path="/register"
              element={
                <AuthRoute>
                  <Register />
                </AuthRoute>
              }
            />
            <Route
              path="/compliance/authorizations"
              element={<DomainAuthorizations />}
            />
            <Route path="/docs" element={<Documentation />} />
            <Route path="/api-reference" element={<ApiReference />} />
            <Route path="/privacy-policy" element={<PrivacyPolicy />} />
            <Route path="/terms-of-service" element={<TermsOfService />} />
            <Route path="/auth/forgot-password" element={<ForgotPassword />} />
            <Route path="/auth/reset-password" element={<ResetPassword />} />
            {/* OAuth callback routes */}
            <Route path="/auth/github/callback" element={<GitHubCallback />} />
            <Route
              path="/auth/microsoft/callback"
              element={<MicrosoftCallback />}
            />

            {/* Email verification routes */}
            <Route path="/auth/verify-email" element={<EmailVerification />} />
            <Route
              path="/auth/email-verification-required"
              element={<EmailVerificationRequired />}
            />

            {/* Protected routes with enhanced email verification */}
            <Route
              path="/dashboard"
              element={
                <EnhancedPrivateRoute>
                  <Dashboard />
                </EnhancedPrivateRoute>
              }
            />
            <Route
              path="/compliance"
              element={
                <EnhancedPrivateRoute>
                  <CompliancePage />
                </EnhancedPrivateRoute>
              }
            />
            <Route
              path="/scans/new"
              element={
                <EnhancedPrivateRoute>
                  <NewScan />
                </EnhancedPrivateRoute>
              }
            />

            <Route
              path="/scans/:id"
              element={
                <EnhancedPrivateRoute>
                  <ScanStatus />
                </EnhancedPrivateRoute>
              }
            />

            <Route
              path="/reports"
              element={
                <EnhancedPrivateRoute>
                  <ReportListPage />
                </EnhancedPrivateRoute>
              }
            />

            <Route
              path="/reports/:id"
              element={
                <EnhancedPrivateRoute>
                  <SecurityReport />
                </EnhancedPrivateRoute>
              }
            />

            <Route
              path="/settings"
              element={
                <EnhancedPrivateRoute>
                  <Settings />
                </EnhancedPrivateRoute>
              }
            />
            <Route
              path="/admin/authorizations"
              element={
                <AdminRoute>
                  <AdminAuthorizationPanel />
                </AdminRoute>
              }
            />

            {/* FIXED: Admin route with proper requireAdmin prop */}
            <Route
              path="/admin/authorizations"
              element={
                <EnhancedPrivateRoute requireAdmin={true}>
                  <AdminAuthorizationPanel />
                </EnhancedPrivateRoute>
              }
            />

            {/* Error routes */}
            <Route path="/404" element={<NotFound />} />
            <Route
              path="/auth/error"
              element={
                <div className="container py-5">
                  <div className="row justify-content-center">
                    <div className="col-md-6">
                      <div className="card shadow">
                        <div className="card-body text-center p-5">
                          <div className="text-danger mb-3">
                            <i className="fas fa-exclamation-triangle fa-3x"></i>
                          </div>
                          <h4 className="text-danger">Authentication Error</h4>
                          <p className="text-muted mb-3">
                            There was an error during the authentication
                            process. This could be due to:
                          </p>
                          <ul className="text-start text-muted small">
                            <li>The authentication was cancelled</li>
                            <li>Required permissions were not granted</li>
                            <li>The email address is not available</li>
                            <li>Network connection issues</li>
                            <li>OAuth service temporarily unavailable</li>
                          </ul>
                          <div className="mt-4">
                            <a href="/login" className="btn btn-primary me-2">
                              <i className="fas fa-redo me-1"></i>
                              Try Again
                            </a>
                            <a href="/" className="btn btn-outline-secondary">
                              <i className="fas fa-home me-1"></i>
                              Go Home
                            </a>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              }
            />

            {/* Email verification error route */}
            <Route
              path="/auth/verification-error"
              element={
                <div className="container py-5">
                  <div className="row justify-content-center">
                    <div className="col-md-6">
                      <div className="card shadow">
                        <div className="card-body text-center p-5">
                          <div className="text-warning mb-3">
                            <i className="fas fa-envelope-open-text fa-3x"></i>
                          </div>
                          <h4 className="text-warning">
                            Email Verification Issue
                          </h4>
                          <p className="text-muted mb-3">
                            There was an issue with email verification. Common
                            causes:
                          </p>
                          <ul className="text-start text-muted small">
                            <div>Verification link has expired (24 hours)</div>
                            <li>Link has already been used</li>
                            <li>Invalid verification token</li>
                            <li>Email address already verified</li>
                          </ul>
                          <div className="mt-4">
                            <a
                              href="/auth/email-verification-required"
                              className="btn btn-primary me-2"
                            >
                              <i className="fas fa-paper-plane me-1"></i>
                              Request New Link
                            </a>
                            <a
                              href="/login"
                              className="btn btn-outline-secondary"
                            >
                              <i className="fas fa-sign-in-alt me-1"></i>
                              Go to Login
                            </a>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              }
            />

            {/* Catch-all redirect */}
            <Route path="*" element={<Navigate to="/404" replace />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </Router>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
