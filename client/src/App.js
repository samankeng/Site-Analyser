// frontend/src/App.js - Updated with OAuth support

import {
  Navigate,
  Route,
  BrowserRouter as Router,
  Routes,
} from "react-router-dom";
import Footer from "./components/common/Footer";
import Navbar from "./components/common/Navbar";
import PrivateRoute from "./components/common/PrivateRoute";
import { AuthProvider, useAuth } from "./contexts/AuthContext";

// Page components
import HomePage from "./pages/HomePage";
import NotFound from "./pages/NotFound";
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import Dashboard from "./pages/dashboard/Dashboard";
import ReportListPage from "./pages/reports/ReportListPage";
import SecurityReport from "./pages/reports/SecurityReport";
import NewScan from "./pages/scans/NewScan";
import ScanStatus from "./pages/scans/ScanStatus";
import Settings from "./pages/settings/Settings";

// OAuth callback components
import GitHubCallback from "./components/auth/GitHubCallback";

import "./App.css";

// Protected auth routes component (redirects to dashboard if authenticated)
const AuthRoute = ({ children }) => {
  const { isAuthenticated } = useAuth();

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
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

            {/* OAuth callback routes */}
            <Route path="/auth/github/callback" element={<GitHubCallback />} />

            {/* Protected routes */}
            <Route
              path="/dashboard"
              element={
                <PrivateRoute>
                  <Dashboard />
                </PrivateRoute>
              }
            />

            <Route
              path="/scans/new"
              element={
                <PrivateRoute>
                  <NewScan />
                </PrivateRoute>
              }
            />

            <Route
              path="/scans/:id"
              element={
                <PrivateRoute>
                  <ScanStatus />
                </PrivateRoute>
              }
            />

            <Route
              path="/reports"
              element={
                <PrivateRoute>
                  <ReportListPage />
                </PrivateRoute>
              }
            />

            <Route
              path="/reports/:id"
              element={
                <PrivateRoute>
                  <SecurityReport />
                </PrivateRoute>
              }
            />

            <Route
              path="/settings"
              element={
                <PrivateRoute>
                  <Settings />
                </PrivateRoute>
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
                          </ul>
                          <div className="mt-4">
                            <a href="/login" className="btn btn-primary me-2">
                              Try Again
                            </a>
                            <a href="/" className="btn btn-outline-secondary">
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
