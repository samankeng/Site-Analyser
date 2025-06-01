// frontend/src/components/common/Navbar.js - COMPLETE VERSION

import { useEffect, useState } from "react";
import {
  Badge,
  Navbar as BootstrapNavbar,
  Container,
  Nav,
  NavDropdown,
} from "react-bootstrap";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { getAuthorizations } from "../../services/api";

const Navbar = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();
  const [pendingCount, setPendingCount] = useState(0);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  // Fetch pending authorization count for admin users (staff OR superuser)
  useEffect(() => {
    if (isAuthenticated && (user?.is_staff || user?.is_superuser)) {
      const fetchPendingCount = async () => {
        try {
          const response = await getAuthorizations();
          const authorizations = response.results || response;
          const pending = Array.isArray(authorizations)
            ? authorizations.filter((auth) => !auth.is_approved).length
            : 0;
          setPendingCount(pending);
          console.log("Admin user detected, pending authorizations:", pending); // Debug log
        } catch (error) {
          console.error("Failed to fetch pending authorization count:", error);
          setPendingCount(0);
        }
      };

      fetchPendingCount();
      // Refresh count every 30 seconds
      const interval = setInterval(fetchPendingCount, 30000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated, user?.is_staff, user?.is_superuser]);

  // Debug logging
  useEffect(() => {
    console.log("Navbar - User object:", user);
    console.log("Navbar - Is authenticated:", isAuthenticated);
    console.log("Navbar - Is staff:", user?.is_staff);
    console.log("Navbar - Is superuser:", user?.is_superuser);
    console.log(
      "Navbar - Should show admin:",
      user?.is_staff || user?.is_superuser
    );
  }, [user, isAuthenticated]);

  return (
    <BootstrapNavbar bg="primary" variant="dark" expand="lg">
      <Container>
        <BootstrapNavbar.Brand as={Link} to="/">
          Site-Analyser
        </BootstrapNavbar.Brand>
        <BootstrapNavbar.Toggle aria-controls="navbarNav" />
        <BootstrapNavbar.Collapse id="navbarNav">
          <Nav className="me-auto">
            {isAuthenticated ? (
              <>
                <Nav.Link as={Link} to="/dashboard">
                  Dashboard
                </Nav.Link>
                <Nav.Link as={Link} to="/scans/new">
                  New Scan
                </Nav.Link>
                <Nav.Link as={Link} to="/reports">
                  Reports
                </Nav.Link>
                <Nav.Link as={Link} to="/compliance/authorizations">
                  My Authorizations
                </Nav.Link>

                {/* Admin Dropdown - Show for staff users OR superusers */}
                {(user?.is_staff || user?.is_superuser) && (
                  <NavDropdown
                    title={
                      <>
                        <i className="bi bi-gear me-1"></i>
                        Admin
                        {pendingCount > 0 && (
                          <Badge bg="warning" className="ms-2">
                            {pendingCount}
                          </Badge>
                        )}
                      </>
                    }
                    id="adminDropdown"
                  >
                    <NavDropdown.Item as={Link} to="/admin/authorizations">
                      <i className="bi bi-shield-check me-2"></i>
                      Domain Authorizations
                      {pendingCount > 0 && (
                        <Badge bg="warning" className="ms-2">
                          {pendingCount}
                        </Badge>
                      )}
                    </NavDropdown.Item>
                    <NavDropdown.Divider />
                    <NavDropdown.Item
                      href="/admin/"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <i className="bi bi-tools me-2"></i>
                      Django Admin
                      <i className="bi bi-box-arrow-up-right ms-1 small"></i>
                    </NavDropdown.Item>
                  </NavDropdown>
                )}

                {/* Debug info - Remove this after testing */}
                {(user?.is_staff || user?.is_superuser) && (
                  <Nav.Link style={{ color: "yellow", fontSize: "12px" }}>
                    DEBUG: Admin={user?.is_staff ? "Staff" : "Super"}
                  </Nav.Link>
                )}
              </>
            ) : (
              <Nav.Link as={Link} to="/">
                Home
              </Nav.Link>
            )}
          </Nav>

          <Nav>
            {isAuthenticated ? (
              <NavDropdown
                title={user?.email || "Account"}
                id="navbarDropdown"
                align="end"
              >
                <NavDropdown.Item as={Link} to="/settings">
                  <i className="bi bi-gear me-2"></i>
                  Settings
                </NavDropdown.Item>
                <NavDropdown.Divider />
                <NavDropdown.Item onClick={handleLogout}>
                  <i className="bi bi-box-arrow-right me-2"></i>
                  Logout
                </NavDropdown.Item>
              </NavDropdown>
            ) : (
              <>
                <Nav.Link as={Link} to="/login">
                  Login
                </Nav.Link>
                <Nav.Link as={Link} to="/register">
                  Register
                </Nav.Link>
              </>
            )}
          </Nav>
        </BootstrapNavbar.Collapse>
      </Container>
    </BootstrapNavbar>
  );
};

export default Navbar;
