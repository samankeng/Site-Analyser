// frontend/src/components/common/Navbar.js

import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { Navbar as BootstrapNavbar, Nav, Container, NavDropdown } from 'react-bootstrap';

const Navbar = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();
  
  const handleLogout = () => {
    logout();
    navigate('/login');
  };
  
  return (
    <BootstrapNavbar bg="primary" variant="dark" expand="lg">
      <Container>
        <BootstrapNavbar.Brand as={Link} to="/">Site-Analyser</BootstrapNavbar.Brand>
        <BootstrapNavbar.Toggle aria-controls="navbarNav" />
        <BootstrapNavbar.Collapse id="navbarNav">
          <Nav className="me-auto">
            {isAuthenticated ? (
              <>
                <Nav.Link as={Link} to="/dashboard">Dashboard</Nav.Link>
                <Nav.Link as={Link} to="/scans/new">New Scan</Nav.Link>
                <Nav.Link as={Link} to="/reports">Reports</Nav.Link>
              </>
            ) : (
              <Nav.Link as={Link} to="/">Home</Nav.Link>
            )}
          </Nav>
          
          <Nav>
            {isAuthenticated ? (
              <NavDropdown title={user?.email || 'Account'} id="navbarDropdown" align="end">
                <NavDropdown.Item as={Link} to="/settings">Settings</NavDropdown.Item>
                <NavDropdown.Divider />
                <NavDropdown.Item onClick={handleLogout}>Logout</NavDropdown.Item>
              </NavDropdown>
            ) : (
              <>
                <Nav.Link as={Link} to="/login">Login</Nav.Link>
                <Nav.Link as={Link} to="/register">Register</Nav.Link>
              </>
            )}
          </Nav>
        </BootstrapNavbar.Collapse>
      </Container>
    </BootstrapNavbar>
  );
};

export default Navbar;