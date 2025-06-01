// frontend/src/components/common/AdminRoute.jsx
// Create this component to protect admin routes

import { Alert, Container } from 'react-bootstrap';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const AdminRoute = ({ children }) => {
  const { user, isAuthenticated, loading } = useAuth();

  // Show loading while checking authentication
  if (loading) {
    return (
      <Container className="mt-4">
        <div className="text-center">
          <div className="spinner-border" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-2">Checking permissions...</p>
        </div>
      </Container>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Check if user has admin privileges (staff OR superuser)
  const hasAdminAccess = user?.is_staff || user?.is_superuser;

  if (!hasAdminAccess) {
    return (
      <Container className="mt-4">
        <Alert variant="danger">
          <Alert.Heading>Access Denied</Alert.Heading>
          <p>
            You don't have permission to access this admin area. 
            You need to be either a staff member or superuser.
          </p>
          <hr />
          <p className="mb-0">
            <strong>Your current status:</strong>
          </p>
          <ul className="mt-2">
            <li>Staff: {user?.is_staff ? '✅ Yes' : '❌ No'}</li>
            <li>Superuser: {user?.is_superuser ? '✅ Yes' : '❌ No'}</li>
          </ul>
        </Alert>
      </Container>
    );
  }

  // User has admin access, render the admin component
  return children;
};

export default AdminRoute;