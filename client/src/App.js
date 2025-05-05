// frontend/src/App.js

import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import PrivateRoute from './components/common/PrivateRoute';
import Navbar from './components/common/Navbar';
import Footer from './components/common/Footer';
import HomePage from './pages/HomePage';
import Dashboard from './pages/dashboard/Dashboard';
import Login from './pages/auth/Login';
import Register from './pages/auth/Register';
import NewScan from './pages/scans/NewScan';
import ScanStatus from './pages/scans/ScanStatus';
import SecurityReport from './pages/reports/SecurityReport';
import ReportListPage from './pages/reports/ReportListPage';
import Settings from './pages/settings/Settings';
import NotFound from './pages/NotFound';
import './App.css';


function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="d-flex flex-column min-vh-100">
          <Navbar />
          <main className="flex-grow-1">
            <Routes>
              {/* Public routes */}
              <Route path="/" element={<HomePage />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              
              {/* Protected routes */}
              <Route path="/dashboard" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
              <Route path="/scans/new" element={<PrivateRoute><NewScan /></PrivateRoute>} />
              <Route path="/scans/:id" element={<PrivateRoute><ScanStatus /></PrivateRoute>} />
              <Route path="/reports" element={<PrivateRoute><ReportListPage /></PrivateRoute>} />
              <Route path="/reports/:id" element={<PrivateRoute><SecurityReport /></PrivateRoute>} />
              <Route path="/settings" element={<PrivateRoute><Settings /></PrivateRoute>} />
              
              {/* 404 and redirect */}
              <Route path="/404" element={<NotFound />} />
              <Route path="*" element={<Navigate to="/404" replace />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;