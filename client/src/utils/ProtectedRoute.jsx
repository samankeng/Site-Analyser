import { useEffect, useState } from 'react';
import {
    approveAuthorization,
    getAuthorizations,
    revokeAuthorization
} from '../../services/api';

const AdminAuthorizationPanel = () => {
  const [authorizations, setAuthorizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedAuth, setSelectedAuth] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [filters, setFilters] = useState({
    status: 'all',
    authType: 'all',
    complianceMode: 'all',
    search: ''
  });
  const [stats, setStats] = useState({
    total: 0,
    pending: 0,
    approved: 0,
    expired: 0
  });

  useEffect(() => {
    fetchAuthorizations();
  }, []);

  useEffect(() => {
    calculateStats();
  }, [authorizations]);

  const fetchAuthorizations = async () => {
    try {
      setLoading(true);
      setError('');
      
      // Since you're an admin, this should return all authorizations
      const response = await getAuthorizations();
      
      if (response.results) {
        setAuthorizations(response.results);
      } else if (Array.isArray(response)) {
        setAuthorizations(response);
      } else {
        setAuthorizations([]);
      }
    } catch (err) {
      console.error('Failed to fetch authorizations:', err);
      setError('Failed to load authorization requests: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const calculateStats = () => {
    const now = new Date();
    const stats = {
      total: authorizations.length,
      pending: authorizations.filter(auth => !auth.is_approved).length,
      approved: authorizations.filter(auth => auth.is_approved && auth.is_active).length,
      expired: authorizations.filter(auth => 
        new Date(auth.valid_until) < now || !auth.is_active
      ).length
    };
    setStats(stats);
  };

  const handleApprove = async (authId) => {
    if (!window.confirm('Are you sure you want to approve this authorization request?')) {
      return;
    }

    try {
      setProcessing(true);
      await approveAuthorization(authId);
      await fetchAuthorizations();
      alert('Authorization approved successfully!');
    } catch (err) {
      console.error('Approval failed:', err);
      alert('Failed to approve authorization: ' + err.message);
    } finally {
      setProcessing(false);
    }
  };

  const handleRevoke = async (authId) => {
    if (!window.confirm('Are you sure you want to revoke this authorization? This cannot be undone.')) {
      return;
    }

    try {
      setProcessing(true);
      await revokeAuthorization(authId);
      await fetchAuthorizations();
      alert('Authorization revoked successfully!');
    } catch (err) {
      console.error('Revocation failed:', err);
      alert('Failed to revoke authorization: ' + err.message);
    } finally {
      setProcessing(false);
    }
  };

  const handleViewDetails = (auth) => {
    setSelectedAuth(auth);
    setShowModal(true);
  };

  const getStatusBadge = (auth) => {
    const now = new Date();
    const validUntil = new Date(auth.valid_until);
    
    if (!auth.is_approved) {
      return <span className="badge bg-warning">Pending Approval</span>;
    }
    if (!auth.is_active) {
      return <span className="badge bg-secondary">Revoked</span>;
    }
    if (validUntil < now) {
      return <span className="badge bg-danger">Expired</span>;
    }
    return <span className="badge bg-success">Active</span>;
  };

  const getUrgencyBadge = (auth) => {
    // Check if authorization was created recently (within 24 hours)
    const createdAt = new Date(auth.created_at);
    const now = new Date();
    const hoursDiff = (now - createdAt) / (1000 * 60 * 60);
    
    if (hoursDiff < 24 && !auth.is_approved) {
      return <span className="badge bg-info ms-2">New</span>;
    }
    
    // Check if approaching expiration (within 30 days)
    const validUntil = new Date(auth.valid_until);
    const daysDiff = (validUntil - now) / (1000 * 60 * 60 * 24);
    
    if (daysDiff <= 30 && daysDiff > 0 && auth.is_approved) {
      return <span className="badge bg-warning ms-2">Expiring Soon</span>;
    }
    
    return null;
  };

  const filteredAuthorizations = authorizations.filter(auth => {
    // Status filter
    if (filters.status !== 'all') {
      const now = new Date();
      const validUntil = new Date(auth.valid_until);
      
      switch (filters.status) {
        case 'pending':
          if (auth.is_approved) return false;
          break;
        case 'approved':
          if (!auth.is_approved || !auth.is_active) return false;
          break;
        case 'expired':
          if (validUntil >= now && auth.is_active) return false;
          break;
        case 'revoked':
          if (auth.is_active) return false;
          break;
      }
    }

    // Authorization type filter
    if (filters.authType !== 'all' && auth.authorization_type !== filters.authType) {
      return false;
    }

    // Compliance mode filter
    if (filters.complianceMode !== 'all' && auth.compliance_mode !== filters.complianceMode) {
      return false;
    }

    // Search filter
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      return (
        auth.domain.toLowerCase().includes(searchLower) ||
        auth.user?.username?.toLowerCase().includes(searchLower) ||
        auth.contact_person?.toLowerCase().includes(searchLower) ||
        auth.authorization_notes?.toLowerCase().includes(searchLower)
      );
    }

    return true;
  });

  if (loading) {
    return (
      <div className="container mt-4">
        <div className="text-center">
          <div className="spinner-border" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-2">Loading authorization requests...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid mt-4">
      <div className="row">
        <div className="col-12">
          {/* Header */}
          <div className="d-flex justify-content-between align-items-center mb-4">
            <div>
              <h2 className="mb-1">
                <i className="bi bi-shield-check me-2"></i>
                Domain Authorization Management
              </h2>
              <p className="text-muted mb-0">Review and manage domain authorization requests</p>
            </div>
            <button 
              className="btn btn-outline-secondary"
              onClick={fetchAuthorizations}
              disabled={loading}
            >
              <i className="bi bi-arrow-clockwise me-1"></i>
              Refresh
            </button>
          </div>

          {/* Stats Cards */}
          <div className="row mb-4">
            <div className="col-lg-3 col-md-6 mb-3">
              <div className="card border-primary">
                <div className="card-body text-center">
                  <h3 className="text-primary mb-1">{stats.total}</h3>
                  <p className="card-text mb-0">Total Requests</p>
                </div>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-3">
              <div className="card border-warning">
                <div className="card-body text-center">
                  <h3 className="text-warning mb-1">{stats.pending}</h3>
                  <p className="card-text mb-0">Pending Approval</p>
                </div>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-3">
              <div className="card border-success">
                <div className="card-body text-center">
                  <h3 className="text-success mb-1">{stats.approved}</h3>
                  <p className="card-text mb-0">Active</p>
                </div>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-3">
              <div className="card border-danger">
                <div className="card-body text-center">
                  <h3 className="text-danger mb-1">{stats.expired}</h3>
                  <p className="card-text mb-0">Expired/Revoked</p>
                </div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="card mb-4">
            <div className="card-body">
              <div className="row g-3">
                <div className="col-md-3">
                  <label className="form-label">Status</label>
                  <select 
                    className="form-select"
                    value={filters.status}
                    onChange={(e) => setFilters({...filters, status: e.target.value})}
                  >
                    <option value="all">All Status</option>
                    <option value="pending">Pending</option>
                    <option value="approved">Approved</option>
                    <option value="expired">Expired</option>
                    <option value="revoked">Revoked</option>
                  </select>
                </div>
                <div className="col-md-3">
                  <label className="form-label">Authorization Type</label>
                  <select 
                    className="form-select"
                    value={filters.authType}
                    onChange={(e) => setFilters({...filters, authType: e.target.value})}
                  >
                    <option value="all">All Types</option>
                    <option value="self_owned">Website Owner</option>
                    <option value="written_permission">Written Permission</option>
                    <option value="bug_bounty">Bug Bounty</option>
                    <option value="penetration_test">Penetration Test</option>
                  </select>
                </div>
                <div className="col-md-3">
                  <label className="form-label">Compliance Mode</label>
                  <select 
                    className="form-select"
                    value={filters.complianceMode}
                    onChange={(e) => setFilters({...filters, complianceMode: e.target.value})}
                  >
                    <option value="all">All Modes</option>
                    <option value="strict">Strict</option>
                    <option value="moderate">Moderate</option>
                    <option value="permissive">Permissive</option>
                  </select>
                </div>
                <div className="col-md-3">
                  <label className="form-label">Search</label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Domain, user, notes..."
                    value={filters.search}
                    onChange={(e) => setFilters({...filters, search: e.target.value})}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Error Display */}
          {error && (
            <div className="alert alert-danger" role="alert">
              <i className="bi bi-exclamation-triangle me-2"></i>
              {error}
            </div>
          )}

          {/* Authorization Requests Table */}
          <div className="card">
            <div className="card-header">
              <h5 className="mb-0">
                Authorization Requests ({filteredAuthorizations.length})
              </h5>
            </div>
            <div className="card-body p-0">
              {filteredAuthorizations.length === 0 ? (
                <div className="text-center py-5">
                  <i className="bi bi-inbox display-4 text-muted"></i>
                  <p className="text-muted mt-3">No authorization requests found</p>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-hover mb-0">
                    <thead className="table-light">
                      <tr>
                        <th>Domain</th>
                        <th>User</th>
                        <th>Type</th>
                        <th>Compliance</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Valid Until</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAuthorizations.map((auth) => (
                        <tr key={auth.id}>
                          <td>
                            <div className="fw-bold">{auth.domain}</div>
                            {auth.contact_person && (
                              <small className="text-muted">
                                Contact: {auth.contact_person}
                              </small>
                            )}
                          </td>
                          <td>
                            <div>{auth.user?.username || 'Unknown'}</div>
                            {auth.contact_email && (
                              <small className="text-muted">{auth.contact_email}</small>
                            )}
                          </td>
                          <td>
                            <span className="badge bg-secondary">
                              {auth.authorization_type?.replace('_', ' ').toUpperCase()}
                            </span>
                          </td>
                          <td>
                            <span className={`badge ${
                              auth.compliance_mode === 'strict' ? 'bg-info' :
                              auth.compliance_mode === 'moderate' ? 'bg-warning' : 'bg-danger'
                            }`}>
                              {auth.compliance_mode?.charAt(0).toUpperCase() + auth.compliance_mode?.slice(1)}
                            </span>
                          </td>
                          <td>
                            {getStatusBadge(auth)}
                            {getUrgencyBadge(auth)}
                          </td>
                          <td>
                            <small className="text-muted">
                              {new Date(auth.created_at).toLocaleDateString()}
                            </small>
                          </td>
                          <td>
                            <small className="text-muted">
                              {auth.valid_until ? 
                                new Date(auth.valid_until).toLocaleDateString() : 
                                'N/A'
                              }
                            </small>
                          </td>
                          <td>
                            <div className="btn-group btn-group-sm">
                              <button
                                className="btn btn-outline-primary"
                                onClick={() => handleViewDetails(auth)}
                              >
                                <i className="bi bi-eye"></i>
                              </button>
                              {!auth.is_approved && (
                                <button
                                  className="btn btn-outline-success"
                                  onClick={() => handleApprove(auth.id)}
                                  disabled={processing}
                                >
                                  <i className="bi bi-check-lg"></i>
                                </button>
                              )}
                              {auth.is_approved && auth.is_active && (
                                <button
                                  className="btn btn-outline-danger"
                                  onClick={() => handleRevoke(auth.id)}
                                  disabled={processing}
                                >
                                  <i className="bi bi-x-lg"></i>
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Details Modal */}
      {showModal && selectedAuth && (
        <div className="modal show" style={{display: 'block'}} tabIndex="-1">
          <div className="modal-dialog modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  Authorization Request Details
                </h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => setShowModal(false)}
                ></button>
              </div>
              <div className="modal-body">
                <div className="row">
                  <div className="col-md-6">
                    <h6>Domain Information</h6>
                    <table className="table table-sm">
                      <tbody>
                        <tr>
                          <td><strong>Domain:</strong></td>
                          <td>{selectedAuth.domain}</td>
                        </tr>
                        <tr>
                          <td><strong>Status:</strong></td>
                          <td>{getStatusBadge(selectedAuth)}</td>
                        </tr>
                        <tr>
                          <td><strong>Type:</strong></td>
                          <td>{selectedAuth.authorization_type?.replace('_', ' ').toUpperCase()}</td>
                        </tr>
                        <tr>
                          <td><strong>Compliance:</strong></td>
                          <td>{selectedAuth.compliance_mode?.charAt(0).toUpperCase() + selectedAuth.compliance_mode?.slice(1)}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  <div className="col-md-6">
                    <h6>User & Contact Information</h6>
                    <table className="table table-sm">
                      <tbody>
                        <tr>
                          <td><strong>User:</strong></td>
                          <td>{selectedAuth.user?.username || 'Unknown'}</td>
                        </tr>
                        <tr>
                          <td><strong>Contact Person:</strong></td>
                          <td>{selectedAuth.contact_person || 'N/A'}</td>
                        </tr>
                        <tr>
                          <td><strong>Contact Email:</strong></td>
                          <td>{selectedAuth.contact_email || 'N/A'}</td>
                        </tr>
                        <tr>
                          <td><strong>Created:</strong></td>
                          <td>{new Date(selectedAuth.created_at).toLocaleString()}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
                
                {selectedAuth.authorization_notes && (
                  <div className="mt-3">
                    <h6>Authorization Notes</h6>
                    <div className="border rounded p-3 bg-light">
                      {selectedAuth.authorization_notes}
                    </div>
                  </div>
                )}

                {selectedAuth.is_approved && (
                  <div className="mt-3">
                    <h6>Approval Information</h6>
                    <table className="table table-sm">
                      <tbody>
                        <tr>
                          <td><strong>Approved By:</strong></td>
                          <td>{selectedAuth.approved_by?.username || 'System'}</td>
                        </tr>
                        <tr>
                          <td><strong>Approved At:</strong></td>
                          <td>
                            {selectedAuth.approved_at ? 
                              new Date(selectedAuth.approved_at).toLocaleString() : 
                              'N/A'
                            }
                          </td>
                        </tr>
                        <tr>
                          <td><strong>Valid Until:</strong></td>
                          <td>
                            {selectedAuth.valid_until ? 
                              new Date(selectedAuth.valid_until).toLocaleString() : 
                              'N/A'
                            }
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
              <div className="modal-footer">
                {!selectedAuth.is_approved && (
                  <button
                    className="btn btn-success"
                    onClick={() => {
                      handleApprove(selectedAuth.id);
                      setShowModal(false);
                    }}
                    disabled={processing}
                  >
                    <i className="bi bi-check-lg me-1"></i>
                    Approve Authorization
                  </button>
                )}
                {selectedAuth.is_approved && selectedAuth.is_active && (
                  <button
                    className="btn btn-danger"
                    onClick={() => {
                      handleRevoke(selectedAuth.id);
                      setShowModal(false);
                    }}
                    disabled={processing}
                  >
                    <i className="bi bi-x-lg me-1"></i>
                    Revoke Authorization
                  </button>
                )}
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => setShowModal(false)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      {showModal && <div className="modal-backdrop show"></div>}
    </div>
  );
};

export default AdminAuthorizationPanel;