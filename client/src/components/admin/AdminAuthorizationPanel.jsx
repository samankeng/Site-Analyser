import { useCallback, useEffect, useState } from 'react';
import api from '../../services/api';

const AdminAuthorizationPanel = () => {
  const [authorizations, setAuthorizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedAuth, setSelectedAuth] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [filters, setFilters] = useState({
    status: 'all',
    verificationMethod: 'all',
    search: ''
  });
  const [stats, setStats] = useState({
    total: 0,
    pending: 0,
    verified: 0,
    rejected: 0
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
      
      // Use the new compliance admin endpoint
      const response = await api.get('compliance/admin/domain-authorizations/');
      
      if (response.data) {
        if (response.data.results) {
          setAuthorizations(response.data.results);
        } else if (Array.isArray(response.data)) {
          setAuthorizations(response.data);
        } else {
          setAuthorizations([]);
        }
      } else if (response.results) {
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

  const calculateStats = useCallback(() => {
  const now = new Date();
  const stats = {
    total: authorizations.length,
    pending: authorizations.filter(auth => auth.status === 'pending').length,
    verified: authorizations.filter(auth => auth.status === 'verified' && auth.is_active).length,
    rejected: authorizations.filter(auth =>
      auth.status === 'rejected' || !auth.is_active ||
      (auth.expires_at && new Date(auth.expires_at) < now)
    ).length
  };
  setStats(stats);
}, [authorizations]); // ✅ dependency for memoization

  const handleApprove = async (authId) => {
    if (!window.confirm('Are you sure you want to approve this authorization request?')) {
      return;
    }

    try {
      setProcessing(true);
      // Use the new compliance endpoint
      await api.post(`compliance/domain-authorizations/${authId}/approve/`);
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
      // Use the new compliance endpoint
      await api.post(`compliance/domain-authorizations/${authId}/revoke/`);
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
    
    if (auth.status === 'pending') {
      return <span className="badge bg-warning">Pending</span>;
    }
    if (auth.status === 'rejected' || !auth.is_active) {
      return <span className="badge bg-secondary">Revoked</span>;
    }
    if (auth.expires_at && new Date(auth.expires_at) < now) {
      return <span className="badge bg-danger">Expired</span>;
    }
    if (auth.status === 'verified') {
      return <span className="badge bg-success">Verified</span>;
    }
    return <span className="badge bg-light text-dark">Unknown</span>;
  };

  const getUrgencyBadge = (auth) => {
    // Check if authorization was created recently (within 24 hours)
    const createdAt = new Date(auth.created_at || auth.requested_at);
    const now = new Date();
    const hoursDiff = (now - createdAt) / (1000 * 60 * 60);
    
    if (hoursDiff < 24 && auth.status === 'pending') {
      return <span className="badge bg-info ms-2">New</span>;
    }
    
    // Check if approaching expiration (within 30 days)
    if (auth.expires_at) {
      const validUntil = new Date(auth.expires_at);
      const daysDiff = (validUntil - now) / (1000 * 60 * 60 * 24);
      
      if (daysDiff <= 30 && daysDiff > 0 && auth.status === 'verified') {
        return <span className="badge bg-warning ms-2">Expiring Soon</span>;
      }
    }
    
    return null;
  };

  const filteredAuthorizations = authorizations.filter(auth => {
    // Status filter
    if (filters.status !== 'all') {
      const now = new Date();
      
      switch (filters.status) {
        case 'pending':
          if (auth.status !== 'pending') return false;
          break;
        case 'verified':
          if (auth.status !== 'verified' || !auth.is_active) return false;
          break;
        case 'expired':
          if (!auth.expires_at || new Date(auth.expires_at) >= now || !auth.is_active) return false;
          break;
        case 'revoked':
          if (auth.is_active) return false;
          break;
        default:
          break;
      }
    }

    // Verification method filter
    if (filters.verificationMethod !== 'all' && auth.verification_method !== filters.verificationMethod) {
      return false;
    }

    // Search filter
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      return (
        auth.domain.toLowerCase().includes(searchLower) ||
        auth.user?.username?.toLowerCase().includes(searchLower) ||
        auth.notes?.toLowerCase().includes(searchLower)
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
              <p className="text-muted mb-0">Review and manage domain authorization requests for active scanning</p>
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
                  <h3 className="text-success mb-1">{stats.verified}</h3>
                  <p className="card-text mb-0">Verified</p>
                </div>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-3">
              <div className="card border-danger">
                <div className="card-body text-center">
                  <h3 className="text-danger mb-1">{stats.rejected}</h3>
                  <p className="card-text mb-0">Expired/Revoked</p>
                </div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="card mb-4">
            <div className="card-body">
              <div className="row g-3">
                <div className="col-md-4">
                  <label className="form-label">Status</label>
                  <select 
                    className="form-select"
                    value={filters.status}
                    onChange={(e) => setFilters({...filters, status: e.target.value})}
                  >
                    <option value="all">All Status</option>
                    <option value="pending">Pending</option>
                    <option value="verified">Verified</option>
                    <option value="expired">Expired</option>
                    <option value="revoked">Revoked</option>
                  </select>
                </div>
                <div className="col-md-4">
                  <label className="form-label">Verification Method</label>
                  <select 
                    className="form-select"
                    value={filters.verificationMethod}
                    onChange={(e) => setFilters({...filters, verificationMethod: e.target.value})}
                  >
                    <option value="all">All Methods</option>
                    <option value="dns_txt">DNS TXT Record</option>
                    <option value="file_upload">File Upload</option>
                    <option value="email_verification">Email Verification</option>
                    <option value="manual_approval">Manual Approval</option>
                  </select>
                </div>
                <div className="col-md-4">
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
                        <th>Verification Method</th>
                        <th>Status</th>
                        <th>Requested</th>
                        <th>Expires</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAuthorizations.map((auth) => (
                        <tr key={auth.id}>
                          <td>
                            <div className="fw-bold">{auth.domain}</div>
                            {auth.notes && (
                              <small className="text-muted">
                                {auth.notes.substring(0, 50)}...
                              </small>
                            )}
                          </td>
                          <td>
                            <div>{auth.user?.username || 'Unknown'}</div>
                            {auth.user?.email && (
                              <small className="text-muted">{auth.user.email}</small>
                            )}
                          </td>
                          <td>
                            <span className="badge bg-secondary">
                              {auth.verification_method?.replace('_', ' ').toUpperCase() || 'N/A'}
                            </span>
                          </td>
                          <td>
                            {getStatusBadge(auth)}
                            {getUrgencyBadge(auth)}
                          </td>
                          <td>
                            <small className="text-muted">
                              {new Date(auth.created_at || auth.requested_at).toLocaleDateString()}
                            </small>
                          </td>
                          <td>
                            <small className="text-muted">
                              {auth.expires_at ? 
                                new Date(auth.expires_at).toLocaleDateString() : 
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
                              {auth.status === 'pending' && (
                                <button
                                  className="btn btn-outline-success"
                                  onClick={() => handleApprove(auth.id)}
                                  disabled={processing}
                                >
                                  <i className="bi bi-check-lg"></i>
                                </button>
                              )}
                              {auth.status === 'verified' && auth.is_active && (
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
                  Domain Authorization Details
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
                          <td><strong>Verification Method:</strong></td>
                          <td>{selectedAuth.verification_method?.replace('_', ' ').toUpperCase() || 'N/A'}</td>
                        </tr>
                        <tr>
                          <td><strong>Active:</strong></td>
                          <td>{selectedAuth.is_active ? 'Yes' : 'No'}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  <div className="col-md-6">
                    <h6>User & Timeline</h6>
                    <table className="table table-sm">
                      <tbody>
                        <tr>
                          <td><strong>User:</strong></td>
                          <td>{selectedAuth.user?.username || 'Unknown'}</td>
                        </tr>
                        <tr>
                          <td><strong>Email:</strong></td>
                          <td>{selectedAuth.user?.email || 'N/A'}</td>
                        </tr>
                        <tr>
                          <td><strong>Requested:</strong></td>
                          <td>{new Date(selectedAuth.created_at || selectedAuth.requested_at).toLocaleString()}</td>
                        </tr>
                        {selectedAuth.verified_at && (
                          <tr>
                            <td><strong>Verified:</strong></td>
                            <td>{new Date(selectedAuth.verified_at).toLocaleString()}</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
                
                {selectedAuth.notes && (
                  <div className="mt-3">
                    <h6>Notes / Justification</h6>
                    <div className="border rounded p-3 bg-light">
                      {selectedAuth.notes}
                    </div>
                  </div>
                )}

                {selectedAuth.verification_token && (
                  <div className="mt-3">
                    <h6>Verification Token</h6>
                    <div className="border rounded p-3 bg-light">
                      <code>{selectedAuth.verification_token}</code>
                    </div>
                  </div>
                )}

                {selectedAuth.verification_data && (
                  <div className="mt-3">
                    <h6>Verification Data</h6>
                    <div className="border rounded p-3 bg-light">
                      <pre className="mb-0 small">
                        {typeof selectedAuth.verification_data === 'object'
                          ? JSON.stringify(selectedAuth.verification_data, null, 2)
                          : selectedAuth.verification_data}
                      </pre>
                    </div>
                  </div>
                )}

                {selectedAuth.status === 'verified' && (
                  <div className="mt-3">
                    <h6>Approval Information</h6>
                    <table className="table table-sm">
                      <tbody>
                        <tr>
                          <td><strong>Approved By:</strong></td>
                          <td>{selectedAuth.approved_by_username || selectedAuth.approved_by?.username || 'System'}</td>
                        </tr>
                        <tr>
                          <td><strong>Verified At:</strong></td>
                          <td>
                            {selectedAuth.verified_at ? 
                              new Date(selectedAuth.verified_at).toLocaleString() : 
                              'N/A'
                            }
                          </td>
                        </tr>
                        <tr>
                          <td><strong>Expires:</strong></td>
                          <td>
                            {selectedAuth.expires_at ? 
                              new Date(selectedAuth.expires_at).toLocaleString() : 
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
                {selectedAuth.status === 'pending' && (
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
                {selectedAuth.status === 'verified' && selectedAuth.is_active && (
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