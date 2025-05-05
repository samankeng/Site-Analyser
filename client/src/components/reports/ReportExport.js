// frontend/src/components/reports/ReportExport.js

import React, { useState } from 'react';

const ReportExport = ({ show, onClose, onExport, selectedCount }) => {
  const [format, setFormat] = useState('pdf');
  const [includeOptions, setIncludeOptions] = useState({
    summary: true,
    details: true,
    recommendations: true,
    screenshots: true,
    raw_data: false
  });
  const [loading, setLoading] = useState(false);

  const handleFormatChange = (e) => {
    setFormat(e.target.value);
  };

  const handleOptionChange = (e) => {
    const { name, checked } = e.target;
    setIncludeOptions(prev => ({
      ...prev,
      [name]: checked
    }));
  };

  const handleExport = async () => {
    setLoading(true);
    try {
      await onExport(format, includeOptions);
    } finally {
      setLoading(false);
    }
  };

  if (!show) {
    return null;
  }

  return (
    <>
      <div className="modal-backdrop fade show"></div>
      <div className="modal fade show" tabIndex="-1" style={{ display: 'block' }}>
        <div className="modal-dialog">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">Export Reports</h5>
              <button 
                type="button" 
                className="btn-close" 
                onClick={onClose}
                aria-label="Close"
              ></button>
            </div>
            <div className="modal-body">
              <p>You are about to export <strong>{selectedCount}</strong> selected report(s).</p>
              
              <div className="mb-3">
                <label className="form-label">Export Format</label>
                <div className="d-flex">
                  <div className="form-check me-3">
                    <input
                      className="form-check-input"
                      type="radio"
                      name="exportFormat"
                      id="formatPdf"
                      value="pdf"
                      checked={format === 'pdf'}
                      onChange={handleFormatChange}
                    />
                    <label className="form-check-label" htmlFor="formatPdf">
                      PDF
                    </label>
                  </div>
                  <div className="form-check me-3">
                    <input
                      className="form-check-input"
                      type="radio"
                      name="exportFormat"
                      id="formatCsv"
                      value="csv"
                      checked={format === 'csv'}
                      onChange={handleFormatChange}
                    />
                    <label className="form-check-label" htmlFor="formatCsv">
                      CSV
                    </label>
                  </div>
                  <div className="form-check me-3">
                    <input
                      className="form-check-input"
                      type="radio"
                      name="exportFormat"
                      id="formatJson"
                      value="json"
                      checked={format === 'json'}
                      onChange={handleFormatChange}
                    />
                    <label className="form-check-label" htmlFor="formatJson">
                      JSON
                    </label>
                  </div>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="radio"
                      name="exportFormat"
                      id="formatHtml"
                      value="html"
                      checked={format === 'html'}
                      onChange={handleFormatChange}
                    />
                    <label className="form-check-label" htmlFor="formatHtml">
                      HTML
                    </label>
                  </div>
                </div>
              </div>
              
              {(format === 'pdf' || format === 'html') && (
                <div className="mb-3">
                  <label className="form-label">Include in Report</label>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      name="summary"
                      id="includeSummary"
                      checked={includeOptions.summary}
                      onChange={handleOptionChange}
                    />
                    <label className="form-check-label" htmlFor="includeSummary">
                      Executive Summary
                    </label>
                  </div>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      name="details"
                      id="includeDetails"
                      checked={includeOptions.details}
                      onChange={handleOptionChange}
                    />
                    <label className="form-check-label" htmlFor="includeDetails">
                      Detailed Findings
                    </label>
                  </div>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      name="recommendations"
                      id="includeRecommendations"
                      checked={includeOptions.recommendations}
                      onChange={handleOptionChange}
                    />
                    <label className="form-check-label" htmlFor="includeRecommendations">
                      Recommendations
                    </label>
                  </div>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      name="screenshots"
                      id="includeScreenshots"
                      checked={includeOptions.screenshots}
                      onChange={handleOptionChange}
                    />
                    <label className="form-check-label" htmlFor="includeScreenshots">
                      Screenshots
                    </label>
                  </div>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      name="raw_data"
                      id="includeRawData"
                      checked={includeOptions.raw_data}
                      onChange={handleOptionChange}
                    />
                    <label className="form-check-label" htmlFor="includeRawData">
                      Raw Data
                    </label>
                  </div>
                </div>
              )}
              
              <div className="alert alert-info small">
                <i className="bi bi-info-circle me-2"></i>
                {format === 'pdf' ? (
                  "PDF exports include all findings with details and can be shared with stakeholders."
                ) : format === 'csv' ? (
                  "CSV exports are useful for data analysis and can be imported into spreadsheet applications."
                ) : format === 'json' ? (
                  "JSON exports contain the complete raw data and are ideal for integration with other tools."
                ) : (
                  "HTML exports can be viewed in any browser and are easy to share."
                )}
              </div>
            </div>
            <div className="modal-footer">
              <button 
                type="button" 
                className="btn btn-secondary" 
                onClick={onClose}
              >
                Cancel
              </button>
              <button 
                type="button" 
                className="btn btn-primary" 
                onClick={handleExport}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                    Exporting...
                  </>
                ) : (
                  `Export ${selectedCount} Report${selectedCount !== 1 ? 's' : ''}`
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default ReportExport;