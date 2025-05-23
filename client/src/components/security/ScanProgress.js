// frontend/src/components/security/ScanProgress.js

import React from 'react';

const ScanProgress = ({ scanTypes }) => {
  // Calculate pseudo-progress based on scan types
  const total = scanTypes.length;
  const current = Math.floor(Math.random() * (total - 1)) + 1; // Simulate progress
  const progressPercent = Math.round((current / total) * 100);
  
  return (
    <div className="mt-4">
      <h6>Scan in Progress</h6>
      <div className="progress mb-3">
        <div
          className="progress-bar progress-bar-striped progress-bar-animated"
          role="progressbar"
          style={{ width: `${progressPercent}%` }}
          aria-valuenow={progressPercent}
          aria-valuemin="0"
          aria-valuemax="100"
        ></div>
      </div>
      <small className="text-muted">
        Please wait while we analyze your website. This may take a few minutes.
      </small>
    </div>
  );
};

export default ScanProgress;