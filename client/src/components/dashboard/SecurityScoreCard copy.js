// frontend/src/components/dashboard/SecurityScoreCard.js

import React from 'react';

const SecurityScoreCard = ({ score, categories }) => {
  const getScoreColor = (score) => {
    if (score >= 90) return 'success';
    if (score >= 70) return 'info';
    if (score >= 50) return 'warning';
    return 'danger';
  };
  
  return (
    <div className="card h-100">
      <div className="card-body">
        <h5 className="card-title">Security Score</h5>
        
        <div className="text-center my-4">
          <div className={`display-3 text-${getScoreColor(score)}`}>
            {score}
          </div>
          <div className="text-muted">out of 100</div>
        </div>
        
        {categories && (
          <div className="mt-4">
            <h6>Category Scores</h6>
            {Object.entries(categories).map(([category, categoryScore]) => (
              <div key={category} className="mb-3">
                <div className="d-flex justify-content-between mb-1">
                  <span className="text-capitalize">{category}</span>
                  <span>{categoryScore}</span>
                </div>
                <div className="progress" style={{ height: '6px' }}>
                  <div
                    className={`progress-bar bg-${getScoreColor(categoryScore)}`}
                    role="progressbar"
                    style={{ width: `${categoryScore}%` }}
                    aria-valuenow={categoryScore}
                    aria-valuemin="0"
                    aria-valuemax="100"
                  ></div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityScoreCard;