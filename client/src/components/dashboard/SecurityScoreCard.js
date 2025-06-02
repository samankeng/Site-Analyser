// frontend/src/components/dashboard/SecurityScoreCard.js

import {
  getScoreColorClass,
  getSecurityRating,
} from "../../utils/securityUtils";

const SecurityScoreCard = ({ score, categories }) => {
  return (
    <div className="card h-100">
      <div className="card-body">
        <h5 className="card-title">Security Score For Latest Scan</h5>

        <div className="text-center my-4">
          <div className={`display-3 ${getScoreColorClass(score)}`}>
            {score}
          </div>
          <div className="text-muted">{getSecurityRating(score)}</div>
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
                <div className="progress" style={{ height: "6px" }}>
                  <div
                    className={`progress-bar ${getScoreColorClass(
                      categoryScore
                    )}`}
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
