// src/pages/compliance/Compliance.js

import ComplianceAcceptance from "../../components/compliance/ComplianceAcceptance";

const CompliancePage = () => {
  const handleComplianceComplete = () => {
    console.log("Compliance agreements complete.");
    // Optional: Redirect or trigger further action
  };

  return (
    <div className="container mt-5">
      <h2 className="mb-4">
        <i className="fas fa-balance-scale text-primary me-2"></i>
        Compliance Center
      </h2>

      <ComplianceAcceptance onComplianceComplete={handleComplianceComplete} />
    </div>
  );
};

export default CompliancePage;
