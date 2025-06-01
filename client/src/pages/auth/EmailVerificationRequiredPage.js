// frontend/src/pages/auth/EmailVerificationRequiredPage.js

import { useLocation } from "react-router-dom";
import EmailVerificationRequired from "../../components/auth/EmailVerificationRequired";

const EmailVerificationRequiredPage = () => {
  const location = useLocation();
  const email = location.state?.email || "";

  return <EmailVerificationRequired email={email} />;
};

export default EmailVerificationRequiredPage;
