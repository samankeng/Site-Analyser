// frontend/src/components/settings/SocialAccountsSettings.js - Updated with Microsoft support

import { useEffect, useState } from "react";
import { authService } from "../../services/authService";

const SocialAccountsSettings = () => {
  const [connectedAccounts, setConnectedAccounts] = useState({
    google: false,
    github: false,
    microsoft: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    fetchConnectedAccounts();
  }, []);

  const fetchConnectedAccounts = async () => {
    try {
      const response = await authService.getConnectedAccounts();
      if (response.success) {
        setConnectedAccounts(
          response.data || {
            google: false,
            github: false,
            microsoft: false,
          }
        );
      }
    } catch (error) {
      console.error("Error fetching connected accounts:", error);
    }
  };

  const handleConnect = async (provider) => {
    setLoading(true);
    setError("");
    setSuccess("");

    try {
      // For OAuth providers, redirect to the OAuth authorization URL
      if (provider === "github") {
        const clientId = process.env.REACT_APP_GITHUB_CLIENT_ID;
        const redirectUri = `${window.location.origin}/auth/github/callback`;
        const scope = "user:email";

        if (!clientId) {
          setError("GitHub OAuth is not configured.");
          setLoading(false);
          return;
        }

        window.location.href = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}`;
        return;
      }

      if (provider === "microsoft") {
        const clientId = process.env.REACT_APP_MICROSOFT_CLIENT_ID;
        const redirectUri = `${window.location.origin}/auth/microsoft/callback`;
        const scope = "openid profile email";

        if (!clientId) {
          setError("Microsoft OAuth is not configured.");
          setLoading(false);
          return;
        }

        const authUrl =
          `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` +
          `client_id=${clientId}&` +
          `response_type=code&` +
          `redirect_uri=${encodeURIComponent(redirectUri)}&` +
          `scope=${encodeURIComponent(scope)}&` +
          `response_mode=query`;

        window.location.href = authUrl;
        return;
      }

      if (provider === "google") {
        const clientId = process.env.REACT_APP_GOOGLE_CLIENT_ID;
        const redirectUri = `${window.location.origin}/auth/google/callback`;
        const scope = "openid profile email";

        if (!clientId) {
          setError("Google OAuth is not configured.");
          setLoading(false);
          return;
        }

        const authUrl =
          `https://accounts.google.com/o/oauth2/v2/auth?` +
          `client_id=${clientId}&` +
          `response_type=code&` +
          `redirect_uri=${encodeURIComponent(redirectUri)}&` +
          `scope=${encodeURIComponent(scope)}`;

        window.location.href = authUrl;
        return;
      }

      // For other providers, use the API endpoint
      const response = await authService.connectSocialAccount(provider);

      if (response.success) {
        if (response.data?.redirect_url) {
          window.location.href = response.data.redirect_url;
        } else {
          setSuccess(`${provider} account connected successfully.`);
          fetchConnectedAccounts();
        }
      } else {
        setError(response.error || `Failed to connect ${provider} account.`);
      }
    } catch (error) {
      console.error(`Error connecting ${provider}:`, error);
      setError(`An error occurred while connecting ${provider}.`);
    } finally {
      setLoading(false);
    }
  };

  const handleDisconnect = async (provider) => {
    setLoading(true);
    setError("");
    setSuccess("");

    try {
      const response = await authService.disconnectSocialAccount(provider);

      if (response.success) {
        setSuccess(`${provider} account disconnected successfully.`);
        setConnectedAccounts({
          ...connectedAccounts,
          [provider]: false,
        });
      } else {
        setError(response.error || `Failed to disconnect ${provider} account.`);
      }
    } catch (error) {
      console.error(`Error disconnecting ${provider}:`, error);
      setError(`An error occurred while disconnecting ${provider}.`);
    } finally {
      setLoading(false);
    }
  };

  const providers = [
    {
      id: "google",
      name: "Google",
      icon: "fab fa-google",
      color: "primary",
      description: "Connect your Google account for easy sign-in",
    },
    {
      id: "github",
      name: "GitHub",
      icon: "fab fa-github",
      color: "dark",
      description: "Connect your GitHub account for developer features",
    },
    {
      id: "microsoft",
      name: "Microsoft",
      icon: "fab fa-microsoft",
      color: "info",
      description: "Connect your Microsoft account for Office 365 integration",
    },
  ];

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header bg-light">
        <h6 className="mb-0">
          <i className="fas fa-link me-2"></i>
          Connected Accounts
        </h6>
      </div>
      <div className="card-body">
        {error && (
          <div
            className="alert alert-danger alert-dismissible fade show"
            role="alert"
          >
            <i className="fas fa-exclamation-triangle me-2"></i>
            {error}
            <button
              type="button"
              className="btn-close"
              onClick={() => setError("")}
              aria-label="Close"
            ></button>
          </div>
        )}

        {success && (
          <div
            className="alert alert-success alert-dismissible fade show"
            role="alert"
          >
            <i className="fas fa-check-circle me-2"></i>
            {success}
            <button
              type="button"
              className="btn-close"
              onClick={() => setSuccess("")}
              aria-label="Close"
            ></button>
          </div>
        )}

        <div className="row">
          {providers.map((provider) => (
            <div key={provider.id} className="col-md-6 col-lg-4 mb-3">
              <div className="card h-100 border">
                <div className="card-body text-center">
                  <div className="mb-3">
                    <i
                      className={`${provider.icon} fa-3x text-${provider.color}`}
                      style={{
                        opacity: connectedAccounts[provider.id] ? 1 : 0.5,
                      }}
                    ></i>
                  </div>

                  <h6 className="card-title">{provider.name}</h6>
                  <p className="card-text small text-muted mb-3">
                    {provider.description}
                  </p>

                  <div className="mb-2">
                    {connectedAccounts[provider.id] ? (
                      <span className="badge bg-success">
                        <i className="fas fa-check me-1"></i>
                        Connected
                      </span>
                    ) : (
                      <span className="badge bg-secondary">
                        <i className="fas fa-times me-1"></i>
                        Not Connected
                      </span>
                    )}
                  </div>

                  {connectedAccounts[provider.id] ? (
                    <button
                      className="btn btn-sm btn-outline-danger"
                      onClick={() => handleDisconnect(provider.id)}
                      disabled={loading}
                    >
                      {loading ? (
                        <span
                          className="spinner-border spinner-border-sm me-1"
                          role="status"
                          aria-hidden="true"
                        ></span>
                      ) : (
                        <i className="fas fa-unlink me-1"></i>
                      )}
                      Disconnect
                    </button>
                  ) : (
                    <button
                      className={`btn btn-sm btn-outline-${provider.color}`}
                      onClick={() => handleConnect(provider.id)}
                      disabled={loading}
                    >
                      {loading ? (
                        <span
                          className="spinner-border spinner-border-sm me-1"
                          role="status"
                          aria-hidden="true"
                        ></span>
                      ) : (
                        <i className={`${provider.icon} me-1`}></i>
                      )}
                      Connect
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-3 p-3 bg-light rounded">
          <div className="d-flex align-items-start">
            <i className="fas fa-info-circle text-info me-2 mt-1"></i>
            <div>
              <h6 className="mb-1">About Connected Accounts</h6>
              <ul className="mb-0 small text-muted">
                <li>
                  Connected accounts allow you to sign in quickly without
                  entering your password
                </li>
                <li>You can connect multiple accounts for added convenience</li>
                <li>
                  Disconnecting all accounts requires you to have a password set
                </li>
                <li>
                  Your account data remains secure and is not shared with
                  connected services
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SocialAccountsSettings;
