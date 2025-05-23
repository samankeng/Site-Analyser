// frontend/src/components/settings/SocialAccountsSettings.js

import { useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { socialAuthService } from "../../services/socialAuthService";

const SocialAccountsSettings = () => {
  const {
    user,
    connectedProviders,
    canDisconnectProvider,
    disconnectSocialAccount,
    setSocialUser,
  } = useAuth();

  const [loading, setLoading] = useState(null);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const availableProviders = socialAuthService.getAvailableProviders();

  const handleConnect = async (provider) => {
    setLoading(provider);
    setError("");
    setSuccess("");

    try {
      if (provider === "google") {
        const result = await socialAuthService.loginWithGoogle();
        if (result && result.success) {
          setSocialUser(result.user);
          setSuccess(`Successfully connected ${provider} account!`);
        }
      } else if (provider === "github") {
        await socialAuthService.loginWithGitHub();
        // GitHub redirects, so we don't handle the response here
      }
    } catch (error) {
      setError(`Failed to connect ${provider}: ${error.message}`);
    } finally {
      setLoading(null);
    }
  };

  const handleDisconnect = async (provider) => {
    if (!canDisconnectProvider(provider)) {
      setError("Cannot disconnect the only authentication method");
      return;
    }

    const confirmed = window.confirm(
      `Are you sure you want to disconnect your ${provider} account?`
    );

    if (!confirmed) return;

    setLoading(provider);
    setError("");
    setSuccess("");

    try {
      const result = await disconnectSocialAccount(provider);
      if (result.success) {
        setSuccess(`Successfully disconnected ${provider} account!`);
      } else {
        setError(result.error || `Failed to disconnect ${provider} account`);
      }
    } catch (error) {
      setError(`Failed to disconnect ${provider}: ${error.message}`);
    } finally {
      setLoading(null);
    }
  };

  const getProviderDisplayName = (provider) => {
    const providerData = availableProviders.find((p) => p.name === provider);
    return providerData ? providerData.displayName : provider;
  };

  const getProviderIcon = (provider) => {
    const providerData = availableProviders.find((p) => p.name === provider);
    return providerData ? providerData.icon : "fas fa-link";
  };

  const getProviderColor = (provider) => {
    const providerData = availableProviders.find((p) => p.name === provider);
    return providerData ? providerData.color : "#6c757d";
  };

  return (
    <div className="card">
      <div className="card-header">
        <h5 className="card-title mb-0">
          <i className="fas fa-users me-2"></i>
          Connected Accounts
        </h5>
      </div>
      <div className="card-body">
        <p className="text-muted mb-4">
          Connect your social accounts to make signing in easier. You can use
          any connected account to access your Site Analyser dashboard.
        </p>

        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}

        {success && (
          <div className="alert alert-success" role="alert">
            {success}
          </div>
        )}

        <div className="row g-3">
          {availableProviders.map((provider) => {
            const isConnected = connectedProviders.includes(provider.name);
            const canDisconnect = canDisconnectProvider(provider.name);
            const isLoading = loading === provider.name;

            return (
              <div key={provider.name} className="col-md-6">
                <div className="border rounded p-3 d-flex align-items-center justify-content-between">
                  <div className="d-flex align-items-center">
                    <i
                      className={`${provider.icon} fa-2x me-3`}
                      style={{ color: provider.color }}
                    ></i>
                    <div>
                      <h6 className="mb-1">{provider.displayName}</h6>
                      <small className="text-muted">
                        {isConnected ? "Connected" : "Not connected"}
                      </small>
                    </div>
                  </div>

                  <div>
                    {isConnected ? (
                      <button
                        type="button"
                        className={`btn btn-outline-danger btn-sm ${
                          !canDisconnect || isLoading ? "disabled" : ""
                        }`}
                        onClick={() => handleDisconnect(provider.name)}
                        disabled={!canDisconnect || isLoading}
                        title={
                          !canDisconnect
                            ? "Cannot disconnect the only authentication method"
                            : ""
                        }
                      >
                        {isLoading ? (
                          <>
                            <span className="spinner-border spinner-border-sm me-1"></span>
                            Disconnecting...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-unlink me-1"></i>
                            Disconnect
                          </>
                        )}
                      </button>
                    ) : (
                      <button
                        type="button"
                        className={`btn btn-outline-primary btn-sm ${
                          isLoading ? "disabled" : ""
                        }`}
                        onClick={() => handleConnect(provider.name)}
                        disabled={isLoading}
                      >
                        {isLoading ? (
                          <>
                            <span className="spinner-border spinner-border-sm me-1"></span>
                            Connecting...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-link me-1"></i>
                            Connect
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {user && user.is_social_account && (
          <div className="mt-4 p-3 bg-light rounded">
            <div className="d-flex align-items-start">
              <i className="fas fa-info-circle text-info me-2 mt-1"></i>
              <div>
                <strong>Account Security</strong>
                <p className="mb-0 small text-muted">
                  Your account was created using social authentication.
                  {connectedProviders.length === 1 && (
                    <span>
                      {" "}
                      Consider connecting another account or setting a password
                      for additional security.
                    </span>
                  )}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SocialAccountsSettings;
