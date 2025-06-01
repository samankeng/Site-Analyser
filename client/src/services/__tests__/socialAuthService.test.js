// src/services/__tests__/socialAuthService.test.js
import api from "../api";
import { socialAuthService } from "../socialAuthService";

jest.mock("../api");

// Mock window.location
delete window.location;
window.location = {
  href: "",
  assign: jest.fn(),
  replace: jest.fn(),
};

describe("socialAuthService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("initiateGitHubLogin redirects to GitHub OAuth", () => {
    const redirectUrl = "https://example.com/callback";
    socialAuthService.initiateGitHubLogin(redirectUrl);

    expect(localStorage.getItem("oauth_redirect")).toBe(redirectUrl);
    expect(window.location.assign).toHaveBeenCalledWith(
      expect.stringContaining("github.com/login/oauth/authorize")
    );
  });

  it("initiateMicrosoftLogin redirects to Microsoft OAuth", () => {
    const redirectUrl = "https://example.com/callback";
    socialAuthService.initiateMicrosoftLogin(redirectUrl);

    expect(localStorage.getItem("oauth_redirect")).toBe(redirectUrl);
    expect(window.location.assign).toHaveBeenCalledWith(
      expect.stringContaining("login.microsoftonline.com")
    );
  });

  it("handleOAuthCallback processes successful callback", async () => {
    const mockResponse = {
      success: true,
      access: "token123",
      refresh: "refresh123",
      user: { email: "test@example.com" },
    };

    api.post.mockResolvedValue({ data: mockResponse });

    const result = await socialAuthService.handleOAuthCallback(
      "github",
      "code123",
      "state123"
    );

    expect(api.post).toHaveBeenCalledWith("/auth/github/exchange/", {
      code: "code123",
      state: "state123",
    });
    expect(result.success).toBe(true);
    expect(result.user.email).toBe("test@example.com");
  });

  it("handles OAuth callback errors", async () => {
    api.post.mockRejectedValue({
      response: {
        status: 400,
        data: { error: "Invalid authorization code" },
      },
    });

    const result = await socialAuthService.handleOAuthCallback(
      "github",
      "invalid_code",
      "state123"
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain("Invalid authorization code");
  });

  it("connectSocialAccount links account to user", async () => {
    const mockResponse = {
      success: true,
      message: "GitHub account connected successfully",
    };

    api.post.mockResolvedValue({ data: mockResponse });

    const result = await socialAuthService.connectSocialAccount(
      "github",
      "access_token_123"
    );

    expect(api.post).toHaveBeenCalledWith("/auth/social/connect/", {
      provider: "github",
      access_token: "access_token_123",
    });
    expect(result.success).toBe(true);
  });

  it("disconnectSocialAccount unlinks account", async () => {
    const mockResponse = {
      success: true,
      message: "GitHub account disconnected successfully",
    };

    api.post.mockResolvedValue({ data: mockResponse });

    const result = await socialAuthService.disconnectSocialAccount("github");

    expect(api.post).toHaveBeenCalledWith("/auth/social/disconnect/", {
      provider: "github",
    });
    expect(result.success).toBe(true);
  });

  it("getConnectedAccounts fetches linked accounts", async () => {
    const mockAccounts = {
      github: true,
      microsoft: false,
      google: true,
    };

    api.get.mockResolvedValue({ data: mockAccounts });

    const result = await socialAuthService.getConnectedAccounts();

    expect(api.get).toHaveBeenCalledWith("/auth/connected-accounts/");
    expect(result.success).toBe(true);
    expect(result.data.github).toBe(true);
  });

  it("generateState creates secure state parameter", () => {
    const state1 = socialAuthService.generateState();
    const state2 = socialAuthService.generateState();

    expect(state1).toBeDefined();
    expect(state2).toBeDefined();
    expect(state1).not.toBe(state2);
    expect(state1.length).toBeGreaterThan(10);
  });

  it("validateState checks state parameter validity", () => {
    const state = "valid_state_123";
    sessionStorage.setItem("oauth_state", state);

    expect(socialAuthService.validateState(state)).toBe(true);
    expect(socialAuthService.validateState("invalid_state")).toBe(false);
  });

  it("clearOAuthData removes stored OAuth information", () => {
    localStorage.setItem("oauth_redirect", "https://example.com");
    sessionStorage.setItem("oauth_state", "state123");
    sessionStorage.setItem("oauth_exchanged", "true");

    socialAuthService.clearOAuthData();

    expect(localStorage.getItem("oauth_redirect")).toBeNull();
    expect(sessionStorage.getItem("oauth_state")).toBeNull();
    expect(sessionStorage.getItem("oauth_exchanged")).toBeNull();
  });

  it("isOAuthInProgress detects ongoing OAuth flow", () => {
    expect(socialAuthService.isOAuthInProgress()).toBe(false);

    sessionStorage.setItem("oauth_state", "state123");
    expect(socialAuthService.isOAuthInProgress()).toBe(true);

    sessionStorage.setItem("oauth_exchanged", "true");
    expect(socialAuthService.isOAuthInProgress()).toBe(false);
  });
});
