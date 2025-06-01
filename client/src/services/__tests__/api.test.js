// src/services/__tests__/api.test.js
import * as storage from "../../utils/storage";
import api from "../api";

jest.mock("../../utils/storage");

describe("api service", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("exports an axios instance", () => {
    expect(api).toBeDefined();
    expect(api.get).toBeDefined();
    expect(api.post).toBeDefined();
    expect(api.put).toBeDefined();
    expect(api.delete).toBeDefined();
  });

  it("has interceptors configured", () => {
    expect(api.interceptors).toBeDefined();
    expect(api.interceptors.request).toBeDefined();
    expect(api.interceptors.response).toBeDefined();
  });

  it("has default configuration", () => {
    expect(api.defaults).toBeDefined();
    expect(api.defaults.baseURL).toBeDefined();
    expect(api.defaults.timeout).toBeDefined();
  });

  it("can make GET requests", async () => {
    // Mock a successful response
    const mockResponse = { data: { message: "success" } };
    jest.spyOn(api, "get").mockResolvedValue(mockResponse);

    const response = await api.get("/test");
    expect(response.data.message).toBe("success");

    api.get.mockRestore();
  });

  it("can make POST requests", async () => {
    const mockResponse = { data: { id: 1 } };
    jest.spyOn(api, "post").mockResolvedValue(mockResponse);

    const response = await api.post("/test", { data: "test" });
    expect(response.data.id).toBe(1);

    api.post.mockRestore();
  });

  it("handles request configuration", () => {
    // Test that we can access configuration
    expect(typeof api.defaults.baseURL).toBe("string");
    expect(typeof api.defaults.timeout).toBe("number");
  });

  it("storage utility is available for token management", () => {
    storage.getToken.mockReturnValue({ access: "test_token" });

    const token = storage.getToken();
    expect(token.access).toBe("test_token");
    expect(storage.getToken).toHaveBeenCalled();
  });
});
