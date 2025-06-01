// src/services/__tests__/anomalyServices.test.js
import { anomalyService } from "../anomalyService";
import api from "../api";

jest.mock("../api");

describe("anomalyServices", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("detectAnomalies analyzes scan data for anomalies", async () => {
    const mockAnomalies = [
      {
        id: "anomaly1",
        type: "suspicious_pattern",
        severity: "high",
        description: "Unusual port configuration detected",
        confidence: 0.85,
      },
    ];

    api.post.mockResolvedValue({ data: { anomalies: mockAnomalies } });

    const scanData = {
      target_url: "https://example.com",
      results: [{ severity: "high", category: "ports" }],
    };

    const result = await anomalyService.detectAnomalies(scanData);

    expect(api.post).toHaveBeenCalledWith(
      "/ai-analyzer/anomaly-detection/",
      scanData
    );
    expect(result.success).toBe(true);
    expect(result.data.anomalies).toEqual(mockAnomalies);
  });

  it("getAnomalyHistory fetches historical anomaly data", async () => {
    const mockHistory = {
      results: [
        {
          date: "2025-01-01",
          anomaly_count: 3,
          severity_distribution: { high: 1, medium: 2 },
        },
        {
          date: "2025-01-02",
          anomaly_count: 1,
          severity_distribution: { low: 1 },
        },
      ],
    };

    api.get.mockResolvedValue({ data: mockHistory });

    const result = await anomalyService.getAnomalyHistory("7d");

    expect(api.get).toHaveBeenCalledWith(
      "/ai-analyzer/anomaly-history/?period=7d"
    );
    expect(result.success).toBe(true);
    expect(result.data.results).toHaveLength(2);
  });

  it("analyzeSecurityTrends identifies security patterns", async () => {
    const mockTrends = {
      trends: [
        {
          pattern: "increasing_ssl_issues",
          confidence: 0.92,
          time_frame: "30d",
          recommendation: "Review SSL configuration",
        },
      ],
    };

    api.post.mockResolvedValue({ data: mockTrends });

    const historicalData = [
      { date: "2025-01-01", ssl_score: 85 },
      { date: "2025-01-02", ssl_score: 75 },
    ];

    const result = await anomalyService.analyzeSecurityTrends(historicalData);

    expect(api.post).toHaveBeenCalledWith("/ai-analyzer/trend-analysis/", {
      data: historicalData,
    });
    expect(result.success).toBe(true);
    expect(result.data.trends).toHaveLength(1);
  });

  it("generateAnomalyReport creates comprehensive anomaly report", async () => {
    const mockReport = {
      report_id: "anomaly_report_123",
      scan_id: "scan123",
      anomalies_detected: 5,
      risk_level: "medium",
      recommendations: ["Update SSL configuration", "Review security headers"],
    };

    api.post.mockResolvedValue({ data: mockReport });

    const result = await anomalyService.generateAnomalyReport("scan123");

    expect(api.post).toHaveBeenCalledWith("/ai-analyzer/anomaly-report/", {
      scan_id: "scan123",
    });
    expect(result.success).toBe(true);
    expect(result.data.anomalies_detected).toBe(5);
  });

  it("handles API errors gracefully", async () => {
    api.post.mockRejectedValue({
      response: { status: 500, data: { error: "Internal server error" } },
    });

    // Use valid data so it passes validation and actually makes the API call
    const validScanData = {
      target_url: "https://example.com",
      results: [{ severity: "high", category: "ports" }],
    };

    const result = await anomalyService.detectAnomalies(validScanData);

    expect(result.success).toBe(false);
    expect(result.error).toContain("Internal server error");
  });

  it("handles validation errors for invalid data", async () => {
    // Test the validation error case separately
    const invalidData = {
      results: [], // missing target_url
    };

    const result = await anomalyService.detectAnomalies(invalidData);

    expect(result.success).toBe(false);
    expect(result.error).toBe(
      "Invalid scan data provided for anomaly detection"
    );
  });

  it("validateAnomalyData checks input data validity", () => {
    const validData = {
      target_url: "https://example.com",
      results: [{ severity: "high", category: "ssl" }],
    };

    const invalidData = {
      results: [], // missing target_url
    };

    expect(anomalyService.validateAnomalyData(validData)).toBe(true);
    expect(anomalyService.validateAnomalyData(invalidData)).toBe(false);
  });

  it("calculateAnomalyScore computes risk score correctly", () => {
    const anomalies = [
      { severity: "critical", confidence: 0.95 },
      { severity: "high", confidence: 0.85 },
      { severity: "medium", confidence: 0.7 },
    ];

    const score = anomalyService.calculateAnomalyScore(anomalies);

    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
    expect(typeof score).toBe("number");
  });
});
