// src/services/__tests__/virtualReportService.test.js
import { scanService } from "../scanService";
import { virtualReportService } from "../virtualReportService";

jest.mock("../scanService");

describe("virtualReportService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("generateVirtualReport creates report from scan data", async () => {
    const mockScan = {
      id: "scan123",
      target_url: "https://example.com",
      status: "completed",
      results: [
        { severity: "high", category: "ssl", title: "SSL Issue" },
        { severity: "medium", category: "headers", title: "Missing Header" },
      ],
    };

    scanService.getScanWithResults.mockResolvedValue({
      success: true,
      data: mockScan,
    });

    const result = await virtualReportService.generateVirtualReport("scan123");

    expect(scanService.getScanWithResults).toHaveBeenCalledWith("scan123");
    expect(result.success).toBe(true);
    expect(result.data.id).toBe("scan123");
    expect(result.data.findings_summary.total).toBe(2);
    expect(result.data.security_score).toBeDefined();
  });

  it("handles failed scan fetch", async () => {
    scanService.getScanWithResults.mockResolvedValue({
      success: false,
      error: "Scan not found",
    });

    const result = await virtualReportService.generateVirtualReport("scan123");

    expect(result.success).toBe(false);
    expect(result.error).toBe("Scan not found");
  });

  it("calculateSecurityMetrics computes correct scores", () => {
    const results = [
      { severity: "critical", category: "ssl" },
      { severity: "high", category: "headers" },
      { severity: "medium", category: "vulnerabilities" },
      { severity: "low", category: "content" },
      { severity: "info", category: "content" },
    ];

    const metrics = virtualReportService.calculateSecurityMetrics(results);

    expect(metrics.severityCounts.critical).toBe(1);
    expect(metrics.severityCounts.high).toBe(1);
    expect(metrics.severityCounts.medium).toBe(1);
    expect(metrics.severityCounts.low).toBe(1);
    expect(metrics.severityCounts.info).toBe(1);
    expect(metrics.totalFindings).toBe(5);
    expect(metrics.securityScore).toBeGreaterThanOrEqual(0);
    expect(metrics.securityScore).toBeLessThanOrEqual(100);
  });

  it("groupResultsByCategory organizes findings correctly", () => {
    const results = [
      { category: "ssl", severity: "high" },
      { category: "ssl", severity: "medium" },
      { category: "headers", severity: "low" },
    ];

    const grouped = virtualReportService.groupResultsByCategory(results);

    expect(grouped.ssl).toHaveLength(2);
    expect(grouped.headers).toHaveLength(1);
    expect(grouped.ssl[0].severity).toBe("high");
  });

  it("formatReportData creates complete report structure", () => {
    const scan = {
      id: "scan123",
      target_url: "https://example.com",
      status: "completed",
      created_at: "2025-01-01T00:00:00Z",
      results: [],
    };

    const metrics = {
      securityScore: 85,
      severityCounts: { critical: 0, high: 1, medium: 2, low: 1, info: 0 },
      totalFindings: 4,
      categoryScores: {
        ssl: 90,
        headers: 80,
        vulnerabilities: 85,
        content: 95,
      },
    };

    const report = virtualReportService.formatReportData(scan, metrics);

    expect(report.id).toBe("scan123");
    expect(report.security_score).toBe(85);
    expect(report.findings_summary.total).toBe(4);
    expect(report.category_scores).toEqual(metrics.categoryScores);
    expect(report.is_virtual).toBe(true);
  });
});
