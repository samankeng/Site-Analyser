// src/services/__tests__/scanReportService.test.js
import api from "../api";
import { scanReportService } from "../scanReportService";

jest.mock("../api");

describe("scanReportService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("getReportForScan fetches report successfully", async () => {
    const mockReport = {
      id: "report123",
      scan_id: "scan123",
      security_score: 85,
      findings_summary: { critical: 0, high: 2, medium: 5, low: 3 },
    };

    api.get.mockResolvedValue({ data: mockReport });

    const result = await scanReportService.getReportForScan("scan123");

    expect(api.get).toHaveBeenCalledWith("/scanner/scans/scan123/report/");
    expect(result.success).toBe(true);
    expect(result.data).toEqual(mockReport);
  });

  it("handles error when report not found", async () => {
    api.get.mockRejectedValue({
      response: { status: 404, data: { detail: "Report not found" } },
    });

    const result = await scanReportService.getReportForScan("scan123");

    expect(result.success).toBe(false);
    expect(result.error).toContain("Report not found");
  });

  it("createReportFromScan creates new report", async () => {
    const mockReport = {
      id: "report123",
      scan_id: "scan123",
      status: "completed",
    };

    api.post.mockResolvedValue({ data: mockReport });

    const result = await scanReportService.createReportFromScan("scan123");

    expect(api.post).toHaveBeenCalledWith(
      "/scanner/scans/scan123/create-report/"
    );
    expect(result.success).toBe(true);
    expect(result.data).toEqual(mockReport);
  });

  it("handles network errors gracefully", async () => {
    api.get.mockRejectedValue(new Error("Network Error"));

    const result = await scanReportService.getReportForScan("scan123");

    expect(result.success).toBe(false);
    expect(result.error).toBe("Network Error");
  });
});
