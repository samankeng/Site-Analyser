// src/services/__tests__/reportService.test.js
import api from "../api";
import { reportService } from "../reportService";
import { scanService } from "../scanService";

jest.mock("../api");
jest.mock("../scanService");

describe("reportService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("getReports fetches virtual reports", async () => {
    scanService.getScans.mockResolvedValue({
      success: true,
      data: { results: [{ id: 1, status: "completed", results: [] }] },
    });
    scanService.getScanResults.mockResolvedValue({
      success: true,
      data: { results: [{ severity: "medium", category: "ssl" }] },
    });

    const result = await reportService.getReports(true);
    expect(result.success).toBe(true);
    expect(result.data.length).toBeGreaterThan(0);
  });

  it("getVirtualReportById uses scanService to fetch details", async () => {
    scanService.getScanWithResults.mockResolvedValue({
      success: true,
      data: {
        id: 1,
        status: "completed",
        results: [{ severity: "medium", category: "ssl" }],
      },
    });

    const result = await reportService.getVirtualReportById(1);
    expect(result.success).toBe(true);
    expect(result.data.id).toBe(1);
  });

  it("convertScanToReport produces a valid report object", () => {
    const report = reportService.convertScanToReport({
      id: 1,
      status: "completed",
      results: [
        { severity: "high", category: "SSL" },
        { severity: "low", category: "headers" },
      ],
    });

    expect(report.id).toBe(1);
    expect(report.security_score).toBeDefined();
    expect(report.findings_summary.total).toBe(2);
  });

  it("generatePdf calls API with correct endpoint", async () => {
    // Mock the API call
    api.get.mockResolvedValue({
      data: new Blob(["PDF"]),
      headers: { "content-disposition": 'attachment; filename="report.pdf"' },
    });

    // Mock DOM methods to avoid errors
    const mockLink = {
      href: "",
      download: "",
      click: jest.fn(),
      setAttribute: jest.fn(),
      parentNode: { removeChild: jest.fn() },
    };

    const createElementSpy = jest
      .spyOn(document, "createElement")
      .mockImplementation((tag) => {
        if (tag === "a") return mockLink;
        return { appendChild: jest.fn(), removeChild: jest.fn() };
      });

    const appendChildSpy = jest
      .spyOn(document.body, "appendChild")
      .mockImplementation(() => {});
    const removeChildSpy = jest
      .spyOn(document.body, "removeChild")
      .mockImplementation(() => {});

    // Mock URL methods
    global.URL.createObjectURL = jest.fn(() => "blob:url");
    global.URL.revokeObjectURL = jest.fn();

    const result = await reportService.generatePdf("123", true);

    expect(api.get).toHaveBeenCalledWith("scanner/scans/123/pdf/", {
      responseType: "blob",
    });
    expect(result.success).toBe(true);

    // Cleanup mocks
    createElementSpy.mockRestore();
    appendChildSpy.mockRestore();
    removeChildSpy.mockRestore();
  });
});
