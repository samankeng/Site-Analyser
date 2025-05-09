// src/services/__tests__/reportService.test.js
import { reportService } from '../reportService';
import { scanService } from '../scanService';
import api from '../api';

jest.mock('../api');
jest.mock('../scanService');

global.URL.createObjectURL = jest.fn(() => 'blob:url');
document.createElement = jest.fn(() => ({
  click: jest.fn(),
  setAttribute: jest.fn(),
  style: {},
  href: '',
  remove: jest.fn(),
}));

describe('reportService', () => {
  afterEach(() => jest.clearAllMocks());

  it('getReports fetches virtual reports', async () => {
    scanService.getScans.mockResolvedValue({
      success: true,
      data: { results: [{ id: 1, status: 'completed', results: [] }] }
    });
    scanService.getScanResults.mockResolvedValue({
      success: true,
      data: { results: [{ severity: 'medium', category: 'ssl' }] }
    });

    const result = await reportService.getReports(true);
    expect(result.success).toBe(true);
    expect(result.data.length).toBeGreaterThan(0);
  });

  it('getVirtualReportById uses scanService to fetch details', async () => {
    scanService.getScanWithResults.mockResolvedValue({
      success: true,
      data: { id: 1, status: 'completed', results: [{ severity: 'medium', category: 'ssl' }] }
    });

    const result = await reportService.getVirtualReportById(1);
    expect(result.success).toBe(true);
    expect(result.data.id).toBe(1);
  });

  it('convertScanToReport produces a valid report object', () => {
    const report = reportService.convertScanToReport({
      id: 1,
      status: 'completed',
      results: [
        { severity: 'high', category: 'SSL' },
        { severity: 'low', category: 'headers' },
      ]
    });

    expect(report.id).toBe(1);
    expect(report.security_score).toBeDefined();
    expect(report.findings_summary.total).toBe(2);
  });

  it('generatePdf triggers correct endpoint', async () => {
    api.get.mockResolvedValue({
      data: new Blob(['PDF']),
      headers: { 'content-disposition': 'filename="report.pdf"' }
    });

    const result = await reportService.generatePdf('123', true);
    expect(api.get).toHaveBeenCalledWith('scanner/scans/123/pdf/', { responseType: 'blob' });
    expect(result.success).toBe(true);
  });
});
