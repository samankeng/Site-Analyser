// src/services/__tests__/scanService.test.js

import { scanService } from '../scanService';
import api from '../api';

jest.mock('../api');

describe('scanService', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('getScans returns data on success', async () => {
    const mockData = { results: [{ id: 1 }] };
    api.get.mockResolvedValue({ data: mockData });

    const response = await scanService.getScans();
    expect(api.get).toHaveBeenCalledWith('/scanner/scans/?page=1');
    expect(response).toEqual({ success: true, data: mockData });
  });

  it('createScan sends scan data and returns success', async () => {
    const scanData = { target_url: 'https://example.com', scan_types: ['ssl'] };
    const mockResponse = { id: 'abc123' };
    api.post.mockResolvedValue({ data: mockResponse });

    const response = await scanService.createScan(scanData);
    expect(api.post).toHaveBeenCalledWith('/scanner/scans/', scanData);
    expect(response.success).toBe(true);
    expect(response.data).toEqual(mockResponse);
  });

  it('deleteScan returns success if deleted', async () => {
    api.delete.mockResolvedValue({ data: {} });

    const response = await scanService.deleteScan(1);
    expect(api.delete).toHaveBeenCalledWith('/scanner/scans/1/');
    expect(response.success).toBe(true);
  });

  it('getScanWithResults fetches both scan and results', async () => {
    const scan = { id: 1, name: 'Test Scan' };
    const results = { results: [{ id: 'r1' }] };

    api.get
      .mockResolvedValueOnce({ data: scan }) // for scan
      .mockResolvedValueOnce({ data: results }); // for results

    const response = await scanService.getScanWithResults(1);
    expect(api.get).toHaveBeenCalledWith('/scanner/scans/1/');
    expect(api.get).toHaveBeenCalledWith('/scanner/scans/1/results/');
    expect(response.success).toBe(true);
    expect(response.data).toBeDefined();
  });

  it('returns error if API fails', async () => {
    api.get.mockRejectedValue({ response: { data: 'Server error' } });

    const response = await scanService.getScans();
    expect(response.success).toBe(false);
    expect(response.error).toBe('Server error');
  });
});
