// src/services/__tests__/aiService.test.js

import { aiService } from '../aiService';
import api from '../api';

jest.mock('../api');

describe('aiService', () => {
  afterEach(() => jest.clearAllMocks());

  it('analyzeScan sends scanId and returns result', async () => {
    api.post.mockResolvedValue({ data: { analysis_id: 'abc123' } });

    const response = await aiService.analyzeScan('scan123');
    expect(api.post).toHaveBeenCalledWith('/ai-analyzer/analyses/analyze/', { scan_id: 'scan123' });
    expect(response.success).toBe(true);
  });

  it('returns error for invalid scanId in analyzeScan', async () => {
    const response = await aiService.analyzeScan(undefined);
    expect(response.success).toBe(false);
    expect(response.error).toBe('Invalid scan ID');
  });

  it('getAnalysesForScan returns list', async () => {
    api.get.mockResolvedValue({ data: { results: [{ id: 'a1' }] } });

    const response = await aiService.getAnalysesForScan('scan123');
    expect(api.get).toHaveBeenCalledWith('/ai-analyzer/analyses/for_scan/?scan_id=scan123');
    expect(response.data.length).toBeGreaterThan(0);
  });

  it('getRecommendationsForAnalysis returns list', async () => {
    api.get.mockResolvedValue({ data: { results: [{ id: 'r1' }] } });

    const response = await aiService.getRecommendationsForAnalysis('analysis123');
    expect(api.get).toHaveBeenCalledWith('/ai-analyzer/recommendations/for_analysis/?analysis_id=analysis123');
    expect(response.success).toBe(true);
  });
});
