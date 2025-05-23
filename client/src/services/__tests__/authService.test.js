// src/services/__tests__/authService.test.js
import { authService } from '../authService';
import api from '../api';
import * as storage from '../../utils/storage';

jest.mock('../api');
jest.mock('../../utils/storage');

beforeAll(() => {
  Object.defineProperty(window, 'localStorage', {
    value: {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn(),
    },
    writable: true
  });
});

describe('authService', () => {
  afterEach(() => jest.clearAllMocks());

  it('login stores tokens and user', async () => {
    const mockUser = { email: 'test@example.com' };
    api.post.mockResolvedValue({
      data: { access: 'abc', refresh: 'xyz', user: mockUser }
    });

    const result = await authService.login('test@example.com', 'password');
    expect(storage.setTokens).toHaveBeenCalledWith('abc', 'xyz');
    expect(window.localStorage.setItem).toHaveBeenCalledWith('user', JSON.stringify(mockUser));
    expect(result.success).toBe(true);
  });

  it('register calls the correct API', async () => {
    const userData = { email: 'test@example.com' };
    api.post.mockResolvedValue({ data: { id: 1 } });

    const res = await authService.register(userData);
    expect(api.post).toHaveBeenCalledWith('/auth/register/', userData);
    expect(res.success).toBe(true);
  });

  it('logout clears tokens and user', () => {
    authService.logout();
    expect(storage.clearTokens).toHaveBeenCalled();
    expect(window.localStorage.removeItem).toHaveBeenCalledWith('user');
  });

  it('getApiKeys fetches keys', async () => {
    api.get.mockResolvedValue({ data: ['key1'] });
    const result = await authService.getApiKeys();
    expect(result.success).toBe(true);
  });
});
