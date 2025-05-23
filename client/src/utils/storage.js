// frontend/src/utils/storage.js

// Get access token
export const getToken = () => {
    return localStorage.getItem('accessToken');
  };
  
  // Get refresh token
  export const getRefreshToken = () => {
    return localStorage.getItem('refreshToken');
  };
  
  // Set tokens in storage
  export const setTokens = (accessToken, refreshToken) => {
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
  };
  
  // Clear tokens from storage
  export const clearTokens = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  };
  