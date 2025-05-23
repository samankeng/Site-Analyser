// frontend/src/config/appConfig.js

/**
 * Application-wide configuration settings
 */
const appConfig = {
    // Report configuration
    reports: {
      // Whether to use virtual reports (generated from scans) by default
      // Set to false to use real persisted reports instead
      useVirtualReports: true,
      
      // PDF generation settings
      pdf: {
        defaultOptions: {
          includeDetails: true,
          includeRecommendations: true,
          includeScreenshots: true
        }
      }
    },
    
    // API configuration
    api: {
      // Base API URL - can be overridden by environment variable
      baseUrl: process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1/'
    },
    
    // Dashboard configuration
    dashboard: {
      // Auto-refresh interval in milliseconds (0 to disable)
      refreshInterval: 60000, // 1 minute
      
      // Default metrics display
      defaultMetrics: {
        showScoreCard: true,
        showVulnerabilityChart: true,
        showAnomalyDetection: true
      }
    },
    
    // Security scoring configuration
    security: {
      // Severity weights for security score calculation
      severityWeights: {
        critical: 20,
        high: 10,
        medium: 5,
        low: 2,
        info: 0
      },
      
      // Score thresholds for rating
      scoreThresholds: {
        verySecure: 90,
        secure: 80,
        moderatelySecure: 70,
        needsImprovement: 60,
        insecure: 40
      }
    }
  };
  
  export default appConfig;