/**
 * Advanced Anomaly Scoring System
 * Implements machine learning-inspired scoring algorithms
 */

class AnomalyScorer {
  constructor(config) {
    this.config = config;
    this.baseline = {
      requestFrequency: new Map(), // IP -> { count, window }
      userAgentPatterns: new Map(), // User-Agent -> frequency
      pathPatterns: new Map(), // Path -> frequency
      queryPatterns: new Map(), // Query param -> frequency
      bodySizePatterns: new Map(), // Body size -> frequency
      headerPatterns: new Map() // Header patterns -> frequency
    };
    this.learningPeriod = config.learningPeriod || 7; // days
    this.isLearning = true;
    this.startTime = new Date();
    this.updateInterval = 60000; // 1 minute
    this.lastUpdate = new Date();
    
    // Start learning process
    this.startLearning();
  }

  /**
   * Start the learning process
   */
  startLearning() {
    if (this.config.adaptiveLearning) {
      // Set learning mode for specified period
      setTimeout(() => {
        this.isLearning = false;
        this.finalizeBaseline();
        console.log('🎓 Adaptive learning completed. WAF now in protection mode.');
      }, this.learningPeriod * 24 * 60 * 60 * 1000);
    }
  }

  /**
   * Calculate anomaly score for a request
   */
  calculateScore(analysis) {
    // Skip anomaly scoring if threshold is very high (test mode)
    if (this.config.anomalyThreshold > 100) {
      return {
        totalScore: 0,
        factors: [],
        isAnomaly: false,
        confidence: 0
      };
    }
    
    let totalScore = 0;
    const factors = [];

    // 1. Request frequency anomaly
    const frequencyScore = this.calculateFrequencyAnomaly(analysis);
    if (frequencyScore > 0) {
      totalScore += frequencyScore;
      factors.push({ type: 'frequency', score: frequencyScore });
    }

    // 2. User-Agent anomaly
    const userAgentScore = this.calculateUserAgentAnomaly(analysis);
    if (userAgentScore > 0) {
      totalScore += userAgentScore;
      factors.push({ type: 'userAgent', score: userAgentScore });
    }

    // 3. Path anomaly
    const pathScore = this.calculatePathAnomaly(analysis);
    if (pathScore > 0) {
      totalScore += pathScore;
      factors.push({ type: 'path', score: pathScore });
    }

    // 4. Query parameter anomaly
    const queryScore = this.calculateQueryAnomaly(analysis);
    if (queryScore > 0) {
      totalScore += queryScore;
      factors.push({ type: 'query', score: queryScore });
    }

    // 5. Body size anomaly
    const bodySizeScore = this.calculateBodySizeAnomaly(analysis);
    if (bodySizeScore > 0) {
      totalScore += bodySizeScore;
      factors.push({ type: 'bodySize', score: bodySizeScore });
    }

    // 6. Header anomaly
    const headerScore = this.calculateHeaderAnomaly(analysis);
    if (headerScore > 0) {
      totalScore += headerScore;
      factors.push({ type: 'header', score: headerScore });
    }

    // 7. Time-based anomaly
    const timeScore = this.calculateTimeAnomaly(analysis);
    if (timeScore > 0) {
      totalScore += timeScore;
      factors.push({ type: 'time', score: timeScore });
    }

    // 8. Geographic anomaly (if IP geolocation available)
    const geoScore = this.calculateGeographicAnomaly(analysis);
    if (geoScore > 0) {
      totalScore += geoScore;
      factors.push({ type: 'geographic', score: geoScore });
    }

    return {
      totalScore: Math.round(totalScore * 100) / 100,
      factors: factors,
      isAnomaly: totalScore > this.config.anomalyThreshold || 5,
      confidence: this.calculateConfidence(factors)
    };
  }

  /**
   * Calculate request frequency anomaly
   */
  calculateFrequencyAnomaly(analysis) {
    const ip = analysis.ip;
    const now = Date.now();
    const windowMs = 5 * 60 * 1000; // 5 minutes

    if (!this.baseline.requestFrequency.has(ip)) {
      this.baseline.requestFrequency.set(ip, { count: 0, window: now });
    }

    const ipData = this.baseline.requestFrequency.get(ip);
    
    // Reset window if expired
    if (now - ipData.window > windowMs) {
      ipData.count = 0;
      ipData.window = now;
    }

    ipData.count++;

    // Calculate anomaly score
    const avgRequestsPerWindow = this.calculateAverageRequestsPerWindow();
    const expectedMax = avgRequestsPerWindow * 2; // 2x average is suspicious
    
    if (ipData.count > expectedMax) {
      const excess = ipData.count - expectedMax;
      return Math.min(excess * 0.5, 10); // Cap at 10 points
    }

    return 0;
  }

  /**
   * Calculate User-Agent anomaly
   */
  calculateUserAgentAnomaly(analysis) {
    const userAgent = analysis.userAgent;
    
    if (!userAgent || userAgent.length < 10) {
      return 3; // Suspicious: no or very short User-Agent
    }

    // Check for common bot patterns
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java/i,
      /postman/i, /insomnia/i
    ];

    const isBot = botPatterns.some(pattern => pattern.test(userAgent));
    if (isBot && !this.isKnownBot(userAgent)) {
      return 2; // Unknown bot
    }

    // Check for unusual patterns
    if (userAgent.length > 500) {
      return 4; // Suspiciously long User-Agent
    }

    // Check against baseline
    const frequency = this.baseline.userAgentPatterns.get(userAgent) || 0;
    const totalRequests = Array.from(this.baseline.userAgentPatterns.values())
      .reduce((sum, count) => sum + count, 0);
    
    if (totalRequests > 0) {
      const frequencyRatio = frequency / totalRequests;
      if (frequencyRatio < 0.01) { // Less than 1% of requests
        return 1; // Unusual User-Agent
      }
    }

    return 0;
  }

  /**
   * Calculate path anomaly
   */
  calculatePathAnomaly(analysis) {
    const path = analysis.path;
    
    // Check for suspicious path patterns
    const suspiciousPatterns = [
      /\.\./, // Directory traversal
      /\/admin/, /\/wp-admin/, /\/phpmyadmin/, // Admin panels
      /\.env/, /\.git/, /\.svn/, // Sensitive files
      /\/api\/v\d+\/.*\/.*\/.*/, // Deep API nesting
      /\/[a-f0-9]{32,}/, // Long hashes
      /\/[A-Za-z0-9+/]{20,}={0,2}/ // Base64-like strings
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(path)) {
        return 2;
      }
    }

    // Check path length
    if (path.length > 200) {
      return 1;
    }

    // Check against baseline
    const frequency = this.baseline.pathPatterns.get(path) || 0;
    const totalRequests = Array.from(this.baseline.pathPatterns.values())
      .reduce((sum, count) => sum + count, 0);
    
    if (totalRequests > 0) {
      const frequencyRatio = frequency / totalRequests;
      if (frequencyRatio < 0.005) { // Less than 0.5% of requests
        return 1; // Unusual path
      }
    }

    return 0;
  }

  /**
   * Calculate query parameter anomaly
   */
  calculateQueryAnomaly(analysis) {
    const query = analysis.query;
    let score = 0;

    if (!query || Object.keys(query).length === 0) {
      return 0;
    }

    // Check for suspicious parameter names
    const suspiciousParams = [
      'cmd', 'exec', 'eval', 'system', 'shell',
      'file', 'path', 'dir', 'root', 'admin',
      'password', 'passwd', 'pwd', 'secret',
      'token', 'key', 'auth', 'login'
    ];

    for (const [key, value] of Object.entries(query)) {
      // Check parameter name
      if (suspiciousParams.some(param => key.toLowerCase().includes(param))) {
        score += 2;
      }

      // Check parameter value length
      if (typeof value === 'string' && value.length > 1000) {
        score += 1;
      }

      // Check for encoded content
      if (typeof value === 'string' && this.isEncoded(value)) {
        score += 1;
      }
    }

    return Math.min(score, 5);
  }

  /**
   * Calculate body size anomaly
   */
  calculateBodySizeAnomaly(analysis) {
    const body = analysis.body;
    let bodySize = 0;

    if (typeof body === 'string') {
      bodySize = body.length;
    } else if (typeof body === 'object' && body !== null) {
      bodySize = JSON.stringify(body).length;
    }

    // Check against baseline
    const avgBodySize = this.calculateAverageBodySize();
    const maxBodySize = avgBodySize * 3; // 3x average is suspicious

    if (bodySize > maxBodySize) {
      const excess = bodySize - maxBodySize;
      return Math.min(excess / 1000, 5); // 1 point per 1KB excess, cap at 5
    }

    return 0;
  }

  /**
   * Calculate header anomaly
   */
  calculateHeaderAnomaly(analysis) {
    const headers = analysis.headers;
    let score = 0;

    // Check for missing common headers
    const commonHeaders = ['user-agent', 'accept', 'accept-language'];
    const missingHeaders = commonHeaders.filter(header => !headers[header]);
    
    if (missingHeaders.length > 1) {
      score += 2; // Missing multiple common headers
    }

    // Check for suspicious header values
    for (const [key, value] of Object.entries(headers)) {
      if (typeof value === 'string') {
        // Check for suspicious patterns in header values
        if (value.length > 500) {
          score += 1; // Unusually long header value
        }
        
        if (this.isEncoded(value) && value.length > 100) {
          score += 1; // Encoded content in header
        }
      }
    }

    return Math.min(score, 3);
  }

  /**
   * Calculate time-based anomaly
   */
  calculateTimeAnomaly(analysis) {
    const now = new Date();
    const hour = now.getHours();
    
    // Check for requests at unusual hours (2 AM - 6 AM)
    if (hour >= 2 && hour <= 6) {
      return 1;
    }

    // Check for requests on weekends (if business hours expected)
    const dayOfWeek = now.getDay();
    if (dayOfWeek === 0 || dayOfWeek === 6) {
      return 0.5;
    }

    return 0;
  }

  /**
   * Calculate geographic anomaly
   */
  calculateGeographicAnomaly(analysis) {
    // This would require IP geolocation service
    // For now, return 0
    return 0;
  }

  /**
   * Calculate confidence score
   */
  calculateConfidence(factors) {
    if (factors.length === 0) return 0;
    
    const totalScore = factors.reduce((sum, factor) => sum + factor.score, 0);
    const factorCount = factors.length;
    
    // Higher confidence with more factors and higher scores
    return Math.min((totalScore / factorCount) * 0.1, 1);
  }

  /**
   * Update baseline with new request data
   */
  updateBaseline(analysis) {
    if (!this.isLearning) return;

    const ip = analysis.ip;
    const userAgent = analysis.userAgent;
    const path = analysis.path;
    const query = analysis.query;
    const body = analysis.body;

    // Update request frequency
    if (!this.baseline.requestFrequency.has(ip)) {
      this.baseline.requestFrequency.set(ip, { count: 0, window: Date.now() });
    }
    this.baseline.requestFrequency.get(ip).count++;

    // Update User-Agent patterns
    if (userAgent) {
      const current = this.baseline.userAgentPatterns.get(userAgent) || 0;
      this.baseline.userAgentPatterns.set(userAgent, current + 1);
    }

    // Update path patterns
    const currentPath = this.baseline.pathPatterns.get(path) || 0;
    this.baseline.pathPatterns.set(path, currentPath + 1);

    // Update query patterns
    if (query) {
      for (const key of Object.keys(query)) {
        const current = this.baseline.queryPatterns.get(key) || 0;
        this.baseline.queryPatterns.set(key, current + 1);
      }
    }

    // Update body size patterns
    let bodySize = 0;
    if (typeof body === 'string') {
      bodySize = body.length;
    } else if (typeof body === 'object' && body !== null) {
      bodySize = JSON.stringify(body).length;
    }
    
    if (bodySize > 0) {
      const current = this.baseline.bodySizePatterns.get(bodySize) || 0;
      this.baseline.bodySizePatterns.set(bodySize, current + 1);
    }
  }

  /**
   * Finalize baseline after learning period
   */
  finalizeBaseline() {
    console.log('📊 Finalizing anomaly detection baseline...');
    
    // Calculate averages and thresholds
    this.baseline.averageRequestsPerWindow = this.calculateAverageRequestsPerWindow();
    this.baseline.averageBodySize = this.calculateAverageBodySize();
    this.baseline.commonUserAgents = this.getTopUserAgents(10);
    this.baseline.commonPaths = this.getTopPaths(20);
    
    console.log('✅ Anomaly detection baseline finalized');
  }

  /**
   * Helper methods
   */
  calculateAverageRequestsPerWindow() {
    const totalRequests = Array.from(this.baseline.requestFrequency.values())
      .reduce((sum, data) => sum + data.count, 0);
    const uniqueIPs = this.baseline.requestFrequency.size;
    return uniqueIPs > 0 ? totalRequests / uniqueIPs : 0;
  }

  calculateAverageBodySize() {
    const sizes = Array.from(this.baseline.bodySizePatterns.keys());
    const totalCount = Array.from(this.baseline.bodySizePatterns.values())
      .reduce((sum, count) => sum + count, 0);
    
    if (totalCount === 0) return 0;
    
    const weightedSum = sizes.reduce((sum, size) => {
      const count = this.baseline.bodySizePatterns.get(size);
      return sum + (size * count);
    }, 0);
    
    return weightedSum / totalCount;
  }

  getTopUserAgents(limit) {
    return Array.from(this.baseline.userAgentPatterns.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, limit)
      .map(([ua]) => ua);
  }

  getTopPaths(limit) {
    return Array.from(this.baseline.pathPatterns.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, limit)
      .map(([path]) => path);
  }

  isKnownBot(userAgent) {
    const knownBots = [
      'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot',
      'Baiduspider', 'YandexBot', 'facebookexternalhit'
    ];
    
    return knownBots.some(bot => userAgent.includes(bot));
  }

  isEncoded(str) {
    // Check for common encoding patterns
    return /^[A-Za-z0-9+/]+={0,2}$/.test(str) || // Base64
           /%[0-9a-fA-F]{2}/.test(str) || // URL encoded
           /&#x?[0-9a-fA-F]+;/.test(str); // HTML encoded
  }

  /**
   * Get baseline statistics
   */
  getBaselineStats() {
    return {
      isLearning: this.isLearning,
      learningProgress: this.isLearning ? 
        Math.min((Date.now() - this.startTime.getTime()) / (this.learningPeriod * 24 * 60 * 60 * 1000), 1) : 1,
      totalIPs: this.baseline.requestFrequency.size,
      totalUserAgents: this.baseline.userAgentPatterns.size,
      totalPaths: this.baseline.pathPatterns.size,
      averageRequestsPerWindow: this.calculateAverageRequestsPerWindow(),
      averageBodySize: this.calculateAverageBodySize(),
      commonUserAgents: this.getTopUserAgents(5),
      commonPaths: this.getTopPaths(10)
    };
  }
}

module.exports = AnomalyScorer;
