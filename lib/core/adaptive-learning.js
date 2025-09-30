/**
 * Adaptive Learning Mode - Machine learning-inspired threat detection
 */

class AdaptiveLearning {
  constructor(config, anomalyScorer) {
    this.config = config;
    this.anomalyScorer = anomalyScorer;
    this.isLearning = config.adaptiveLearning || false;
    this.learningPeriod = config.learningPeriod || 7; // days
    this.startTime = new Date();
    this.endTime = new Date(this.startTime.getTime() + this.learningPeriod * 24 * 60 * 60 * 1000);
    
    // Learning data
    this.learningData = {
      requests: [],
      threats: [],
      patterns: new Map(),
      normalBehavior: {},
      anomalyThresholds: {},
      learningProgress: 0
    };
    
    // Learning phases
    this.phases = {
      COLLECTING: 'collecting',
      ANALYZING: 'analyzing',
      ADAPTING: 'adapting',
      PROTECTING: 'protecting'
    };
    
    this.currentPhase = this.isLearning ? this.phases.COLLECTING : this.phases.PROTECTING;
    
    // Start learning process
    if (this.isLearning) {
      this.startLearning();
    }
  }

  /**
   * Start the learning process
   */
  startLearning() {
    console.log('🎓 Starting adaptive learning mode...');
    console.log(`📅 Learning period: ${this.learningPeriod} days`);
    console.log(`⏰ Learning will complete at: ${this.endTime.toISOString()}`);
    
    // Set up phase transitions
    this.setupPhaseTransitions();
  }

  /**
   * Setup phase transitions
   */
  setupPhaseTransitions() {
    // Phase 1: Collecting (first 60% of learning period)
    const collectingEnd = new Date(this.startTime.getTime() + this.learningPeriod * 24 * 60 * 60 * 1000 * 0.6);
    
    setTimeout(() => {
      this.transitionToPhase(this.phases.ANALYZING);
    }, collectingEnd.getTime() - Date.now());
    
    // Phase 2: Analyzing (next 20% of learning period)
    const analyzingEnd = new Date(this.startTime.getTime() + this.learningPeriod * 24 * 60 * 60 * 1000 * 0.8);
    
    setTimeout(() => {
      this.transitionToPhase(this.phases.ADAPTING);
    }, analyzingEnd.getTime() - Date.now());
    
    // Phase 3: Adapting (final 20% of learning period)
    setTimeout(() => {
      this.transitionToPhase(this.phases.PROTECTING);
    }, this.endTime.getTime() - Date.now());
  }

  /**
   * Transition to a new phase
   */
  transitionToPhase(newPhase) {
    const oldPhase = this.currentPhase;
    this.currentPhase = newPhase;
    
    console.log(`🔄 Learning phase transition: ${oldPhase} → ${newPhase}`);
    
    switch (newPhase) {
      case this.phases.ANALYZING:
        this.analyzeCollectedData();
        break;
      case this.phases.ADAPTING:
        this.adaptRules();
        break;
      case this.phases.PROTECTING:
        this.finalizeLearning();
        break;
    }
  }

  /**
   * Process a request during learning
   */
  processRequest(analysis) {
    if (!this.isLearning) {
      return { action: 'allow', reason: 'Not in learning mode' };
    }
    
    // Record request data
    this.recordRequest(analysis);
    
    // Calculate learning progress
    this.updateLearningProgress();
    
    // In learning mode, always allow requests but record them
    return {
      action: 'allow',
      reason: 'Learning mode - collecting data',
      learningPhase: this.currentPhase,
      progress: this.learningData.learningProgress
    };
  }

  /**
   * Record request data for learning
   */
  recordRequest(analysis) {
    const requestData = {
      timestamp: analysis.timestamp,
      ip: analysis.ip,
      userAgent: analysis.userAgent,
      method: analysis.method,
      path: analysis.path,
      query: analysis.query,
      body: analysis.body,
      headers: analysis.headers,
      cookies: analysis.cookies,
      score: analysis.score,
      threats: analysis.threats,
      modules: analysis.modules
    };
    
    this.learningData.requests.push(requestData);
    
    // Keep only last 10000 requests to prevent memory issues
    if (this.learningData.requests.length > 10000) {
      this.learningData.requests = this.learningData.requests.slice(-10000);
    }
    
    // Record threats separately
    if (analysis.threats && analysis.threats.length > 0) {
      this.learningData.threats.push({
        timestamp: analysis.timestamp,
        ip: analysis.ip,
        threats: analysis.threats,
        score: analysis.score
      });
    }
  }

  /**
   * Analyze collected data
   */
  analyzeCollectedData() {
    console.log('🔍 Analyzing collected data...');
    
    const requests = this.learningData.requests;
    const threats = this.learningData.threats;
    
    // Analyze request patterns
    this.analyzeRequestPatterns(requests);
    
    // Analyze threat patterns
    this.analyzeThreatPatterns(threats);
    
    // Build normal behavior profile
    this.buildNormalBehaviorProfile(requests);
    
    // Calculate anomaly thresholds
    this.calculateAnomalyThresholds(requests);
    
    console.log('✅ Data analysis completed');
  }

  /**
   * Analyze request patterns
   */
  analyzeRequestPatterns(requests) {
    const patterns = {
      ipFrequency: new Map(),
      userAgentFrequency: new Map(),
      pathFrequency: new Map(),
      methodFrequency: new Map(),
      queryParamFrequency: new Map(),
      headerFrequency: new Map(),
      bodySizeDistribution: [],
      requestTimes: []
    };
    
    requests.forEach(req => {
      // IP frequency
      patterns.ipFrequency.set(req.ip, (patterns.ipFrequency.get(req.ip) || 0) + 1);
      
      // User-Agent frequency
      if (req.userAgent) {
        patterns.userAgentFrequency.set(req.userAgent, (patterns.userAgentFrequency.get(req.userAgent) || 0) + 1);
      }
      
      // Path frequency
      patterns.pathFrequency.set(req.path, (patterns.pathFrequency.get(req.path) || 0) + 1);
      
      // Method frequency
      patterns.methodFrequency.set(req.method, (patterns.methodFrequency.get(req.method) || 0) + 1);
      
      // Query parameter frequency
      if (req.query) {
        Object.keys(req.query).forEach(param => {
          patterns.queryParamFrequency.set(param, (patterns.queryParamFrequency.get(param) || 0) + 1);
        });
      }
      
      // Header frequency
      if (req.headers) {
        Object.keys(req.headers).forEach(header => {
          patterns.headerFrequency.set(header, (patterns.headerFrequency.get(header) || 0) + 1);
        });
      }
      
      // Body size distribution
      let bodySize = 0;
      if (typeof req.body === 'string') {
        bodySize = req.body.length;
      } else if (typeof req.body === 'object' && req.body !== null) {
        bodySize = JSON.stringify(req.body).length;
      }
      patterns.bodySizeDistribution.push(bodySize);
      
      // Request times
      patterns.requestTimes.push(req.timestamp.getHours());
    });
    
    this.learningData.patterns = patterns;
  }

  /**
   * Analyze threat patterns
   */
  analyzeThreatPatterns(threats) {
    const threatAnalysis = {
      byType: new Map(),
      byIP: new Map(),
      byPath: new Map(),
      byModule: new Map(),
      scoreDistribution: [],
      timeDistribution: []
    };
    
    threats.forEach(threat => {
      // By type
      threat.threats.forEach(t => {
        threatAnalysis.byType.set(t.type, (threatAnalysis.byType.get(t.type) || 0) + 1);
      });
      
      // By IP
      threatAnalysis.byIP.set(threat.ip, (threatAnalysis.byIP.get(threat.ip) || 0) + 1);
      
      // By path (if available)
      const request = this.learningData.requests.find(r => r.timestamp === threat.timestamp);
      if (request) {
        threatAnalysis.byPath.set(request.path, (threatAnalysis.byPath.get(request.path) || 0) + 1);
      }
      
      // Score distribution
      threatAnalysis.scoreDistribution.push(threat.score);
      
      // Time distribution
      threatAnalysis.timeDistribution.push(threat.timestamp.getHours());
    });
    
    this.learningData.threatAnalysis = threatAnalysis;
  }

  /**
   * Build normal behavior profile
   */
  buildNormalBehaviorProfile(requests) {
    const patterns = this.learningData.patterns;
    
    this.learningData.normalBehavior = {
      // IP behavior
      averageRequestsPerIP: this.calculateAverage(Array.from(patterns.ipFrequency.values())),
      maxRequestsPerIP: Math.max(...Array.from(patterns.ipFrequency.values())),
      uniqueIPs: patterns.ipFrequency.size,
      
      // User-Agent behavior
      commonUserAgents: this.getTopItems(patterns.userAgentFrequency, 10),
      uniqueUserAgents: patterns.userAgentFrequency.size,
      
      // Path behavior
      commonPaths: this.getTopItems(patterns.pathFrequency, 20),
      uniquePaths: patterns.pathFrequency.size,
      
      // Method behavior
      methodDistribution: Object.fromEntries(patterns.methodFrequency),
      
      // Query parameter behavior
      commonQueryParams: this.getTopItems(patterns.queryParamFrequency, 20),
      uniqueQueryParams: patterns.queryParamFrequency.size,
      
      // Header behavior
      commonHeaders: this.getTopItems(patterns.headerFrequency, 20),
      uniqueHeaders: patterns.headerFrequency.size,
      
      // Body size behavior
      averageBodySize: this.calculateAverage(patterns.bodySizeDistribution),
      maxBodySize: Math.max(...patterns.bodySizeDistribution),
      bodySizePercentiles: this.calculatePercentiles(patterns.bodySizeDistribution),
      
      // Time behavior
      peakHours: this.calculatePeakHours(patterns.requestTimes),
      requestTimeDistribution: this.calculateTimeDistribution(patterns.requestTimes)
    };
  }

  /**
   * Calculate anomaly thresholds
   */
  calculateAnomalyThresholds(requests) {
    const scores = requests.map(req => req.score).filter(score => score > 0);
    
    if (scores.length === 0) {
      this.learningData.anomalyThresholds = {
        low: 1,
        medium: 3,
        high: 5,
        critical: 10
      };
      return;
    }
    
    // Calculate percentiles
    const sortedScores = scores.sort((a, b) => a - b);
    const percentiles = this.calculatePercentiles(sortedScores);
    
    this.learningData.anomalyThresholds = {
      low: Math.max(1, Math.round(percentiles[50])), // 50th percentile
      medium: Math.max(3, Math.round(percentiles[75])), // 75th percentile
      high: Math.max(5, Math.round(percentiles[90])), // 90th percentile
      critical: Math.max(10, Math.round(percentiles[95])) // 95th percentile
    };
  }

  /**
   * Adapt rules based on learning
   */
  adaptRules() {
    console.log('🔧 Adapting rules based on learned patterns...');
    
    const adaptations = [];
    
    // Adapt thresholds based on learned behavior
    const normalBehavior = this.learningData.normalBehavior;
    const thresholds = this.learningData.anomalyThresholds;
    
    // Adjust IP frequency threshold
    if (normalBehavior.averageRequestsPerIP > 0) {
      const ipThreshold = Math.round(normalBehavior.averageRequestsPerIP * 3);
      adaptations.push({
        type: 'ip_frequency_threshold',
        value: ipThreshold,
        reason: `Based on average ${normalBehavior.averageRequestsPerIP.toFixed(2)} requests per IP`
      });
    }
    
    // Adjust body size threshold
    if (normalBehavior.averageBodySize > 0) {
      const bodySizeThreshold = Math.round(normalBehavior.averageBodySize * 2);
      adaptations.push({
        type: 'body_size_threshold',
        value: bodySizeThreshold,
        reason: `Based on average body size of ${normalBehavior.averageBodySize.toFixed(2)} bytes`
      });
    }
    
    // Create custom rules for common attack patterns
    const threatAnalysis = this.learningData.threatAnalysis;
    if (threatAnalysis.byType.size > 0) {
      for (const [type, count] of threatAnalysis.byType) {
        if (count > 5) { // If this threat type appeared more than 5 times
          adaptations.push({
            type: 'custom_rule',
            ruleType: type,
            count: count,
            reason: `Frequent threat type detected (${count} occurrences)`
          });
        }
      }
    }
    
    this.learningData.adaptations = adaptations;
    console.log(`✅ Applied ${adaptations.length} rule adaptations`);
  }

  /**
   * Finalize learning process
   */
  finalizeLearning() {
    console.log('🎯 Finalizing adaptive learning...');
    
    this.isLearning = false;
    this.learningData.learningProgress = 1.0;
    
    // Generate learning report
    const report = this.generateLearningReport();
    console.log('📊 Learning Report:', report);
    
    console.log('✅ Adaptive learning completed. WAF now in protection mode.');
  }

  /**
   * Generate learning report
   */
  generateLearningReport() {
    const requests = this.learningData.requests;
    const threats = this.learningData.threats;
    const normalBehavior = this.learningData.normalBehavior;
    const threatAnalysis = this.learningData.threatAnalysis;
    
    return {
      learningPeriod: {
        start: this.startTime.toISOString(),
        end: this.endTime.toISOString(),
        duration: this.learningPeriod
      },
      dataCollected: {
        totalRequests: requests.length,
        totalThreats: threats.length,
        uniqueIPs: normalBehavior.uniqueIPs,
        uniquePaths: normalBehavior.uniquePaths,
        uniqueUserAgents: normalBehavior.uniqueUserAgents
      },
      threatAnalysis: {
        threatTypes: Object.fromEntries(threatAnalysis.byType),
        topThreatIPs: this.getTopItems(threatAnalysis.byIP, 5),
        topThreatPaths: this.getTopItems(threatAnalysis.byPath, 5),
        averageThreatScore: this.calculateAverage(threatAnalysis.scoreDistribution)
      },
      normalBehavior: {
        averageRequestsPerIP: normalBehavior.averageRequestsPerIP,
        averageBodySize: normalBehavior.averageBodySize,
        peakHours: normalBehavior.peakHours,
        commonPaths: normalBehavior.commonPaths.slice(0, 5),
        commonUserAgents: normalBehavior.commonUserAgents.slice(0, 5)
      },
      anomalyThresholds: this.learningData.anomalyThresholds,
      adaptations: this.learningData.adaptations || []
    };
  }

  /**
   * Update learning progress
   */
  updateLearningProgress() {
    const now = Date.now();
    const totalDuration = this.endTime.getTime() - this.startTime.getTime();
    const elapsed = now - this.startTime.getTime();
    
    this.learningData.learningProgress = Math.min(elapsed / totalDuration, 1);
  }

  /**
   * Get learning status
   */
  getStatus() {
    return {
      isLearning: this.isLearning,
      currentPhase: this.currentPhase,
      progress: this.learningData.learningProgress,
      startTime: this.startTime,
      endTime: this.endTime,
      timeRemaining: Math.max(0, this.endTime.getTime() - Date.now()),
      dataCollected: {
        requests: this.learningData.requests.length,
        threats: this.learningData.threats.length
      }
    };
  }

  /**
   * Helper methods
   */
  calculateAverage(numbers) {
    if (numbers.length === 0) return 0;
    return numbers.reduce((sum, num) => sum + num, 0) / numbers.length;
  }

  calculatePercentiles(numbers) {
    if (numbers.length === 0) return {};
    
    const sorted = [...numbers].sort((a, b) => a - b);
    const percentiles = {};
    
    [10, 25, 50, 75, 90, 95, 99].forEach(p => {
      const index = Math.ceil((p / 100) * sorted.length) - 1;
      percentiles[p] = sorted[Math.max(0, index)];
    });
    
    return percentiles;
  }

  getTopItems(map, limit) {
    return Array.from(map.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, limit)
      .map(([key, value]) => ({ key, value }));
  }

  calculatePeakHours(hours) {
    const hourCounts = new Array(24).fill(0);
    hours.forEach(hour => hourCounts[hour]++);
    
    const maxCount = Math.max(...hourCounts);
    return hourCounts
      .map((count, hour) => ({ hour, count }))
      .filter(item => item.count >= maxCount * 0.8)
      .map(item => item.hour);
  }

  calculateTimeDistribution(hours) {
    const distribution = new Array(24).fill(0);
    hours.forEach(hour => distribution[hour]++);
    return distribution;
  }
}

module.exports = AdaptiveLearning;
