/**
 * WAF Middleware - Main Express middleware implementation
 */

const EventEmitter = require('events');
const AnomalyScorer = require('./anomaly-scorer');
const AdaptiveLearning = require('./adaptive-learning');
const PrometheusMetrics = require('./prometheus-metrics');
const APIManager = require('./api-manager');

class WAFMiddleware extends EventEmitter {
  constructor(config, ruleEngine, statsCollector, ruleManager) {
    super();
    this.config = config;
    this.ruleEngine = ruleEngine;
    this.statsCollector = statsCollector;
    this.ruleManager = ruleManager;
    
    // Initialize advanced features
    this.anomalyScorer = new AnomalyScorer(config);
    this.adaptiveLearning = new AdaptiveLearning(config, this.anomalyScorer);
    this.prometheusMetrics = new PrometheusMetrics(config);
    this.apiManager = new APIManager(config, ruleManager, statsCollector, this.adaptiveLearning);
    
    // Connect rule manager to rule engine
    this.ruleEngine.setRuleManager(ruleManager);
    
    this.isLearningMode = config.adaptiveLearning && this.adaptiveLearning.isLearning;
  }

  /**
   * Main middleware function
   */
  middleware() {
    return (req, res, next) => {
      try {
        // Skip WAF for certain paths
        if (this.shouldSkipPath(req.path)) {
          return next();
        }

        // Analyze request
        const analysis = this.analyzeRequest(req);
        
        // Update stats
        this.statsCollector.recordRequest(req, analysis);

        // Check if in learning mode
        if (this.isLearningMode) {
          this.handleLearningMode(req, analysis);
          return next();
        }

        // Apply rules and make decision
        const decision = this.ruleEngine.evaluate(analysis);
        
        if (decision.action === 'block') {
          if (this.config.dryRun) {
            // In dry run mode, log but don't block
            this.statsCollector.recordThreat(req, analysis, 'dry-run');
            this.emit('threat-detected', {
              type: 'dry-run',
              request: req,
              analysis
            });
            return next();
          } else {
            this.handleBlock(req, res, decision);
            return;
          }
        }

        // Request is safe, continue
        next();

      } catch (error) {
        this.emit('error', error);
        // In case of error, allow request to continue
        next();
      }
    };
  }

  /**
   * Analyze incoming request for threats
   */
  analyzeRequest(req) {
    const analysis = {
      timestamp: new Date(),
      ip: this.getClientIP(req),
      userAgent: req.get('User-Agent') || '',
      method: req.method,
      path: req.path,
      query: req.query,
      body: req.body,
      headers: req.headers,
      cookies: req.cookies || {},
      score: 0,
      threats: [],
      modules: []
    };

    // Run enabled modules
    this.config.modules.forEach(moduleName => {
      const module = this.ruleEngine.getModule(moduleName);
      if (module) {
        const moduleResult = module.analyze(analysis);
        if (moduleResult) {
          analysis.score += moduleResult.score;
          analysis.threats.push(...moduleResult.threats);
          analysis.modules.push(moduleName);
        }
      }
    });

    // Calculate anomaly score
    const anomalyResult = this.anomalyScorer.calculateScore(analysis);
    analysis.anomalyScore = anomalyResult.totalScore;
    analysis.anomalyFactors = anomalyResult.factors;
    analysis.isAnomaly = anomalyResult.isAnomaly;
    analysis.confidence = anomalyResult.confidence;

    // Add anomaly score to total score
    analysis.score += anomalyResult.totalScore;

    // Update baseline for learning
    this.anomalyScorer.updateBaseline(analysis);

    return analysis;
  }

  /**
   * Handle learning mode - log but don't block
   */
  handleLearningMode(req, analysis) {
    // Process through adaptive learning
    const learningResult = this.adaptiveLearning.processRequest(analysis);
    
    if (analysis.score > 0) {
      this.statsCollector.recordThreat(req, analysis, 'learning');
      this.emit('threat-detected', {
        type: 'learning',
        request: req,
        analysis,
        learningResult
      });
    }
    
    // Record learning metrics
    this.prometheusMetrics.recordLearning(
      learningResult.learningPhase || 'collecting',
      learningResult.progress || 0
    );
  }

  /**
   * Handle blocked request
   */
  handleBlock(req, res, decision) {
    this.statsCollector.recordThreat(req, decision.analysis, 'blocked');
    
    // Record metrics
    this.prometheusMetrics.recordBlock(decision.reason, decision.analysis.modules.join(','));
    this.prometheusMetrics.recordThreat('blocked', 'high', decision.analysis.score, decision.analysis.modules.join(','));
    
    this.emit('request-blocked', {
      request: req,
      decision
    });

    // Send block response
    res.status(403).json({
      error: 'Request blocked by WAF',
      reason: decision.reason,
      requestId: decision.requestId,
      score: decision.analysis.score,
      anomalyScore: decision.analysis.anomalyScore,
      threats: decision.analysis.threats.map(t => t.description),
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Check if we're in learning period
   */
  isInLearningPeriod() {
    if (!this.config.adaptiveLearning) return false;
    
    const learningDays = this.config.learningPeriod || 7;
    const startTime = this.config.startTime || new Date();
    const now = new Date();
    const daysSinceStart = (now - startTime) / (1000 * 60 * 60 * 24);
    
    return daysSinceStart < learningDays;
  }

  /**
   * Check if path should be skipped
   */
  shouldSkipPath(path) {
    const skipPaths = this.config.skipPaths || ['/health', '/metrics', '/favicon.ico'];
    return skipPaths.some(skipPath => path.startsWith(skipPath));
  }

  /**
   * Get client IP address
   */
  getClientIP(req) {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           'unknown';
  }

  /**
   * Stats endpoint middleware
   */
  stats() {
    return (req, res) => {
      const stats = this.statsCollector.getStats();
      const anomalyStats = this.anomalyScorer.getBaselineStats();
      const learningStatus = this.adaptiveLearning.getStatus();
      
      res.json({
        ...stats,
        anomaly: anomalyStats,
        learning: learningStatus
      });
    };
  }

  /**
   * Metrics endpoint middleware (Prometheus format)
   */
  metrics() {
    return (req, res) => {
      const metrics = this.prometheusMetrics.generatePrometheusOutput();
      res.set('Content-Type', 'text/plain');
      res.send(metrics);
    };
  }

  /**
   * Get API routes
   */
  getAPIRoutes() {
    return this.apiManager.createRoutes();
  }

  /**
   * Get API middleware
   */
  getAPIMiddleware() {
    return this.apiManager.apiMiddleware();
  }

  /**
   * Get anomaly scorer
   */
  getAnomalyScorer() {
    return this.anomalyScorer;
  }

  /**
   * Get adaptive learning
   */
  getAdaptiveLearning() {
    return this.adaptiveLearning;
  }

  /**
   * Get Prometheus metrics
   */
  getPrometheusMetrics() {
    return this.prometheusMetrics;
  }
}

module.exports = WAFMiddleware;
