/**
 * Advanced Express server with Node-WAF v0.3 features
 * Demonstrates all new features including adaptive learning, API management, and Prometheus metrics
 */

const express = require('express');
const waf = require('../lib/index');

const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize WAF with advanced configuration
const wafMiddleware = waf({
  // Core settings
  enabled: true,
  dryRun: false,
  threshold: 5,
  
  // Modules
  modules: ['xss', 'sqli', 'ratelimit'],
  
  // Adaptive learning
  adaptiveLearning: true,
  learningPeriod: 7, // 7 days
  anomalyThreshold: 5,
  
  // Rate limiting
  rateLimit: {
    enabled: true,
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // requests per window
  },
  
  // IP blocking
  ipBlocking: {
    enabled: true,
    blockDuration: 24 * 60 * 60 * 1000, // 24 hours
    maxViolations: 5
  },
  
  // Community rules
  communityRules: true,
  autoUpdate: true,
  updateInterval: 24 * 60 * 60 * 1000, // 24 hours
  
  // API management
  apiKey: process.env.WAF_API_KEY || 'demo-api-key',
  maxLogs: 10000,
  
  // Stats
  stats: {
    enabled: true,
    retentionDays: 30
  }
});

// Apply WAF middleware
app.use(wafMiddleware.middleware());

// Add event listeners for WAF events
wafMiddleware.on('threat-detected', (data) => {
  console.log('🚨 Threat detected:', {
    type: data.type,
    ip: data.request.ip,
    path: data.request.path,
    score: data.analysis.score,
    anomalyScore: data.analysis.anomalyScore,
    threats: data.analysis.threats.map(t => t.description),
    learningPhase: data.learningResult?.learningPhase
  });
});

wafMiddleware.on('request-blocked', (data) => {
  console.log('🛡️ Request blocked:', {
    ip: data.request.ip,
    path: data.request.path,
    reason: data.decision.reason,
    score: data.decision.score,
    anomalyScore: data.decision.analysis.anomalyScore
  });
});

wafMiddleware.on('error', (error) => {
  console.error('❌ WAF Error:', error.message);
});

// API Management Routes
const apiRoutes = wafMiddleware.getAPIRoutes();
const apiMiddleware = wafMiddleware.getAPIMiddleware();

// Apply API middleware to all API routes
app.use('/waf', apiMiddleware);

// Register API routes manually
app.get('/waf/config', apiRoutes['GET /waf/config']);
app.put('/waf/config', apiRoutes['PUT /waf/config']);
app.get('/waf/rules', apiRoutes['GET /waf/rules']);
app.post('/waf/rules', apiRoutes['POST /waf/rules']);
app.get('/waf/stats', apiRoutes['GET /waf/stats']);
app.get('/waf/logs', apiRoutes['GET /waf/logs']);
app.get('/waf/learning', apiRoutes['GET /waf/learning']);
app.get('/waf/health', apiRoutes['GET /waf/health']);
app.get('/waf/metrics', apiRoutes['GET /waf/metrics']);

// Override stats endpoint to use WAF's built-in stats
app.get('/waf/stats', wafMiddleware.stats());
app.get('/waf/metrics', wafMiddleware.metrics());

// Basic routes
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Node-WAF Advanced Demo Server',
    timestamp: new Date().toISOString(),
    waf: {
      version: waf.version,
      status: 'active',
      features: {
        adaptiveLearning: true,
        anomalyDetection: true,
        prometheusMetrics: true,
        apiManagement: true,
        communityRules: true
      }
    }
  });
});

app.get('/api/users', (req, res) => {
  res.json({
    users: [
      { id: 1, name: 'John Doe', email: 'john@example.com' },
      { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
    ]
  });
});

app.post('/api/users', (req, res) => {
  const { name, email } = req.body;
  
  if (!name || !email) {
    return res.status(400).json({
      error: 'Name and email are required'
    });
  }
  
  res.json({
    message: 'User created successfully',
    user: { name, email }
  });
});

app.get('/api/search', (req, res) => {
  const { q } = req.query;
  
  if (!q) {
    return res.status(400).json({
      error: 'Query parameter "q" is required'
    });
  }
  
  res.json({
    query: q,
    results: [
      { id: 1, title: `Result for "${q}"`, content: 'Sample content' }
    ]
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    waf: {
      learning: wafMiddleware.getAdaptiveLearning().getStatus(),
      anomaly: wafMiddleware.getAnomalyScorer().getBaselineStats()
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({
    error: 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Advanced Server running on http://localhost:${PORT}`);
  console.log(`📊 WAF Stats: http://localhost:${PORT}/waf/stats`);
  console.log(`📈 Prometheus Metrics: http://localhost:${PORT}/waf/metrics`);
  console.log(`🔧 WAF Config: http://localhost:${PORT}/waf/config`);
  console.log(`📋 WAF Rules: http://localhost:${PORT}/waf/rules`);
  console.log(`📝 WAF Logs: http://localhost:${PORT}/waf/logs`);
  console.log(`🎓 Learning Status: http://localhost:${PORT}/waf/learning`);
  console.log(`❤️ Health: http://localhost:${PORT}/health`);
  console.log('');
  console.log('🔑 API Key (for protected endpoints): demo-api-key');
  console.log('');
  console.log('Test the WAF with these URLs:');
  console.log(`- XSS: http://localhost:${PORT}/api/search?q=<script>alert('xss')</script>`);
  console.log(`- SQLi: http://localhost:${PORT}/api/search?q=1' OR 1=1--`);
  console.log(`- Normal: http://localhost:${PORT}/api/search?q=hello`);
  console.log('');
  console.log('🎓 Adaptive Learning Features:');
  console.log('- Learning mode is active for 7 days');
  console.log('- Anomaly detection learns normal behavior patterns');
  console.log('- Rules adapt based on learned patterns');
  console.log('- Check learning status at /waf/learning');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down gracefully...');
  process.exit(0);
});

module.exports = app;
