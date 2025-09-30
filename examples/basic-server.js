/**
 * Basic Express server with Node-WAF
 * Example usage of the WAF middleware
 */

const express = require('express');
const waf = require('../lib/index');

const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize WAF with basic configuration
const wafMiddleware = waf({
  modules: ['xss', 'sqli', 'ratelimit'],
  threshold: 5,
  dryRun: false,
  adaptiveLearning: false,
  rateLimit: {
    enabled: true,
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // requests per window
  },
  ipBlocking: {
    enabled: true,
    blockDuration: 24 * 60 * 60 * 1000, // 24 hours
    maxViolations: 5
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
    threats: data.analysis.threats.map(t => t.description)
  });
});

wafMiddleware.on('request-blocked', (data) => {
  console.log('🛡️ Request blocked:', {
    ip: data.request.ip,
    path: data.request.path,
    reason: data.decision.reason,
    score: data.decision.score
  });
});

wafMiddleware.on('error', (error) => {
  console.error('❌ WAF Error:', error.message);
});

// Basic routes
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Node-WAF Demo Server',
    timestamp: new Date().toISOString(),
    waf: {
      version: waf.version,
      status: 'active'
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

// WAF stats endpoint
app.get('/waf/stats', wafMiddleware.stats());

// WAF metrics endpoint (Prometheus format)
app.get('/metrics', wafMiddleware.metrics());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
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
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 WAF Stats: http://localhost:${PORT}/waf/stats`);
  console.log(`📈 Metrics: http://localhost:${PORT}/metrics`);
  console.log(`❤️ Health: http://localhost:${PORT}/health`);
  console.log('');
  console.log('Test the WAF with these URLs:');
  console.log(`- XSS: http://localhost:${PORT}/api/search?q=<script>alert('xss')</script>`);
  console.log(`- SQLi: http://localhost:${PORT}/api/search?q=1' OR 1=1--`);
  console.log(`- Normal: http://localhost:${PORT}/api/search?q=hello`);
});

module.exports = app;
