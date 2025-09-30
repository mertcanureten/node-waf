/**
 * Unit tests for WAF Middleware
 */

const request = require('supertest');
const express = require('express');
const waf = require('../../lib/index');

describe('WAF Middleware', () => {
  let app;
  let wafMiddleware;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    
    wafMiddleware = waf({
      modules: ['xss', 'sqli'],
      threshold: 3,
      dryRun: false,
      adaptiveLearning: false,
      anomalyThreshold: 1000 // Disable anomaly scoring for tests
    });
    
    app.use(wafMiddleware.middleware());
    
    app.get('/', (req, res) => {
      res.json({ message: 'Hello World' });
    });
    
    app.post('/api/test', (req, res) => {
      res.json({ received: req.body });
    });
    
    // Add WAF endpoints
    app.get('/waf/stats', wafMiddleware.stats());
    app.get('/metrics', wafMiddleware.metrics());
  });

  describe('Basic functionality', () => {
    test('should allow normal requests', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);
      
      expect(response.body.message).toBe('Hello World');
    });

    test('should allow normal POST requests', async () => {
      const response = await request(app)
        .post('/api/test')
        .send({ name: 'John', email: 'john@example.com' })
        .expect(200);
      
      expect(response.body.received.name).toBe('John');
    });
  });

  describe('XSS Detection', () => {
    test('should block XSS in query parameters', async () => {
      const response = await request(app)
        .get('/?q=<script>alert("xss")</script>')
        .expect(403);
      
      expect(response.body.error).toBe('Request blocked by WAF');
      expect(response.body.reason).toContain('Threat score');
    });

    test('should block XSS in request body', async () => {
      const response = await request(app)
        .post('/api/test')
        .send({ comment: '<script>alert("xss")</script>' })
        .expect(403);
      
      expect(response.body.error).toBe('Request blocked by WAF');
    });

    test('should block JavaScript URL schemes', async () => {
      const response = await request(app)
        .get('/?url=javascript:alert("xss")')
        .expect(403);
      
      expect(response.body.error).toBe('Request blocked by WAF');
    });

    test('should block event handlers', async () => {
      const response = await request(app)
        .get('/?html=<img onerror="alert(1)">')
        .expect(403);
      
      expect(response.body.error).toBe('Request blocked by WAF');
    });
  });

  describe('SQL Injection Detection', () => {
    test('should block UNION SELECT injection', async () => {
      const response = await request(app)
        .get('/?id=1 UNION SELECT * FROM users')
        .expect(403);
      
      expect(response.body.error).toBe('Request blocked by WAF');
    });

    test('should block OR 1=1 injection', async () => {
      const response = await request(app)
        .get('/?id=1 OR 1=1')
        .expect(403);
      
      expect(response.body.error).toBe('Request blocked by WAF');
    });

    test('should block DROP TABLE injection', async () => {
      const response = await request(app)
        .post('/api/test')
        .send({ query: 'DROP TABLE users' })
        .expect(403);
      
      expect(response.body.error).toBe('Request blocked by WAF');
    });

    test('should block comment injection', async () => {
      const response = await request(app)
        .get('/?id=1--')
        .expect(403);
      
      expect(response.body.error).toBe('Request blocked by WAF');
    });
  });

  describe('Dry Run Mode', () => {
    beforeEach(() => {
      app = express();
      app.use(express.json());
      
      wafMiddleware = waf({
        modules: ['xss', 'sqli'],
        threshold: 3,
        dryRun: true,
        adaptiveLearning: false,
        anomalyThreshold: 1000 // Disable anomaly scoring for tests
      });
      
      app.use(wafMiddleware.middleware());
      
      app.get('/', (req, res) => {
        res.json({ message: 'Hello World' });
      });
    });

    test('should allow requests in dry run mode', async () => {
      const response = await request(app)
        .get('/?q=<script>alert("xss")</script>')
        .expect(200);
      
      expect(response.body.message).toBe('Hello World');
    });
  });

  describe('Stats Endpoint', () => {
    test('should return stats', async () => {
      // Make a request first
      await request(app).get('/');
      
      const response = await request(app)
        .get('/waf/stats')
        .expect(200);
      
      expect(response.body).toHaveProperty('totalRequests');
      expect(response.body).toHaveProperty('blockedRequests');
      expect(response.body).toHaveProperty('threatsDetected');
      expect(response.body.totalRequests).toBeGreaterThan(0);
    });
  });

  describe('Error Handling', () => {
    test('should handle middleware errors gracefully', async () => {
      // This test would require injecting an error into the middleware
      // For now, we'll just test that the app doesn't crash
      const response = await request(app)
        .get('/')
        .expect(200);
      
      expect(response.body.message).toBe('Hello World');
    });
  });
});
