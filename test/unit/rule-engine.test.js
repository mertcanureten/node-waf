/**
 * Unit tests for Rule Engine
 */

const RuleEngine = require('../../lib/core/rule-engine');

describe('Rule Engine', () => {
  let ruleEngine;

  beforeEach(() => {
    ruleEngine = new RuleEngine({
      modules: ['xss', 'sqli'],
      threshold: 3
    });
  });

  describe('Rule Loading', () => {
    test('should load built-in rules', () => {
      const rules = ruleEngine.getRules();
      expect(rules.length).toBeGreaterThan(0);
      
      const xssRules = rules.filter(rule => rule.module === 'xss');
      const sqliRules = rules.filter(rule => rule.module === 'sqli');
      
      expect(xssRules.length).toBeGreaterThan(0);
      expect(sqliRules.length).toBeGreaterThan(0);
    });

    test('should add custom rules', () => {
      const customRule = {
        id: 'custom-test',
        name: 'Custom Test Rule',
        pattern: /test-pattern/gi,
        score: 5,
        module: 'custom',
        description: 'Custom test rule'
      };
      
      ruleEngine.addRule(customRule);
      const rules = ruleEngine.getRules();
      
      expect(rules.find(rule => rule.id === 'custom-test')).toBeDefined();
    });

    test('should remove rules by ID', () => {
      const rules = ruleEngine.getRules();
      const initialCount = rules.length;
      
      ruleEngine.removeRule('xss-script-tag');
      const updatedRules = ruleEngine.getRules();
      
      expect(updatedRules.length).toBe(initialCount - 1);
      expect(updatedRules.find(rule => rule.id === 'xss-script-tag')).toBeUndefined();
    });
  });

  describe('Rule Evaluation', () => {
    test('should evaluate XSS rules correctly', () => {
      const analysis = {
        path: '/test',
        query: { q: '<script>alert("xss")</script>' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = ruleEngine.evaluate(analysis);
      
      expect(result.action).toBe('block');
      expect(result.score).toBeGreaterThan(0);
      expect(result.matchedRules.length).toBeGreaterThan(0);
    });

    test('should evaluate SQL injection rules correctly', () => {
      const analysis = {
        path: '/test',
        query: { id: '1 UNION SELECT * FROM users' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = ruleEngine.evaluate(analysis);
      
      expect(result.action).toBe('block');
      expect(result.score).toBeGreaterThan(0);
      expect(result.matchedRules.length).toBeGreaterThan(0);
    });

    test('should allow safe requests', () => {
      const analysis = {
        path: '/test',
        query: { q: 'hello world' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = ruleEngine.evaluate(analysis);
      
      expect(result.action).toBe('allow');
      expect(result.score).toBe(0);
      expect(result.matchedRules.length).toBe(0);
    });

    test('should handle JSON body content', () => {
      const analysis = {
        path: '/api/test',
        query: {},
        body: { comment: '<script>alert("xss")</script>' },
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = ruleEngine.evaluate(analysis);
      
      expect(result.action).toBe('block');
      expect(result.score).toBeGreaterThan(0);
    });

    test('should handle header content', () => {
      const analysis = {
        path: '/test',
        query: {},
        body: null,
        headers: { 'user-agent': '<script>alert("xss")</script>' },
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = ruleEngine.evaluate(analysis);
      
      expect(result.action).toBe('block');
      expect(result.score).toBeGreaterThan(0);
    });

    test('should handle cookie content', () => {
      const analysis = {
        path: '/test',
        query: {},
        body: null,
        headers: {},
        cookies: { session: '1 OR 1=1' },
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = ruleEngine.evaluate(analysis);
      
      expect(result.action).toBe('block');
      expect(result.score).toBeGreaterThan(0);
    });
  });

  describe('Threshold Handling', () => {
    test('should block when score exceeds threshold', () => {
      const analysis = {
        path: '/test',
        query: { q: '<script>alert("xss")</script>' },
        body: null,
        headers: {},
        cookies: {},
        score: 15, // Above threshold of 10
        threats: [],
        modules: []
      };
      
      const result = ruleEngine.evaluate(analysis);
      
      expect(result.action).toBe('block');
      expect(result.reason).toContain('Threat score 18 exceeds threshold 3');
    });

    test('should allow when score is below threshold', () => {
      const analysis = {
        path: '/test',
        query: { q: 'hello' },
        body: null,
        headers: {},
        cookies: {},
        score: 2, // Below threshold of 3
        threats: [],
        modules: []
      };
      
      const result = ruleEngine.evaluate(analysis);
      
      expect(result.action).toBe('allow');
    });
  });

  describe('Request ID Generation', () => {
    test('should generate unique request IDs', () => {
      const analysis1 = { path: '/test1', query: {}, body: null, headers: {}, cookies: {}, score: 0, threats: [], modules: [] };
      const analysis2 = { path: '/test2', query: {}, body: null, headers: {}, cookies: {}, score: 0, threats: [], modules: [] };
      
      const result1 = ruleEngine.evaluate(analysis1);
      const result2 = ruleEngine.evaluate(analysis2);
      
      expect(result1.requestId).toBeDefined();
      expect(result2.requestId).toBeDefined();
      expect(result1.requestId).not.toBe(result2.requestId);
      expect(result1.requestId).toMatch(/^req_\d+_[a-z0-9]+$/);
    });
  });
});
