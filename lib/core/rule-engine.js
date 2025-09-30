/**
 * Rule Engine - Core rule evaluation and scoring system
 */

const path = require('path');

class RuleEngine {
  constructor(config) {
    this.config = config;
    this.modules = new Map();
    this.rules = [];
    this.threshold = config.threshold || 10;
    
    this.loadModules();
    this.loadRules();
  }

  /**
   * Load security modules
   */
  loadModules() {
    const moduleNames = this.config.modules || ['xss', 'sqli'];
    
    moduleNames.forEach(moduleName => {
      try {
        const ModuleClass = require(`../modules/${moduleName}`);
        const module = new ModuleClass(this.config);
        this.modules.set(moduleName, module);
      } catch (error) {
        console.warn(`Failed to load module ${moduleName}:`, error.message);
      }
    });
  }

  /**
   * Set rule manager
   */
  setRuleManager(ruleManager) {
    this.ruleManager = ruleManager;
    this.loadRulesFromManager();
  }

  /**
   * Load rules from rule manager
   */
  loadRulesFromManager() {
    if (this.ruleManager) {
      const enabledRules = this.ruleManager.getEnabledRules();
      this.rules = enabledRules.map(rule => ({
        id: rule.id,
        name: rule.name,
        pattern: rule.pattern,
        score: rule.score,
        module: rule.category,
        description: rule.description
      }));
    }
  }

  /**
   * Load rules from configuration
   */
  loadRules() {
    // Load built-in rules
    this.loadBuiltInRules();
    
    // Load custom rules if provided
    if (this.config.rules) {
      this.rules.push(...this.config.rules);
    }
  }

  /**
   * Load built-in security rules
   */
  loadBuiltInRules() {
    // Basic XSS patterns
    this.rules.push({
      id: 'xss-script-tag',
      name: 'XSS Script Tag Detection',
      pattern: /<script[^>]*>.*?<\/script>/gi,
      score: 3,
      module: 'xss',
      description: 'Detects script tag injection attempts'
    });

    this.rules.push({
      id: 'xss-javascript-url',
      name: 'XSS JavaScript URL Detection',
      pattern: /javascript:/gi,
      score: 2,
      module: 'xss',
      description: 'Detects javascript: URL schemes'
    });

    // Basic SQL injection patterns
    this.rules.push({
      id: 'sqli-union',
      name: 'SQL Union Injection',
      pattern: /union\s+select/gi,
      score: 4,
      module: 'sqli',
      description: 'Detects UNION SELECT injection attempts'
    });

    this.rules.push({
      id: 'sqli-or-1-1',
      name: 'SQL OR 1=1 Injection',
      pattern: /or\s+1\s*=\s*1/gi,
      score: 3,
      module: 'sqli',
      description: 'Detects OR 1=1 injection attempts'
    });

    this.rules.push({
      id: 'sqli-drop-table',
      name: 'SQL DROP TABLE Injection',
      pattern: /drop\s+table/gi,
      score: 5,
      module: 'sqli',
      description: 'Detects DROP TABLE injection attempts'
    });

    // NoSQL injection patterns
    this.rules.push({
      id: 'nosqli-operator',
      name: 'NoSQL Operator Injection',
      pattern: /\$where|\$ne|\$gt|\$lt|\$regex/gi,
      score: 3,
      module: 'nosqli',
      description: 'Detects NoSQL operator injection'
    });
  }

  /**
   * Evaluate request against all rules
   */
  evaluate(analysis) {
    const result = {
      action: 'allow',
      score: analysis.score,
      reason: null,
      requestId: this.generateRequestId(),
      analysis: analysis,
      matchedRules: []
    };

    // Check threshold
    if (analysis.score >= this.threshold) {
      result.action = 'block';
      result.reason = `Threat score ${analysis.score} exceeds threshold ${this.threshold}`;
    }

    // Check individual rules
    this.rules.forEach(rule => {
      if (this.evaluateRule(rule, analysis)) {
        result.matchedRules.push(rule);
        // Add rule score to total score
        result.score += rule.score;
      }
    });

    // Re-check threshold with updated score
    if (result.score >= this.threshold) {
      result.action = 'block';
      result.reason = `Threat score ${result.score} exceeds threshold ${this.threshold}`;
    }

    return result;
  }

  /**
   * Evaluate a single rule against analysis
   */
  evaluateRule(rule, analysis) {
    const searchTexts = this.extractSearchTexts(analysis);
    
    return searchTexts.some(text => {
      if (typeof text !== 'string') return false;
      // Reset regex lastIndex for global patterns
      rule.pattern.lastIndex = 0;
      return rule.pattern.test(text);
    });
  }

  /**
   * Extract searchable texts from request analysis
   */
  extractSearchTexts(analysis) {
    const texts = [];
    
    // Add URL path
    texts.push(analysis.path);
    
    // Add query parameters
    if (analysis.query) {
      Object.values(analysis.query).forEach(value => {
        if (typeof value === 'string') {
          texts.push(value);
        }
      });
    }
    
    // Add request body
    if (analysis.body) {
      if (typeof analysis.body === 'string') {
        texts.push(analysis.body);
      } else if (typeof analysis.body === 'object') {
        texts.push(JSON.stringify(analysis.body));
      }
    }
    
    // Add headers
    Object.values(analysis.headers).forEach(value => {
      if (typeof value === 'string') {
        texts.push(value);
      }
    });
    
    // Add cookies
    Object.values(analysis.cookies).forEach(value => {
      if (typeof value === 'string') {
        texts.push(value);
      }
    });
    
    return texts;
  }

  /**
   * Get module by name
   */
  getModule(name) {
    return this.modules.get(name);
  }

  /**
   * Generate unique request ID
   */
  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Add custom rule
   */
  addRule(rule) {
    this.rules.push(rule);
  }

  /**
   * Remove rule by ID
   */
  removeRule(ruleId) {
    this.rules = this.rules.filter(rule => rule.id !== ruleId);
  }

  /**
   * Get all rules
   */
  getRules() {
    return [...this.rules];
  }
}

module.exports = RuleEngine;
