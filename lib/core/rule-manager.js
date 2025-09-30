/**
 * Rule Manager - Advanced rule management and updates
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

class RuleManager {
  constructor(config) {
    this.config = config;
    this.rules = new Map();
    this.ruleCategories = new Map();
    this.customRules = [];
    this.ruleSources = [
      {
        name: 'builtin',
        type: 'local',
        path: path.join(__dirname, '../rules/builtin.json'),
        enabled: true
      },
      {
        name: 'community',
        type: 'remote',
        url: 'https://raw.githubusercontent.com/node-waf/rules/main/community.json',
        enabled: config.communityRules || false,
        updateInterval: 24 * 60 * 60 * 1000 // 24 hours
      }
    ];
    
    this.loadBuiltInRules();
    this.loadCustomRules();
    this.startRuleUpdates();
  }

  /**
   * Load built-in rules
   */
  loadBuiltInRules() {
    try {
      const builtinPath = path.join(__dirname, '../rules/builtin.json');
      if (fs.existsSync(builtinPath)) {
        const rules = JSON.parse(fs.readFileSync(builtinPath, 'utf8'));
        this.addRules(rules, 'builtin');
      } else {
        // Create default built-in rules if file doesn't exist
        this.createDefaultBuiltInRules();
      }
    } catch (error) {
      console.warn('Failed to load built-in rules:', error.message);
      this.createDefaultBuiltInRules();
    }
  }

  /**
   * Create default built-in rules
   */
  createDefaultBuiltInRules() {
    const defaultRules = [
      // XSS Rules
      {
        id: 'xss-script-tag',
        name: 'XSS Script Tag Detection',
        category: 'xss',
        pattern: /<script[^>]*>.*?<\/script>/gi,
        score: 3,
        description: 'Detects script tag injection attempts',
        severity: 'high',
        tags: ['xss', 'script', 'injection']
      },
      {
        id: 'xss-javascript-url',
        name: 'XSS JavaScript URL Detection',
        category: 'xss',
        pattern: /javascript:/gi,
        score: 2,
        description: 'Detects javascript: URL schemes',
        severity: 'medium',
        tags: ['xss', 'javascript', 'url']
      },
      {
        id: 'xss-event-handler',
        name: 'XSS Event Handler Detection',
        category: 'xss',
        pattern: /on\w+\s*=/gi,
        score: 2,
        description: 'Detects event handler injection',
        severity: 'medium',
        tags: ['xss', 'event', 'handler']
      },
      
      // SQL Injection Rules
      {
        id: 'sqli-union',
        name: 'SQL Union Injection',
        category: 'sqli',
        pattern: /union\s+select/gi,
        score: 4,
        description: 'Detects UNION SELECT injection attempts',
        severity: 'high',
        tags: ['sqli', 'union', 'select']
      },
      {
        id: 'sqli-or-1-1',
        name: 'SQL OR 1=1 Injection',
        category: 'sqli',
        pattern: /or\s+1\s*=\s*1/gi,
        score: 3,
        description: 'Detects OR 1=1 injection attempts',
        severity: 'high',
        tags: ['sqli', 'or', 'boolean']
      },
      {
        id: 'sqli-drop-table',
        name: 'SQL DROP TABLE Injection',
        category: 'sqli',
        pattern: /drop\s+table/gi,
        score: 5,
        description: 'Detects DROP TABLE injection attempts',
        severity: 'critical',
        tags: ['sqli', 'drop', 'table']
      },
      {
        id: 'sqli-comment',
        name: 'SQL Comment Injection',
        category: 'sqli',
        pattern: /--\s*$/gm,
        score: 2,
        description: 'Detects SQL comment injection',
        severity: 'medium',
        tags: ['sqli', 'comment', 'injection']
      },
      
      // NoSQL Injection Rules
      {
        id: 'nosqli-operator',
        name: 'NoSQL Operator Injection',
        category: 'nosqli',
        pattern: /\$where|\$ne|\$gt|\$lt|\$regex/gi,
        score: 3,
        description: 'Detects NoSQL operator injection',
        severity: 'high',
        tags: ['nosqli', 'operator', 'mongodb']
      },
      
      // Path Traversal Rules
      {
        id: 'path-traversal',
        name: 'Path Traversal Detection',
        category: 'path-traversal',
        pattern: /\.\.\/|\.\.\\|\.\.%2f|\.\.%5c/gi,
        score: 4,
        description: 'Detects path traversal attempts',
        severity: 'high',
        tags: ['path-traversal', 'directory', 'traversal']
      },
      
      // Command Injection Rules
      {
        id: 'cmd-injection',
        name: 'Command Injection Detection',
        category: 'cmd-injection',
        pattern: /[;&|`$(){}[\]\\]/gi,
        score: 2,
        description: 'Detects command injection characters',
        severity: 'medium',
        tags: ['cmd-injection', 'shell', 'command']
      }
    ];
    
    this.addRules(defaultRules, 'builtin');
  }

  /**
   * Load custom rules from config
   */
  loadCustomRules() {
    if (this.config.customRules && Array.isArray(this.config.customRules)) {
      this.customRules = [...this.config.customRules];
      this.addRules(this.customRules, 'custom');
    }
  }

  /**
   * Add rules to the manager
   */
  addRules(rules, source) {
    rules.forEach(rule => {
      // Validate rule
      if (!this.validateRule(rule)) {
        console.warn(`Invalid rule skipped: ${rule.id || 'unknown'}`);
        return;
      }
      
      // Compile regex pattern
      if (typeof rule.pattern === 'string') {
        try {
          rule.pattern = new RegExp(rule.pattern, rule.flags || 'gi');
        } catch (error) {
          console.warn(`Invalid regex pattern for rule ${rule.id}:`, error.message);
          return;
        }
      }
      
      // Add to rules map
      this.rules.set(rule.id, {
        ...rule,
        source: source,
        addedAt: new Date(),
        enabled: rule.enabled !== false
      });
      
      // Add to category map
      if (!this.ruleCategories.has(rule.category)) {
        this.ruleCategories.set(rule.category, []);
      }
      this.ruleCategories.get(rule.category).push(rule.id);
    });
  }

  /**
   * Validate rule structure
   */
  validateRule(rule) {
    const required = ['id', 'name', 'category', 'pattern', 'score'];
    return required.every(field => rule.hasOwnProperty(field));
  }

  /**
   * Get rules by category
   */
  getRulesByCategory(category) {
    const ruleIds = this.ruleCategories.get(category) || [];
    return ruleIds.map(id => this.rules.get(id)).filter(Boolean);
  }

  /**
   * Get all enabled rules
   */
  getEnabledRules() {
    return Array.from(this.rules.values()).filter(rule => rule.enabled);
  }

  /**
   * Get rule by ID
   */
  getRule(id) {
    return this.rules.get(id);
  }

  /**
   * Add custom rule
   */
  addCustomRule(rule) {
    if (!this.validateRule(rule)) {
      throw new Error('Invalid rule structure');
    }
    
    rule.source = 'custom';
    rule.addedAt = new Date();
    rule.enabled = rule.enabled !== false;
    
    // Compile regex pattern
    if (typeof rule.pattern === 'string') {
      try {
        rule.pattern = new RegExp(rule.pattern, rule.flags || 'gi');
      } catch (error) {
        throw new Error(`Invalid regex pattern: ${error.message}`);
      }
    }
    
    this.rules.set(rule.id, rule);
    this.customRules.push(rule);
    
    // Add to category
    if (!this.ruleCategories.has(rule.category)) {
      this.ruleCategories.set(rule.category, []);
    }
    this.ruleCategories.get(rule.category).push(rule.id);
    
    return rule;
  }

  /**
   * Update custom rule
   */
  updateCustomRule(id, updates) {
    const rule = this.rules.get(id);
    if (!rule || rule.source !== 'custom') {
      throw new Error('Rule not found or not custom');
    }
    
    // Update rule
    Object.assign(rule, updates);
    
    // Recompile pattern if changed
    if (updates.pattern) {
      if (typeof updates.pattern === 'string') {
        try {
          rule.pattern = new RegExp(updates.pattern, updates.flags || 'gi');
        } catch (error) {
          throw new Error(`Invalid regex pattern: ${error.message}`);
        }
      }
    }
    
    // Update in custom rules array
    const customIndex = this.customRules.findIndex(r => r.id === id);
    if (customIndex >= 0) {
      this.customRules[customIndex] = rule;
    }
    
    return rule;
  }

  /**
   * Delete custom rule
   */
  deleteCustomRule(id) {
    const rule = this.rules.get(id);
    if (!rule || rule.source !== 'custom') {
      throw new Error('Rule not found or not custom');
    }
    
    this.rules.delete(id);
    
    // Remove from category
    const categoryRules = this.ruleCategories.get(rule.category) || [];
    const index = categoryRules.indexOf(id);
    if (index >= 0) {
      categoryRules.splice(index, 1);
    }
    
    // Remove from custom rules array
    const customIndex = this.customRules.findIndex(r => r.id === id);
    if (customIndex >= 0) {
      this.customRules.splice(customIndex, 1);
    }
    
    return true;
  }

  /**
   * Enable/disable rule
   */
  toggleRule(id, enabled) {
    const rule = this.rules.get(id);
    if (!rule) {
      throw new Error('Rule not found');
    }
    
    rule.enabled = enabled;
    return rule;
  }

  /**
   * Start automatic rule updates
   */
  startRuleUpdates() {
    if (!this.config.autoUpdate) return;
    
    // Update immediately
    this.updateCommunityRules();
    
    // Set up periodic updates
    setInterval(() => {
      this.updateCommunityRules();
    }, this.config.updateInterval || 24 * 60 * 60 * 1000);
  }

  /**
   * Update community rules
   */
  async updateCommunityRules() {
    const communitySource = this.ruleSources.find(s => s.name === 'community');
    if (!communitySource || !communitySource.enabled) return;
    
    try {
      console.log('🔄 Updating community rules...');
      const rules = await this.fetchRemoteRules(communitySource.url);
      
      // Validate and add new rules
      const newRules = rules.filter(rule => !this.rules.has(rule.id));
      if (newRules.length > 0) {
        this.addRules(newRules, 'community');
        console.log(`✅ Added ${newRules.length} new community rules`);
      } else {
        console.log('ℹ️ No new community rules available');
      }
    } catch (error) {
      console.warn('Failed to update community rules:', error.message);
    }
  }

  /**
   * Fetch rules from remote URL
   */
  fetchRemoteRules(url) {
    return new Promise((resolve, reject) => {
      https.get(url, (res) => {
        let data = '';
        
        res.on('data', chunk => {
          data += chunk;
        });
        
        res.on('end', () => {
          try {
            const rules = JSON.parse(data);
            resolve(rules);
          } catch (error) {
            reject(new Error('Invalid JSON response'));
          }
        });
      }).on('error', reject);
    });
  }

  /**
   * Export rules to file
   */
  exportRules(filePath, options = {}) {
    const { categories, sources, enabled } = options;
    let rules = Array.from(this.rules.values());
    
    // Filter by categories
    if (categories && categories.length > 0) {
      rules = rules.filter(rule => categories.includes(rule.category));
    }
    
    // Filter by sources
    if (sources && sources.length > 0) {
      rules = rules.filter(rule => sources.includes(rule.source));
    }
    
    // Filter by enabled status
    if (enabled !== undefined) {
      rules = rules.filter(rule => rule.enabled === enabled);
    }
    
    // Remove internal properties
    const exportRules = rules.map(rule => {
      const { source, addedAt, ...exportRule } = rule;
      return exportRule;
    });
    
    fs.writeFileSync(filePath, JSON.stringify(exportRules, null, 2));
    return exportRules.length;
  }

  /**
   * Import rules from file
   */
  importRules(filePath, source = 'imported') {
    try {
      const rules = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      this.addRules(rules, source);
      return rules.length;
    } catch (error) {
      throw new Error(`Failed to import rules: ${error.message}`);
    }
  }

  /**
   * Get rule statistics
   */
  getStats() {
    const stats = {
      total: this.rules.size,
      enabled: Array.from(this.rules.values()).filter(r => r.enabled).length,
      disabled: Array.from(this.rules.values()).filter(r => !r.enabled).length,
      byCategory: {},
      bySource: {},
      bySeverity: {}
    };
    
    // Count by category
    for (const [category, ruleIds] of this.ruleCategories) {
      stats.byCategory[category] = ruleIds.length;
    }
    
    // Count by source
    for (const rule of this.rules.values()) {
      stats.bySource[rule.source] = (stats.bySource[rule.source] || 0) + 1;
    }
    
    // Count by severity
    for (const rule of this.rules.values()) {
      const severity = rule.severity || 'unknown';
      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
    }
    
    return stats;
  }
}

module.exports = RuleManager;
