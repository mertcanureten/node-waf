/**
 * API Manager - Runtime configuration and management endpoints
 */

const fs = require('fs');
const path = require('path');

class APIManager {
  constructor(config, ruleManager, statsCollector, adaptiveLearning) {
    this.config = config;
    this.ruleManager = ruleManager;
    this.statsCollector = statsCollector;
    this.adaptiveLearning = adaptiveLearning;
    this.logs = [];
    this.maxLogs = config.maxLogs || 10000;
    this.apiKey = config.apiKey || null;
    this.rateLimits = new Map(); // IP -> { count, resetTime }
  }

  /**
   * Create API routes
   */
  createRoutes() {
    return {
      // Configuration endpoints
      'GET /waf/config': this.getConfig.bind(this),
      'PUT /waf/config': this.updateConfig.bind(this),
      'POST /waf/config/reset': this.resetConfig.bind(this),
      
      // Rule management endpoints
      'GET /waf/rules': this.getRules.bind(this),
      'POST /waf/rules': this.addRule.bind(this),
      'PUT /waf/rules/:id': this.updateRule.bind(this),
      'DELETE /waf/rules/:id': this.deleteRule.bind(this),
      'POST /waf/rules/:id/toggle': this.toggleRule.bind(this),
      'GET /waf/rules/categories': this.getRuleCategories.bind(this),
      'POST /waf/rules/import': this.importRules.bind(this),
      'GET /waf/rules/export': this.exportRules.bind(this),
      
      // Statistics endpoints
      'GET /waf/stats': this.getStats.bind(this),
      'GET /waf/stats/reset': this.resetStats.bind(this),
      'GET /waf/stats/export': this.exportStats.bind(this),
      
      // Logs endpoints
      'GET /waf/logs': this.getLogs.bind(this),
      'GET /waf/logs/:id': this.getLogById.bind(this),
      'POST /waf/logs/clear': this.clearLogs.bind(this),
      'GET /waf/logs/export': this.exportLogs.bind(this),
      
      // Learning endpoints
      'GET /waf/learning': this.getLearningStatus.bind(this),
      'POST /waf/learning/start': this.startLearning.bind(this),
      'POST /waf/learning/stop': this.stopLearning.bind(this),
      'GET /waf/learning/report': this.getLearningReport.bind(this),
      
      // IP management endpoints
      'GET /waf/ips': this.getIPs.bind(this),
      'POST /waf/ips/:ip/block': this.blockIP.bind(this),
      'POST /waf/ips/:ip/unblock': this.unblockIP.bind(this),
      'GET /waf/ips/blocked': this.getBlockedIPs.bind(this),
      
      // Health and monitoring
      'GET /waf/health': this.getHealth.bind(this),
      'GET /waf/metrics': this.getMetrics.bind(this),
      'GET /waf/version': this.getVersion.bind(this)
    };
  }

  /**
   * Middleware for API authentication and rate limiting
   */
  apiMiddleware() {
    return (req, res, next) => {
      // Rate limiting
      if (!this.checkRateLimit(req)) {
        return res.status(429).json({ error: 'Rate limit exceeded' });
      }
      
      // API key authentication (if enabled)
      if (this.apiKey && req.headers['x-api-key'] !== this.apiKey) {
        return res.status(401).json({ error: 'Invalid API key' });
      }
      
      next();
    };
  }

  /**
   * Check rate limit for API requests
   */
  checkRateLimit(req) {
    const ip = this.getClientIP(req);
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute
    const maxRequests = 100; // 100 requests per minute
    
    if (!this.rateLimits.has(ip)) {
      this.rateLimits.set(ip, { count: 0, resetTime: now + windowMs });
    }
    
    const limit = this.rateLimits.get(ip);
    
    if (now > limit.resetTime) {
      limit.count = 0;
      limit.resetTime = now + windowMs;
    }
    
    if (limit.count >= maxRequests) {
      return false;
    }
    
    limit.count++;
    return true;
  }

  /**
   * Get current configuration
   */
  getConfig(req, res) {
    try {
      const config = {
        enabled: this.config.enabled,
        dryRun: this.config.dryRun,
        threshold: this.config.threshold,
        modules: this.config.modules,
        adaptiveLearning: this.config.adaptiveLearning,
        learningPeriod: this.config.learningPeriod,
        skipPaths: this.config.skipPaths,
        rateLimit: this.config.rateLimit,
        ipBlocking: this.config.ipBlocking,
        stats: this.config.stats
      };
      
      res.json({
        success: true,
        config: config,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Update configuration
   */
  updateConfig(req, res) {
    try {
      const updates = req.body;
      const allowedFields = [
        'enabled', 'dryRun', 'threshold', 'modules', 'adaptiveLearning',
        'learningPeriod', 'skipPaths', 'rateLimit', 'ipBlocking', 'stats'
      ];
      
      // Validate updates
      for (const field of Object.keys(updates)) {
        if (!allowedFields.includes(field)) {
          return res.status(400).json({ error: `Field '${field}' is not allowed` });
        }
      }
      
      // Apply updates
      Object.assign(this.config, updates);
      
      // Save to file if configured
      if (this.config.configFile) {
        this.saveConfigToFile();
      }
      
      res.json({
        success: true,
        message: 'Configuration updated successfully',
        config: this.config,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Reset configuration to defaults
   */
  resetConfig(req, res) {
    try {
      // Reset to default configuration
      const defaultConfig = require('./config-manager').getDefaultConfig();
      Object.assign(this.config, defaultConfig);
      
      // Save to file if configured
      if (this.config.configFile) {
        this.saveConfigToFile();
      }
      
      res.json({
        success: true,
        message: 'Configuration reset to defaults',
        config: this.config,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get all rules
   */
  getRules(req, res) {
    try {
      const { category, enabled, source } = req.query;
      let rules = Array.from(this.ruleManager.rules.values());
      
      // Filter by category
      if (category) {
        rules = rules.filter(rule => rule.category === category);
      }
      
      // Filter by enabled status
      if (enabled !== undefined) {
        const isEnabled = enabled === 'true';
        rules = rules.filter(rule => rule.enabled === isEnabled);
      }
      
      // Filter by source
      if (source) {
        rules = rules.filter(rule => rule.source === source);
      }
      
      res.json({
        success: true,
        rules: rules,
        total: rules.length,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Add new rule
   */
  addRule(req, res) {
    try {
      const rule = req.body;
      const addedRule = this.ruleManager.addCustomRule(rule);
      
      this.log('info', `Rule added: ${rule.id}`, { ruleId: rule.id, category: rule.category });
      
      res.status(201).json({
        success: true,
        message: 'Rule added successfully',
        rule: addedRule,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Update existing rule
   */
  updateRule(req, res) {
    try {
      const { id } = req.params;
      const updates = req.body;
      const updatedRule = this.ruleManager.updateCustomRule(id, updates);
      
      this.log('info', `Rule updated: ${id}`, { ruleId: id, updates });
      
      res.json({
        success: true,
        message: 'Rule updated successfully',
        rule: updatedRule,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Delete rule
   */
  deleteRule(req, res) {
    try {
      const { id } = req.params;
      this.ruleManager.deleteCustomRule(id);
      
      this.log('info', `Rule deleted: ${id}`, { ruleId: id });
      
      res.json({
        success: true,
        message: 'Rule deleted successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Toggle rule enabled status
   */
  toggleRule(req, res) {
    try {
      const { id } = req.params;
      const { enabled } = req.body;
      const updatedRule = this.ruleManager.toggleRule(id, enabled);
      
      this.log('info', `Rule ${enabled ? 'enabled' : 'disabled'}: ${id}`, { ruleId: id, enabled });
      
      res.json({
        success: true,
        message: `Rule ${enabled ? 'enabled' : 'disabled'} successfully`,
        rule: updatedRule,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Get rule categories
   */
  getRuleCategories(req, res) {
    try {
      const categories = Array.from(this.ruleManager.ruleCategories.keys());
      const stats = this.ruleManager.getStats();
      
      res.json({
        success: true,
        categories: categories,
        stats: stats.byCategory,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Import rules from file
   */
  importRules(req, res) {
    try {
      const { filePath, source = 'imported' } = req.body;
      const count = this.ruleManager.importRules(filePath, source);
      
      this.log('info', `Rules imported: ${count} rules from ${filePath}`, { count, filePath });
      
      res.json({
        success: true,
        message: `${count} rules imported successfully`,
        count: count,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Export rules to file
   */
  exportRules(req, res) {
    try {
      const { filePath, categories, sources, enabled } = req.query;
      const count = this.ruleManager.exportRules(filePath, { categories, sources, enabled });
      
      res.json({
        success: true,
        message: `${count} rules exported successfully`,
        count: count,
        filePath: filePath,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Get statistics
   */
  getStats(req, res) {
    try {
      const stats = this.statsCollector.getStats();
      const ruleStats = this.ruleManager.getStats();
      
      res.json({
        success: true,
        stats: {
          ...stats,
          rules: ruleStats
        },
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Reset statistics
   */
  resetStats(req, res) {
    try {
      this.statsCollector.reset();
      
      this.log('info', 'Statistics reset', {});
      
      res.json({
        success: true,
        message: 'Statistics reset successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Export statistics
   */
  exportStats(req, res) {
    try {
      const { format = 'json' } = req.query;
      const stats = this.statsCollector.getStats();
      
      if (format === 'csv') {
        const csv = this.convertStatsToCSV(stats);
        res.set('Content-Type', 'text/csv');
        res.send(csv);
      } else {
        res.json({
          success: true,
          stats: stats,
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get logs
   */
  getLogs(req, res) {
    try {
      const { level, limit = 100, offset = 0 } = req.query;
      let logs = [...this.logs];
      
      // Filter by level
      if (level) {
        logs = logs.filter(log => log.level === level);
      }
      
      // Apply pagination
      const start = parseInt(offset);
      const end = start + parseInt(limit);
      const paginatedLogs = logs.slice(start, end);
      
      res.json({
        success: true,
        logs: paginatedLogs,
        total: logs.length,
        limit: parseInt(limit),
        offset: parseInt(offset),
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get log by ID
   */
  getLogById(req, res) {
    try {
      const { id } = req.params;
      const log = this.logs.find(l => l.id === id);
      
      if (!log) {
        return res.status(404).json({ error: 'Log not found' });
      }
      
      res.json({
        success: true,
        log: log,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Clear logs
   */
  clearLogs(req, res) {
    try {
      const { level } = req.body;
      
      if (level) {
        this.logs = this.logs.filter(log => log.level !== level);
      } else {
        this.logs = [];
      }
      
      res.json({
        success: true,
        message: 'Logs cleared successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Export logs
   */
  exportLogs(req, res) {
    try {
      const { format = 'json', level } = req.query;
      let logs = [...this.logs];
      
      if (level) {
        logs = logs.filter(log => log.level === level);
      }
      
      if (format === 'csv') {
        const csv = this.convertLogsToCSV(logs);
        res.set('Content-Type', 'text/csv');
        res.send(csv);
      } else {
        res.json({
          success: true,
          logs: logs,
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get learning status
   */
  getLearningStatus(req, res) {
    try {
      const status = this.adaptiveLearning.getStatus();
      
      res.json({
        success: true,
        learning: status,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Start learning
   */
  startLearning(req, res) {
    try {
      if (this.adaptiveLearning.isLearning) {
        return res.status(400).json({ error: 'Learning is already in progress' });
      }
      
      this.adaptiveLearning.startLearning();
      
      res.json({
        success: true,
        message: 'Learning started successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Stop learning
   */
  stopLearning(req, res) {
    try {
      if (!this.adaptiveLearning.isLearning) {
        return res.status(400).json({ error: 'Learning is not in progress' });
      }
      
      this.adaptiveLearning.finalizeLearning();
      
      res.json({
        success: true,
        message: 'Learning stopped successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get learning report
   */
  getLearningReport(req, res) {
    try {
      const report = this.adaptiveLearning.generateLearningReport();
      
      res.json({
        success: true,
        report: report,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get IPs
   */
  getIPs(req, res) {
    try {
      const { status, limit = 100 } = req.query;
      const ipStats = this.statsCollector.stats.ipStats;
      
      let ips = Object.entries(ipStats).map(([ip, stats]) => ({
        ip,
        ...stats,
        status: stats.blocked > 0 ? 'blocked' : 'active'
      }));
      
      if (status) {
        ips = ips.filter(ip => ip.status === status);
      }
      
      ips = ips.slice(0, parseInt(limit));
      
      res.json({
        success: true,
        ips: ips,
        total: ips.length,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Block IP
   */
  blockIP(req, res) {
    try {
      const { ip } = req.params;
      const { reason = 'Manual block', duration } = req.body;
      
      // This would integrate with the rate limiting module
      // For now, just log the action
      this.log('warn', `IP blocked: ${ip}`, { ip, reason, duration });
      
      res.json({
        success: true,
        message: `IP ${ip} blocked successfully`,
        ip: ip,
        reason: reason,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Unblock IP
   */
  unblockIP(req, res) {
    try {
      const { ip } = req.params;
      
      // This would integrate with the rate limiting module
      // For now, just log the action
      this.log('info', `IP unblocked: ${ip}`, { ip });
      
      res.json({
        success: true,
        message: `IP ${ip} unblocked successfully`,
        ip: ip,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get blocked IPs
   */
  getBlockedIPs(req, res) {
    try {
      // This would integrate with the rate limiting module
      // For now, return empty array
      const blockedIPs = [];
      
      res.json({
        success: true,
        blockedIPs: blockedIPs,
        total: blockedIPs.length,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get health status
   */
  getHealth(req, res) {
    try {
      const health = {
        status: 'healthy',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: require('../../package.json').version,
        timestamp: new Date().toISOString()
      };
      
      res.json({
        success: true,
        health: health
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get metrics
   */
  getMetrics(req, res) {
    try {
      const metrics = this.statsCollector.getPrometheusMetrics();
      
      res.set('Content-Type', 'text/plain');
      res.send(metrics);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get version
   */
  getVersion(req, res) {
    try {
      const pkg = require('../../package.json');
      
      res.json({
        success: true,
        version: pkg.version,
        name: pkg.name,
        description: pkg.description,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Log message
   */
  log(level, message, data = {}) {
    const logEntry = {
      id: this.generateLogId(),
      level: level,
      message: message,
      data: data,
      timestamp: new Date().toISOString()
    };
    
    this.logs.push(logEntry);
    
    // Keep only last maxLogs entries
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }
  }

  /**
   * Helper methods
   */
  generateLogId() {
    return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getClientIP(req) {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           'unknown';
  }

  saveConfigToFile() {
    if (this.config.configFile) {
      fs.writeFileSync(this.config.configFile, JSON.stringify(this.config, null, 2));
    }
  }

  convertStatsToCSV(stats) {
    // Implementation for CSV conversion
    return 'timestamp,metric,value\n' + 
           `${new Date().toISOString()},totalRequests,${stats.totalRequests}\n` +
           `${new Date().toISOString()},blockedRequests,${stats.blockedRequests}\n`;
  }

  convertLogsToCSV(logs) {
    // Implementation for CSV conversion
    return 'id,level,message,timestamp\n' + 
           logs.map(log => `${log.id},${log.level},${log.message},${log.timestamp}`).join('\n');
  }
}

module.exports = APIManager;
