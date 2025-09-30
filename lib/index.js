/**
 * Node-WAF - Web Application Firewall for Node.js
 * Main entry point
 */

const WAFMiddleware = require('./core/middleware');
const RuleEngine = require('./core/rule-engine');
const ConfigManager = require('./core/config-manager');
const StatsCollector = require('./core/stats-collector');
const RuleManager = require('./core/rule-manager');

/**
 * Create WAF middleware with configuration
 * @param {Object} options - Configuration options
 * @returns {Function} Express middleware function
 */
function createWAF(options = {}) {
  const config = ConfigManager.loadConfig(options);
  const ruleManager = new RuleManager(config);
  const ruleEngine = new RuleEngine(config);
  const statsCollector = new StatsCollector(config);
  
  return new WAFMiddleware(config, ruleEngine, statsCollector, ruleManager);
}

/**
 * Default WAF middleware with minimal configuration
 */
function waf(options = {}) {
  return createWAF(options);
}

// Export main function and utilities
module.exports = waf;
module.exports.createWAF = createWAF;
module.exports.RuleEngine = RuleEngine;
module.exports.ConfigManager = ConfigManager;
module.exports.StatsCollector = StatsCollector;
module.exports.RuleManager = RuleManager;

// Export version
module.exports.version = require('../package.json').version;
