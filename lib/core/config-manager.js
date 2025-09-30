/**
 * Configuration Manager - Handles WAF configuration
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

class ConfigManager {
  /**
   * Load configuration from various sources
   */
  static loadConfig(options = {}) {
    const defaultConfig = this.getDefaultConfig();
    const fileConfig = this.loadConfigFile();
    const envConfig = this.loadEnvConfig();
    
    // Merge configurations (options override everything)
    return this.mergeConfigs(defaultConfig, fileConfig, envConfig, options);
  }

  /**
   * Get default configuration
   */
  static getDefaultConfig() {
    return {
      // Core settings
      enabled: true,
      dryRun: false,
      threshold: 10,
      
      // Modules
      modules: ['xss', 'sqli'],
      
      // Adaptive learning
      adaptiveLearning: false,
      learningPeriod: 7, // days
      startTime: new Date(),
      
      // Paths to skip
      skipPaths: ['/health', '/metrics', '/favicon.ico'],
      
      // Logging
      logLevel: 'info',
      logFile: null,
      
      // Rate limiting
      rateLimit: {
        enabled: false,
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100 // requests per window
      },
      
      // IP blocking
      ipBlocking: {
        enabled: false,
        blockDuration: 24 * 60 * 60 * 1000, // 24 hours
        maxViolations: 5
      },
      
      // Custom rules
      rules: [],
      
      // Stats
      stats: {
        enabled: true,
        retentionDays: 30
      }
    };
  }

  /**
   * Load configuration from file
   */
  static loadConfigFile() {
    const configPaths = [
      'waf.config.json',
      'waf.config.yaml',
      'waf.config.yml',
      '.wafrc.json',
      '.wafrc.yaml',
      '.wafrc.yml'
    ];

    for (const configPath of configPaths) {
      if (fs.existsSync(configPath)) {
        try {
          const content = fs.readFileSync(configPath, 'utf8');
          const ext = path.extname(configPath).toLowerCase();
          
          if (ext === '.json') {
            return JSON.parse(content);
          } else if (['.yaml', '.yml'].includes(ext)) {
            return yaml.load(content);
          }
        } catch (error) {
          console.warn(`Failed to load config file ${configPath}:`, error.message);
        }
      }
    }

    return {};
  }

  /**
   * Load configuration from environment variables
   */
  static loadEnvConfig() {
    const config = {};
    
    // Map environment variables to config
    const envMappings = {
      'WAF_ENABLED': 'enabled',
      'WAF_DRY_RUN': 'dryRun',
      'WAF_THRESHOLD': 'threshold',
      'WAF_MODULES': 'modules',
      'WAF_ADAPTIVE_LEARNING': 'adaptiveLearning',
      'WAF_LEARNING_PERIOD': 'learningPeriod',
      'WAF_LOG_LEVEL': 'logLevel',
      'WAF_LOG_FILE': 'logFile'
    };

    Object.entries(envMappings).forEach(([envKey, configKey]) => {
      if (process.env[envKey] !== undefined) {
        let value = process.env[envKey];
        
        // Convert string values to appropriate types
        if (value === 'true') value = true;
        else if (value === 'false') value = false;
        else if (!isNaN(value) && value !== '') value = Number(value);
        else if (value.includes(',')) value = value.split(',').map(v => v.trim());
        
        this.setNestedProperty(config, configKey, value);
      }
    });

    return config;
  }

  /**
   * Merge multiple configuration objects
   */
  static mergeConfigs(...configs) {
    const result = {};
    
    configs.forEach(config => {
      this.deepMerge(result, config);
    });
    
    return result;
  }

  /**
   * Deep merge two objects
   */
  static deepMerge(target, source) {
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        if (!target[key]) target[key] = {};
        this.deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }

  /**
   * Set nested property using dot notation
   */
  static setNestedProperty(obj, path, value) {
    const keys = path.split('.');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }
    
    current[keys[keys.length - 1]] = value;
  }

  /**
   * Validate configuration
   */
  static validateConfig(config) {
    const errors = [];
    
    // Validate threshold
    if (typeof config.threshold !== 'number' || config.threshold < 0) {
      errors.push('Threshold must be a non-negative number');
    }
    
    // Validate modules
    if (!Array.isArray(config.modules)) {
      errors.push('Modules must be an array');
    }
    
    // Validate learning period
    if (config.adaptiveLearning && (typeof config.learningPeriod !== 'number' || config.learningPeriod <= 0)) {
      errors.push('Learning period must be a positive number');
    }
    
    if (errors.length > 0) {
      throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
    }
    
    return true;
  }

  /**
   * Save configuration to file
   */
  static saveConfig(config, filePath = 'waf.config.json') {
    try {
      const content = JSON.stringify(config, null, 2);
      fs.writeFileSync(filePath, content);
      return true;
    } catch (error) {
      console.error('Failed to save config:', error.message);
      return false;
    }
  }
}

module.exports = ConfigManager;
