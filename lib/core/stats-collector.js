/**
 * Stats Collector - Collects and manages WAF statistics
 */

class StatsCollector {
  constructor(config) {
    this.config = config;
    this.stats = {
      totalRequests: 0,
      blockedRequests: 0,
      threatsDetected: 0,
      learningModeRequests: 0,
      moduleStats: {},
      threatTypes: {},
      ipStats: {},
      hourlyStats: {},
      dailyStats: {},
      startTime: new Date()
    };
    
    this.initializeModuleStats();
  }

  /**
   * Initialize module statistics
   */
  initializeModuleStats() {
    this.config.modules.forEach(module => {
      this.stats.moduleStats[module] = {
        requests: 0,
        threats: 0,
        blocked: 0
      };
    });
  }

  /**
   * Record a request
   */
  recordRequest(req, analysis) {
    this.stats.totalRequests++;
    
    const hour = this.getHourKey();
    const day = this.getDayKey();
    
    // Update hourly stats
    if (!this.stats.hourlyStats[hour]) {
      this.stats.hourlyStats[hour] = { requests: 0, threats: 0, blocked: 0 };
    }
    this.stats.hourlyStats[hour].requests++;
    
    // Update daily stats
    if (!this.stats.dailyStats[day]) {
      this.stats.dailyStats[day] = { requests: 0, threats: 0, blocked: 0 };
    }
    this.stats.dailyStats[day].requests++;
    
    // Update IP stats
    const ip = this.getClientIP(req);
    if (!this.stats.ipStats[ip]) {
      this.stats.ipStats[ip] = { requests: 0, threats: 0, blocked: 0 };
    }
    this.stats.ipStats[ip].requests++;
    
    // Update module stats
    analysis.modules.forEach(module => {
      if (this.stats.moduleStats[module]) {
        this.stats.moduleStats[module].requests++;
      }
    });
  }

  /**
   * Record a threat detection
   */
  recordThreat(req, analysis, action) {
    this.stats.threatsDetected++;
    
    const hour = this.getHourKey();
    const day = this.getDayKey();
    const ip = this.getClientIP(req);
    
    // Update hourly stats
    this.stats.hourlyStats[hour].threats++;
    if (action === 'blocked') {
      this.stats.hourlyStats[hour].blocked++;
    }
    
    // Update daily stats
    this.stats.dailyStats[day].threats++;
    if (action === 'blocked') {
      this.stats.dailyStats[day].blocked++;
    }
    
    // Update IP stats
    this.stats.ipStats[ip].threats++;
    if (action === 'blocked') {
      this.stats.ipStats[ip].blocked++;
    }
    
    // Update threat types
    analysis.threats.forEach(threat => {
      if (!this.stats.threatTypes[threat.type]) {
        this.stats.threatTypes[threat.type] = 0;
      }
      this.stats.threatTypes[threat.type]++;
    });
    
    // Update module stats
    analysis.modules.forEach(module => {
      if (this.stats.moduleStats[module]) {
        this.stats.moduleStats[module].threats++;
        if (action === 'blocked') {
          this.stats.moduleStats[module].blocked++;
        }
      }
    });
    
    if (action === 'learning') {
      this.stats.learningModeRequests++;
    } else if (action === 'blocked') {
      this.stats.blockedRequests++;
    }
  }

  /**
   * Get comprehensive statistics
   */
  getStats() {
    const uptime = Date.now() - this.stats.startTime.getTime();
    const uptimeHours = Math.floor(uptime / (1000 * 60 * 60));
    const uptimeDays = Math.floor(uptimeHours / 24);
    
    return {
      ...this.stats,
      uptime: {
        milliseconds: uptime,
        hours: uptimeHours,
        days: uptimeDays,
        human: this.formatUptime(uptime)
      },
      rates: {
        threatRate: this.stats.totalRequests > 0 ? 
          (this.stats.threatsDetected / this.stats.totalRequests * 100).toFixed(2) + '%' : '0%',
        blockRate: this.stats.totalRequests > 0 ? 
          (this.stats.blockedRequests / this.stats.totalRequests * 100).toFixed(2) + '%' : '0%'
      },
      topThreats: this.getTopThreats(),
      topIPs: this.getTopIPs(),
      recentActivity: this.getRecentActivity()
    };
  }

  /**
   * Get Prometheus metrics format
   */
  getPrometheusMetrics() {
    const metrics = [];
    
    // Basic counters
    metrics.push(`# HELP waf_requests_total Total number of requests processed`);
    metrics.push(`# TYPE waf_requests_total counter`);
    metrics.push(`waf_requests_total ${this.stats.totalRequests}`);
    
    metrics.push(`# HELP waf_threats_total Total number of threats detected`);
    metrics.push(`# TYPE waf_threats_total counter`);
    metrics.push(`waf_threats_total ${this.stats.threatsDetected}`);
    
    metrics.push(`# HELP waf_blocks_total Total number of requests blocked`);
    metrics.push(`# TYPE waf_blocks_total counter`);
    metrics.push(`waf_blocks_total ${this.stats.blockedRequests}`);
    
    // Module-specific metrics
    Object.entries(this.stats.moduleStats).forEach(([module, stats]) => {
      metrics.push(`# HELP waf_module_requests_total Total requests processed by module`);
      metrics.push(`# TYPE waf_module_requests_total counter`);
      metrics.push(`waf_module_requests_total{module="${module}"} ${stats.requests}`);
      
      metrics.push(`# HELP waf_module_threats_total Total threats detected by module`);
      metrics.push(`# TYPE waf_module_threats_total counter`);
      metrics.push(`waf_module_threats_total{module="${module}"} ${stats.threats}`);
    });
    
    // Threat type metrics
    Object.entries(this.stats.threatTypes).forEach(([type, count]) => {
      metrics.push(`# HELP waf_threat_type_total Total threats by type`);
      metrics.push(`# TYPE waf_threat_type_total counter`);
      metrics.push(`waf_threat_type_total{type="${type}"} ${count}`);
    });
    
    return metrics.join('\n');
  }

  /**
   * Get top threat types
   */
  getTopThreats(limit = 10) {
    return Object.entries(this.stats.threatTypes)
      .sort(([,a], [,b]) => b - a)
      .slice(0, limit)
      .map(([type, count]) => ({ type, count }));
  }

  /**
   * Get top IPs by threat count
   */
  getTopIPs(limit = 10) {
    return Object.entries(this.stats.ipStats)
      .filter(([, stats]) => stats.threats > 0)
      .sort(([,a], [,b]) => b.threats - a.threats)
      .slice(0, limit)
      .map(([ip, stats]) => ({ ip, ...stats }));
  }

  /**
   * Get recent activity (last 24 hours)
   */
  getRecentActivity() {
    const now = new Date();
    const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    
    const recentHours = Object.entries(this.stats.hourlyStats)
      .filter(([hour]) => new Date(hour) >= last24Hours)
      .sort(([a], [b]) => new Date(a) - new Date(b))
      .map(([hour, stats]) => ({
        hour: new Date(hour).toISOString(),
        ...stats
      }));
    
    return recentHours;
  }

  /**
   * Get client IP from request
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
   * Get hour key for statistics
   */
  getHourKey() {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours()).toISOString();
  }

  /**
   * Get day key for statistics
   */
  getDayKey() {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  }

  /**
   * Format uptime in human readable format
   */
  formatUptime(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }

  /**
   * Reset statistics
   */
  reset() {
    this.stats = {
      totalRequests: 0,
      blockedRequests: 0,
      threatsDetected: 0,
      learningModeRequests: 0,
      moduleStats: {},
      threatTypes: {},
      ipStats: {},
      hourlyStats: {},
      dailyStats: {},
      startTime: new Date()
    };
    this.initializeModuleStats();
  }
}

module.exports = StatsCollector;
