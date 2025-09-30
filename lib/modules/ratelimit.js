/**
 * Rate Limiting Module
 */

class RateLimitModule {
  constructor(config) {
    this.config = config;
    this.rateLimitConfig = config.rateLimit || {};
    this.enabled = this.rateLimitConfig.enabled || false;
    this.windowMs = this.rateLimitConfig.windowMs || 15 * 60 * 1000; // 15 minutes
    this.max = this.rateLimitConfig.max || 100; // requests per window
    this.ipBlocking = config.ipBlocking || {};
    this.blockDuration = this.ipBlocking.blockDuration || 24 * 60 * 60 * 1000; // 24 hours
    this.maxViolations = this.ipBlocking.maxViolations || 5;
    
    // In-memory storage for rate limiting
    this.requests = new Map(); // IP -> { count, firstRequest, violations }
    this.blockedIPs = new Map(); // IP -> { blockedUntil, reason }
    
    // Cleanup interval
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000); // Cleanup every minute
  }

  /**
   * Analyze request for rate limiting
   */
  analyze(analysis) {
    if (!this.enabled) {
      return null;
    }

    const ip = analysis.ip;
    const now = Date.now();
    
    // Check if IP is currently blocked
    if (this.isIPBlocked(ip)) {
      return {
        score: 10,
        threats: [{
          type: 'ratelimit',
          pattern: 'ip-blocked',
          description: 'IP address is blocked due to rate limiting violations',
          score: 10,
          matched: `IP ${ip} is blocked`
        }],
        module: 'ratelimit'
      };
    }
    
    // Get or create request record for this IP
    let requestRecord = this.requests.get(ip);
    if (!requestRecord) {
      requestRecord = {
        count: 0,
        firstRequest: now,
        violations: 0
      };
      this.requests.set(ip, requestRecord);
    }
    
    // Check if window has expired
    if (now - requestRecord.firstRequest > this.windowMs) {
      // Reset window
      requestRecord.count = 0;
      requestRecord.firstRequest = now;
      requestRecord.violations = 0;
    }
    
    // Increment request count
    requestRecord.count++;
    
    // Check if rate limit exceeded
    if (requestRecord.count > this.max) {
      requestRecord.violations++;
      
      // Check if IP should be blocked
      if (this.ipBlocking.enabled && requestRecord.violations >= this.maxViolations) {
        this.blockIP(ip, 'Rate limit violations exceeded');
        return {
          score: 10,
          threats: [{
            type: 'ratelimit',
            pattern: 'ip-blocked-violations',
            description: 'IP blocked due to repeated rate limit violations',
            score: 10,
            matched: `IP ${ip} blocked after ${requestRecord.violations} violations`
          }],
          module: 'ratelimit'
        };
      }
      
      return {
        score: 5,
        threats: [{
          type: 'ratelimit',
          pattern: 'rate-limit-exceeded',
          description: `Rate limit exceeded: ${requestRecord.count}/${this.max} requests in window`,
          score: 5,
          matched: `Rate limit exceeded: ${requestRecord.count}/${this.max}`
        }],
        module: 'ratelimit'
      };
    }
    
    return null;
  }

  /**
   * Check if IP is currently blocked
   */
  isIPBlocked(ip) {
    const blockRecord = this.blockedIPs.get(ip);
    if (!blockRecord) {
      return false;
    }
    
    const now = Date.now();
    if (now > blockRecord.blockedUntil) {
      // Block has expired, remove it
      this.blockedIPs.delete(ip);
      return false;
    }
    
    return true;
  }

  /**
   * Block an IP address
   */
  blockIP(ip, reason) {
    const now = Date.now();
    this.blockedIPs.set(ip, {
      blockedUntil: now + this.blockDuration,
      reason: reason,
      blockedAt: now
    });
    
    // Remove from requests map
    this.requests.delete(ip);
  }

  /**
   * Unblock an IP address
   */
  unblockIP(ip) {
    this.blockedIPs.delete(ip);
  }

  /**
   * Get rate limit status for an IP
   */
  getIPStatus(ip) {
    const requestRecord = this.requests.get(ip);
    const blockRecord = this.blockedIPs.get(ip);
    
    if (blockRecord) {
      return {
        status: 'blocked',
        blockedUntil: new Date(blockRecord.blockedUntil),
        reason: blockRecord.reason,
        blockedAt: new Date(blockRecord.blockedAt)
      };
    }
    
    if (requestRecord) {
      const now = Date.now();
      const windowStart = requestRecord.firstRequest;
      const windowEnd = windowStart + this.windowMs;
      const remainingTime = Math.max(0, windowEnd - now);
      
      return {
        status: 'active',
        requests: requestRecord.count,
        maxRequests: this.max,
        windowStart: new Date(windowStart),
        windowEnd: new Date(windowEnd),
        remainingTime: remainingTime,
        violations: requestRecord.violations
      };
    }
    
    return {
      status: 'clean',
      requests: 0,
      maxRequests: this.max,
      violations: 0
    };
  }

  /**
   * Get all blocked IPs
   */
  getBlockedIPs() {
    const now = Date.now();
    const blocked = [];
    
    for (const [ip, record] of this.blockedIPs.entries()) {
      if (now <= record.blockedUntil) {
        blocked.push({
          ip: ip,
          blockedUntil: new Date(record.blockedUntil),
          reason: record.reason,
          blockedAt: new Date(record.blockedAt),
          remainingTime: record.blockedUntil - now
        });
      }
    }
    
    return blocked.sort((a, b) => b.blockedAt - a.blockedAt);
  }

  /**
   * Get rate limit statistics
   */
  getStats() {
    const now = Date.now();
    const activeIPs = Array.from(this.requests.entries())
      .filter(([ip, record]) => now - record.firstRequest <= this.windowMs)
      .length;
    
    const blockedIPs = Array.from(this.blockedIPs.entries())
      .filter(([ip, record]) => now <= record.blockedUntil)
      .length;
    
    const totalViolations = Array.from(this.requests.values())
      .reduce((sum, record) => sum + record.violations, 0);
    
    return {
      enabled: this.enabled,
      windowMs: this.windowMs,
      maxRequests: this.max,
      activeIPs: activeIPs,
      blockedIPs: blockedIPs,
      totalViolations: totalViolations,
      ipBlockingEnabled: this.ipBlocking.enabled,
      maxViolations: this.maxViolations,
      blockDuration: this.blockDuration
    };
  }

  /**
   * Cleanup expired records
   */
  cleanup() {
    const now = Date.now();
    
    // Cleanup expired request records
    for (const [ip, record] of this.requests.entries()) {
      if (now - record.firstRequest > this.windowMs) {
        this.requests.delete(ip);
      }
    }
    
    // Cleanup expired block records
    for (const [ip, record] of this.blockedIPs.entries()) {
      if (now > record.blockedUntil) {
        this.blockedIPs.delete(ip);
      }
    }
  }

  /**
   * Reset all data
   */
  reset() {
    this.requests.clear();
    this.blockedIPs.clear();
  }

  /**
   * Destroy the module and cleanup
   */
  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.reset();
  }
}

module.exports = RateLimitModule;
