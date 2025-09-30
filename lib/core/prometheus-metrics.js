/**
 * Prometheus Metrics - Advanced monitoring and metrics collection
 */

class PrometheusMetrics {
  constructor(config) {
    this.config = config;
    this.metrics = new Map();
    this.histogramBuckets = [0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600];
    this.initializeMetrics();
  }

  /**
   * Initialize all metrics
   */
  initializeMetrics() {
    // Counter metrics
    this.createCounter('waf_requests_total', 'Total number of requests processed', ['method', 'status']);
    this.createCounter('waf_threats_total', 'Total number of threats detected', ['type', 'severity']);
    this.createCounter('waf_blocks_total', 'Total number of requests blocked', ['reason', 'module']);
    this.createCounter('waf_learning_requests_total', 'Total requests during learning mode', ['phase']);
    this.createCounter('waf_rule_matches_total', 'Total rule matches', ['rule_id', 'category']);
    this.createCounter('waf_ip_blocks_total', 'Total IP blocks', ['reason']);
    this.createCounter('waf_rate_limit_hits_total', 'Total rate limit hits', ['ip']);
    
    // Gauge metrics
    this.createGauge('waf_active_connections', 'Number of active connections');
    this.createGauge('waf_blocked_ips', 'Number of currently blocked IPs');
    this.createGauge('waf_learning_progress', 'Learning progress (0-1)', ['phase']);
    this.createGauge('waf_rules_enabled', 'Number of enabled rules', ['category']);
    this.createGauge('waf_anomaly_score', 'Current anomaly score', ['ip']);
    this.createGauge('waf_memory_usage_bytes', 'Memory usage in bytes');
    this.createGauge('waf_cpu_usage_percent', 'CPU usage percentage');
    
    // Histogram metrics
    this.createHistogram('waf_request_duration_seconds', 'Request processing duration', ['method', 'status'], this.histogramBuckets);
    this.createHistogram('waf_threat_score', 'Threat score distribution', ['module'], [1, 2, 3, 5, 10, 20, 50]);
    this.createHistogram('waf_response_size_bytes', 'Response size in bytes', ['status'], [100, 1000, 10000, 100000, 1000000]);
    this.createHistogram('waf_learning_duration_seconds', 'Learning phase duration', ['phase'], [60, 300, 900, 3600, 86400]);
    
    // Summary metrics
    this.createSummary('waf_anomaly_score_summary', 'Anomaly score summary', ['ip']);
    this.createSummary('waf_rule_evaluation_time_seconds', 'Rule evaluation time', ['category']);
  }

  /**
   * Create a counter metric
   */
  createCounter(name, help, labels = []) {
    this.metrics.set(name, {
      type: 'counter',
      help,
      labels,
      value: 0,
      labelValues: new Map()
    });
  }

  /**
   * Create a gauge metric
   */
  createGauge(name, help, labels = []) {
    this.metrics.set(name, {
      type: 'gauge',
      help,
      labels,
      value: 0,
      labelValues: new Map()
    });
  }

  /**
   * Create a histogram metric
   */
  createHistogram(name, help, labels = [], buckets = this.histogramBuckets) {
    this.metrics.set(name, {
      type: 'histogram',
      help,
      labels,
      buckets,
      count: 0,
      sum: 0,
      bucketCounts: new Array(buckets.length + 1).fill(0),
      labelValues: new Map()
    });
  }

  /**
   * Create a summary metric
   */
  createSummary(name, help, labels = []) {
    this.metrics.set(name, {
      type: 'summary',
      help,
      labels,
      count: 0,
      sum: 0,
      quantiles: new Map(),
      labelValues: new Map()
    });
  }

  /**
   * Increment a counter
   */
  incrementCounter(name, value = 1, labelValues = {}) {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'counter') return;

    const key = this.getLabelKey(labelValues);
    const current = metric.labelValues.get(key) || 0;
    metric.labelValues.set(key, current + value);
    metric.value += value;
  }

  /**
   * Set a gauge value
   */
  setGauge(name, value, labelValues = {}) {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'gauge') return;

    const key = this.getLabelKey(labelValues);
    metric.labelValues.set(key, value);
    metric.value = value;
  }

  /**
   * Observe a histogram value
   */
  observeHistogram(name, value, labelValues = {}) {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'histogram') return;

    const key = this.getLabelKey(labelValues);
    const data = metric.labelValues.get(key) || { count: 0, sum: 0, bucketCounts: new Array(metric.buckets.length + 1).fill(0) };
    
    data.count++;
    data.sum += value;
    
    // Update bucket counts
    for (let i = 0; i < metric.buckets.length; i++) {
      if (value <= metric.buckets[i]) {
        data.bucketCounts[i]++;
        break;
      }
    }
    data.bucketCounts[metric.buckets.length]++; // +Inf bucket
    
    metric.labelValues.set(key, data);
    metric.count++;
    metric.sum += value;
  }

  /**
   * Observe a summary value
   */
  observeSummary(name, value, labelValues = {}) {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'summary') return;

    const key = this.getLabelKey(labelValues);
    const data = metric.labelValues.get(key) || { count: 0, sum: 0, values: [] };
    
    data.count++;
    data.sum += value;
    data.values.push(value);
    
    // Calculate quantiles
    if (data.values.length > 0) {
      const sorted = [...data.values].sort((a, b) => a - b);
      const quantiles = [0.5, 0.9, 0.95, 0.99];
      
      quantiles.forEach(q => {
        const index = Math.ceil(q * sorted.length) - 1;
        data.quantiles.set(q, sorted[Math.max(0, index)]);
      });
    }
    
    metric.labelValues.set(key, data);
    metric.count++;
    metric.sum += value;
  }

  /**
   * Record request metrics
   */
  recordRequest(method, status, duration, responseSize) {
    this.incrementCounter('waf_requests_total', 1, { method, status });
    this.observeHistogram('waf_request_duration_seconds', duration, { method, status });
    this.observeHistogram('waf_response_size_bytes', responseSize, { status });
  }

  /**
   * Record threat metrics
   */
  recordThreat(type, severity, score, module) {
    this.incrementCounter('waf_threats_total', 1, { type, severity });
    this.observeHistogram('waf_threat_score', score, { module });
  }

  /**
   * Record block metrics
   */
  recordBlock(reason, module) {
    this.incrementCounter('waf_blocks_total', 1, { reason, module });
  }

  /**
   * Record learning metrics
   */
  recordLearning(phase, progress) {
    this.incrementCounter('waf_learning_requests_total', 1, { phase });
    this.setGauge('waf_learning_progress', progress, { phase });
  }

  /**
   * Record rule match metrics
   */
  recordRuleMatch(ruleId, category, evaluationTime) {
    this.incrementCounter('waf_rule_matches_total', 1, { rule_id: ruleId, category });
    this.observeSummary('waf_rule_evaluation_time_seconds', evaluationTime, { category });
  }

  /**
   * Record IP block metrics
   */
  recordIPBlock(reason) {
    this.incrementCounter('waf_ip_blocks_total', 1, { reason });
  }

  /**
   * Record rate limit metrics
   */
  recordRateLimit(ip) {
    this.incrementCounter('waf_rate_limit_hits_total', 1, { ip });
  }

  /**
   * Update system metrics
   */
  updateSystemMetrics() {
    const memUsage = process.memoryUsage();
    this.setGauge('waf_memory_usage_bytes', memUsage.heapUsed);
    
    // CPU usage would require additional monitoring
    // this.setGauge('waf_cpu_usage_percent', cpuUsage);
  }

  /**
   * Update anomaly score
   */
  updateAnomalyScore(ip, score) {
    this.setGauge('waf_anomaly_score', score, { ip });
  }

  /**
   * Update active connections
   */
  updateActiveConnections(count) {
    this.setGauge('waf_active_connections', count);
  }

  /**
   * Update blocked IPs count
   */
  updateBlockedIPs(count) {
    this.setGauge('waf_blocked_ips', count);
  }

  /**
   * Update enabled rules count
   */
  updateEnabledRules(category, count) {
    this.setGauge('waf_rules_enabled', count, { category });
  }

  /**
   * Generate Prometheus format output
   */
  generatePrometheusOutput() {
    const lines = [];
    
    // Add HELP and TYPE lines
    for (const [name, metric] of this.metrics) {
      lines.push(`# HELP ${name} ${metric.help}`);
      lines.push(`# TYPE ${name} ${metric.type}`);
      
      if (metric.type === 'counter' || metric.type === 'gauge') {
        if (metric.labelValues.size === 0) {
          lines.push(`${name} ${metric.value}`);
        } else {
          for (const [labelKey, value] of metric.labelValues) {
            const labels = this.formatLabels(labelKey);
            lines.push(`${name}${labels} ${value}`);
          }
        }
      } else if (metric.type === 'histogram') {
        for (const [labelKey, data] of metric.labelValues) {
          const labels = this.formatLabels(labelKey);
          lines.push(`${name}_count${labels} ${data.count}`);
          lines.push(`${name}_sum${labels} ${data.sum}`);
          
          for (let i = 0; i < metric.buckets.length; i++) {
            lines.push(`${name}_bucket{le="${metric.buckets[i]}"}${labels} ${data.bucketCounts[i]}`);
          }
          lines.push(`${name}_bucket{le="+Inf"}${labels} ${data.bucketCounts[metric.buckets.length]}`);
        }
      } else if (metric.type === 'summary') {
        for (const [labelKey, data] of metric.labelValues) {
          const labels = this.formatLabels(labelKey);
          lines.push(`${name}_count${labels} ${data.count}`);
          lines.push(`${name}_sum${labels} ${data.sum}`);
          
          for (const [quantile, value] of data.quantiles) {
            lines.push(`${name}{quantile="${quantile}"}${labels} ${value}`);
          }
        }
      }
      
      lines.push(''); // Empty line between metrics
    }
    
    return lines.join('\n');
  }

  /**
   * Get metrics in JSON format
   */
  getMetricsJSON() {
    const result = {};
    
    for (const [name, metric] of this.metrics) {
      result[name] = {
        type: metric.type,
        help: metric.help,
        labels: metric.labels,
        data: {}
      };
      
      if (metric.type === 'counter' || metric.type === 'gauge') {
        if (metric.labelValues.size === 0) {
          result[name].data.default = metric.value;
        } else {
          for (const [labelKey, value] of metric.labelValues) {
            result[name].data[labelKey] = value;
          }
        }
      } else if (metric.type === 'histogram') {
        for (const [labelKey, data] of metric.labelValues) {
          result[name].data[labelKey] = {
            count: data.count,
            sum: data.sum,
            buckets: data.bucketCounts
          };
        }
      } else if (metric.type === 'summary') {
        for (const [labelKey, data] of metric.labelValues) {
          result[name].data[labelKey] = {
            count: data.count,
            sum: data.sum,
            quantiles: Object.fromEntries(data.quantiles)
          };
        }
      }
    }
    
    return result;
  }

  /**
   * Helper methods
   */
  getLabelKey(labelValues) {
    return Object.entries(labelValues)
      .map(([key, value]) => `${key}="${value}"`)
      .join(',');
  }

  formatLabels(labelKey) {
    if (!labelKey) return '';
    return `{${labelKey}}`;
  }

  /**
   * Reset all metrics
   */
  reset() {
    for (const metric of this.metrics.values()) {
      metric.value = 0;
      metric.count = 0;
      metric.sum = 0;
      metric.labelValues.clear();
      
      if (metric.type === 'histogram') {
        metric.bucketCounts.fill(0);
      } else if (metric.type === 'summary') {
        metric.quantiles.clear();
      }
    }
  }

  /**
   * Get metric value
   */
  getMetric(name, labelValues = {}) {
    const metric = this.metrics.get(name);
    if (!metric) return null;
    
    const key = this.getLabelKey(labelValues);
    return metric.labelValues.get(key) || metric.value;
  }
}

module.exports = PrometheusMetrics;
