/**
 * XSS (Cross-Site Scripting) Detection Module
 */

class XSSModule {
  constructor(config) {
    this.config = config;
    this.patterns = this.loadXSSPatterns();
  }

  /**
   * Load XSS detection patterns
   */
  loadXSSPatterns() {
    return [
      // Script tag patterns
      {
        name: 'script-tag',
        pattern: /<script[^>]*>.*?<\/script>/gi,
        score: 3,
        description: 'Script tag injection'
      },
      {
        name: 'script-src',
        pattern: /<script[^>]*src\s*=/gi,
        score: 2,
        description: 'External script source'
      },
      
      // Event handler patterns
      {
        name: 'onload-event',
        pattern: /onload\s*=/gi,
        score: 2,
        description: 'onload event handler'
      },
      {
        name: 'onclick-event',
        pattern: /onclick\s*=/gi,
        score: 2,
        description: 'onclick event handler'
      },
      {
        name: 'onerror-event',
        pattern: /onerror\s*=/gi,
        score: 2,
        description: 'onerror event handler'
      },
      
      // JavaScript URL patterns
      {
        name: 'javascript-url',
        pattern: /javascript:/gi,
        score: 3,
        description: 'JavaScript URL scheme'
      },
      {
        name: 'vbscript-url',
        pattern: /vbscript:/gi,
        score: 3,
        description: 'VBScript URL scheme'
      },
      
      // Expression patterns
      {
        name: 'expression',
        pattern: /expression\s*\(/gi,
        score: 2,
        description: 'CSS expression'
      },
      
      // Iframe patterns
      {
        name: 'iframe-src',
        pattern: /<iframe[^>]*src\s*=/gi,
        score: 2,
        description: 'Iframe with external source'
      },
      
      // Object/Embed patterns
      {
        name: 'object-data',
        pattern: /<object[^>]*data\s*=/gi,
        score: 2,
        description: 'Object with external data'
      },
      {
        name: 'embed-src',
        pattern: /<embed[^>]*src\s*=/gi,
        score: 2,
        description: 'Embed with external source'
      },
      
      // Form action patterns
      {
        name: 'form-action',
        pattern: /<form[^>]*action\s*=/gi,
        score: 1,
        description: 'Form with action attribute'
      },
      
      // Meta refresh patterns
      {
        name: 'meta-refresh',
        pattern: /<meta[^>]*http-equiv\s*=\s*["']refresh["']/gi,
        score: 2,
        description: 'Meta refresh redirect'
      },
      
      // Base tag patterns
      {
        name: 'base-href',
        pattern: /<base[^>]*href\s*=/gi,
        score: 2,
        description: 'Base tag with href'
      },
      
      // Link patterns
      {
        name: 'link-href',
        pattern: /<link[^>]*href\s*=/gi,
        score: 1,
        description: 'Link with href attribute'
      },
      
      // Style patterns
      {
        name: 'style-tag',
        pattern: /<style[^>]*>.*?<\/style>/gi,
        score: 1,
        description: 'Style tag injection'
      },
      
      // Common XSS payloads
      {
        name: 'alert-payload',
        pattern: /alert\s*\(/gi,
        score: 2,
        description: 'Alert function call'
      },
      {
        name: 'confirm-payload',
        pattern: /confirm\s*\(/gi,
        score: 2,
        description: 'Confirm function call'
      },
      {
        name: 'prompt-payload',
        pattern: /prompt\s*\(/gi,
        score: 2,
        description: 'Prompt function call'
      },
      {
        name: 'document-cookie',
        pattern: /document\.cookie/gi,
        score: 3,
        description: 'Document cookie access'
      },
      {
        name: 'document-write',
        pattern: /document\.write/gi,
        score: 2,
        description: 'Document write'
      },
      {
        name: 'innerHTML',
        pattern: /innerHTML\s*=/gi,
        score: 2,
        description: 'innerHTML assignment'
      },
      {
        name: 'outerHTML',
        pattern: /outerHTML\s*=/gi,
        score: 2,
        description: 'outerHTML assignment'
      },
      
      // Encoded patterns
      {
        name: 'html-encoded',
        pattern: /&#x?[0-9a-fA-F]+;/gi,
        score: 1,
        description: 'HTML encoded characters'
      },
      {
        name: 'url-encoded',
        pattern: /%[0-9a-fA-F]{2}/gi,
        score: 1,
        description: 'URL encoded characters'
      },
      
      // SVG patterns
      {
        name: 'svg-script',
        pattern: /<svg[^>]*>.*?<script/gi,
        score: 3,
        description: 'SVG with script tag'
      },
      
      // Data URI patterns
      {
        name: 'data-uri-javascript',
        pattern: /data:text\/html.*javascript/gi,
        score: 3,
        description: 'Data URI with JavaScript'
      }
    ];
  }

  /**
   * Analyze request for XSS threats
   */
  analyze(analysis) {
    const threats = [];
    let totalScore = 0;
    
    // Get all searchable text from the request
    const searchTexts = this.extractSearchTexts(analysis);
    
    // Check each pattern
    this.patterns.forEach(pattern => {
      searchTexts.forEach(text => {
        if (typeof text === 'string' && pattern.pattern.test(text)) {
          threats.push({
            type: 'xss',
            pattern: pattern.name,
            description: pattern.description,
            score: pattern.score,
            matched: text.substring(0, 100) + (text.length > 100 ? '...' : '')
          });
          totalScore += pattern.score;
        }
      });
    });
    
    // Check for suspicious combinations
    const combinationThreats = this.checkCombinations(searchTexts);
    threats.push(...combinationThreats);
    totalScore += combinationThreats.reduce((sum, threat) => sum + threat.score, 0);
    
    if (threats.length > 0) {
      return {
        score: totalScore,
        threats: threats,
        module: 'xss'
      };
    }
    
    return null;
  }

  /**
   * Extract searchable texts from analysis
   */
  extractSearchTexts(analysis) {
    const texts = [];
    
    // URL path
    texts.push(analysis.path);
    
    // Query parameters
    if (analysis.query) {
      Object.values(analysis.query).forEach(value => {
        if (typeof value === 'string') {
          texts.push(value);
        }
      });
    }
    
    // Request body
    if (analysis.body) {
      if (typeof analysis.body === 'string') {
        texts.push(analysis.body);
      } else if (typeof analysis.body === 'object') {
        texts.push(JSON.stringify(analysis.body));
      }
    }
    
    // Headers
    Object.values(analysis.headers).forEach(value => {
      if (typeof value === 'string') {
        texts.push(value);
      }
    });
    
    // Cookies
    Object.values(analysis.cookies).forEach(value => {
      if (typeof value === 'string') {
        texts.push(value);
      }
    });
    
    return texts;
  }

  /**
   * Check for suspicious pattern combinations
   */
  checkCombinations(searchTexts) {
    const threats = [];
    const text = searchTexts.join(' ').toLowerCase();
    
    // Check for script tag with suspicious content
    if (text.includes('<script') && (text.includes('alert') || text.includes('document'))) {
      threats.push({
        type: 'xss',
        pattern: 'script-suspicious-content',
        description: 'Script tag with suspicious content',
        score: 4,
        matched: 'Script tag with alert/document access'
      });
    }
    
    // Check for event handler with JavaScript
    if ((text.includes('onclick') || text.includes('onload')) && text.includes('javascript:')) {
      threats.push({
        type: 'xss',
        pattern: 'event-handler-javascript',
        description: 'Event handler with JavaScript URL',
        score: 4,
        matched: 'Event handler with JavaScript URL'
      });
    }
    
    // Check for encoded payloads
    if (text.includes('&#x') && (text.includes('script') || text.includes('alert'))) {
      threats.push({
        type: 'xss',
        pattern: 'encoded-payload',
        description: 'Encoded XSS payload',
        score: 3,
        matched: 'Encoded XSS payload detected'
      });
    }
    
    return threats;
  }
}

module.exports = XSSModule;
