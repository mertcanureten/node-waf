/**
 * Unit tests for XSS Module
 */

const XSSModule = require('../../lib/modules/xss');

describe('XSS Module', () => {
  let xssModule;

  beforeEach(() => {
    xssModule = new XSSModule({});
  });

  describe('Pattern Detection', () => {
    test('should detect script tag injection', () => {
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
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.module).toBe('xss');
      
      const scriptThreat = result.threats.find(threat => threat.pattern === 'script-tag');
      expect(scriptThreat).toBeDefined();
      expect(scriptThreat.description).toBe('Script tag injection');
    });

    test('should detect JavaScript URL schemes', () => {
      const analysis = {
        path: '/test',
        query: { url: 'javascript:alert("xss")' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const jsUrlThreat = result.threats.find(threat => threat.pattern === 'javascript-url');
      expect(jsUrlThreat).toBeDefined();
    });

    test('should detect event handlers', () => {
      const analysis = {
        path: '/test',
        query: { html: '<img onerror="alert(1)">' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const eventThreat = result.threats.find(threat => threat.pattern === 'onerror-event');
      expect(eventThreat).toBeDefined();
    });

    test('should detect VBScript URL schemes', () => {
      const analysis = {
        path: '/test',
        query: { url: 'vbscript:msgbox("xss")' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const vbThreat = result.threats.find(threat => threat.pattern === 'vbscript-url');
      expect(vbThreat).toBeDefined();
    });

    test('should detect CSS expressions', () => {
      const analysis = {
        path: '/test',
        query: { css: 'expression(alert("xss"))' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const exprThreat = result.threats.find(threat => threat.pattern === 'expression');
      expect(exprThreat).toBeDefined();
    });

    test('should detect iframe injection', () => {
      const analysis = {
        path: '/test',
        query: { html: '<iframe src="javascript:alert(1)"></iframe>' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const iframeThreat = result.threats.find(threat => threat.pattern === 'iframe-src');
      expect(iframeThreat).toBeDefined();
    });

    test('should detect alert function calls', () => {
      const analysis = {
        path: '/test',
        query: { js: 'alert("xss")' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const alertThreat = result.threats.find(threat => threat.pattern === 'alert-payload');
      expect(alertThreat).toBeDefined();
    });

    test('should detect document.cookie access', () => {
      const analysis = {
        path: '/test',
        query: { js: 'document.cookie' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const cookieThreat = result.threats.find(threat => threat.pattern === 'document-cookie');
      expect(cookieThreat).toBeDefined();
    });

    test('should detect innerHTML assignment', () => {
      const analysis = {
        path: '/test',
        query: { js: 'element.innerHTML = "xss"' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const innerHTMLThreat = result.threats.find(threat => threat.pattern === 'innerHTML');
      expect(innerHTMLThreat).toBeDefined();
    });
  });

  describe('Combination Detection', () => {
    test('should detect script tag with suspicious content', () => {
      const analysis = {
        path: '/test',
        query: { html: '<script>alert("xss")</script>' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const comboThreat = result.threats.find(threat => threat.pattern === 'script-suspicious-content');
      expect(comboThreat).toBeDefined();
    });

    test('should detect event handler with JavaScript URL', () => {
      const analysis = {
        path: '/test',
        query: { html: '<img onclick="javascript:alert(1)">' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const comboThreat = result.threats.find(threat => threat.pattern === 'event-handler-javascript');
      expect(comboThreat).toBeDefined();
    });

    test('should detect encoded payloads', () => {
      const analysis = {
        path: '/test',
        query: { html: '&#x3C;script&#x3E;alert("xss")&#x3C;/script&#x3E;' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
      
      const encodedThreat = result.threats.find(threat => threat.pattern === 'encoded-payload');
      expect(encodedThreat).toBeDefined();
    });
  });

  describe('Safe Content', () => {
    test('should not detect threats in safe content', () => {
      const analysis = {
        path: '/test',
        query: { q: 'hello world' },
        body: { name: 'John Doe' },
        headers: { 'user-agent': 'Mozilla/5.0' },
        cookies: { session: 'abc123' },
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeNull();
    });

    test('should not detect threats in normal HTML', () => {
      const analysis = {
        path: '/test',
        query: { html: '<p>Hello World</p>' },
        body: null,
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeNull();
    });
  });

  describe('Multiple Sources', () => {
    test('should analyze query parameters', () => {
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
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
    });

    test('should analyze request body', () => {
      const analysis = {
        path: '/test',
        query: {},
        body: { comment: '<script>alert("xss")</script>' },
        headers: {},
        cookies: {},
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
    });

    test('should analyze headers', () => {
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
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
    });

    test('should analyze cookies', () => {
      const analysis = {
        path: '/test',
        query: {},
        body: null,
        headers: {},
        cookies: { session: '<script>alert("xss")</script>' },
        score: 0,
        threats: [],
        modules: []
      };
      
      const result = xssModule.analyze(analysis);
      
      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThan(0);
    });
  });
});
