/**
 * SQL Injection Detection Module
 */

class SQLiModule {
  constructor(config) {
    this.config = config;
    this.patterns = this.loadSQLiPatterns();
  }

  /**
   * Load SQL injection detection patterns
   */
  loadSQLiPatterns() {
    return [
      // Union-based injection
      {
        name: 'union-select',
        pattern: /union\s+select/gi,
        score: 4,
        description: 'UNION SELECT injection'
      },
      {
        name: 'union-all-select',
        pattern: /union\s+all\s+select/gi,
        score: 4,
        description: 'UNION ALL SELECT injection'
      },
      
      // Boolean-based blind injection
      {
        name: 'or-1-1',
        pattern: /or\s+1\s*=\s*1/gi,
        score: 3,
        description: 'OR 1=1 injection'
      },
      {
        name: 'or-1-0',
        pattern: /or\s+1\s*=\s*0/gi,
        score: 3,
        description: 'OR 1=0 injection'
      },
      {
        name: 'and-1-1',
        pattern: /and\s+1\s*=\s*1/gi,
        score: 3,
        description: 'AND 1=1 injection'
      },
      {
        name: 'and-1-0',
        pattern: /and\s+1\s*=\s*0/gi,
        score: 3,
        description: 'AND 1=0 injection'
      },
      
      // Time-based blind injection
      {
        name: 'sleep-function',
        pattern: /sleep\s*\(/gi,
        score: 4,
        description: 'SLEEP function injection'
      },
      {
        name: 'waitfor-delay',
        pattern: /waitfor\s+delay/gi,
        score: 4,
        description: 'WAITFOR DELAY injection'
      },
      {
        name: 'benchmark-function',
        pattern: /benchmark\s*\(/gi,
        score: 4,
        description: 'BENCHMARK function injection'
      },
      
      // Error-based injection
      {
        name: 'extractvalue',
        pattern: /extractvalue\s*\(/gi,
        score: 4,
        description: 'EXTRACTVALUE function injection'
      },
      {
        name: 'updatexml',
        pattern: /updatexml\s*\(/gi,
        score: 4,
        description: 'UPDATEXML function injection'
      },
      {
        name: 'exp-function',
        pattern: /exp\s*\(/gi,
        score: 3,
        description: 'EXP function injection'
      },
      
      // Stacked queries
      {
        name: 'semicolon',
        pattern: /;\s*(select|insert|update|delete|drop|create|alter)/gi,
        score: 3,
        description: 'Semicolon stacked query'
      },
      
      // Comment injection
      {
        name: 'comment-dash',
        pattern: /--\s*$/gm,
        score: 2,
        description: 'SQL comment injection'
      },
      {
        name: 'comment-hash',
        pattern: /#\s*$/gm,
        score: 2,
        description: 'SQL hash comment injection'
      },
      {
        name: 'comment-slash',
        pattern: /\/\*.*?\*\//gi,
        score: 2,
        description: 'SQL block comment injection'
      },
      
      // Database-specific functions
      {
        name: 'mysql-version',
        pattern: /version\s*\(/gi,
        score: 3,
        description: 'MySQL VERSION function'
      },
      {
        name: 'mysql-database',
        pattern: /database\s*\(/gi,
        score: 3,
        description: 'MySQL DATABASE function'
      },
      {
        name: 'mysql-user',
        pattern: /user\s*\(/gi,
        score: 3,
        description: 'MySQL USER function'
      },
      {
        name: 'mysql-current-user',
        pattern: /current_user\s*\(/gi,
        score: 3,
        description: 'MySQL CURRENT_USER function'
      },
      
      // Information schema
      {
        name: 'information-schema',
        pattern: /information_schema/gi,
        score: 3,
        description: 'INFORMATION_SCHEMA access'
      },
      {
        name: 'mysql-tables',
        pattern: /mysql\.tables/gi,
        score: 3,
        description: 'MySQL tables access'
      },
      
      // System functions
      {
        name: 'load-file',
        pattern: /load_file\s*\(/gi,
        score: 4,
        description: 'LOAD_FILE function injection'
      },
      {
        name: 'into-outfile',
        pattern: /into\s+outfile/gi,
        score: 4,
        description: 'INTO OUTFILE injection'
      },
      {
        name: 'into-dumpfile',
        pattern: /into\s+dumpfile/gi,
        score: 4,
        description: 'INTO DUMPFILE injection'
      },
      
      // Privilege escalation
      {
        name: 'grant-privileges',
        pattern: /grant\s+.*\s+on/gi,
        score: 5,
        description: 'GRANT privileges injection'
      },
      {
        name: 'revoke-privileges',
        pattern: /revoke\s+.*\s+on/gi,
        score: 5,
        description: 'REVOKE privileges injection'
      },
      
      // Data manipulation
      {
        name: 'drop-table',
        pattern: /drop\s+table/gi,
        score: 5,
        description: 'DROP TABLE injection'
      },
      {
        name: 'drop-database',
        pattern: /drop\s+database/gi,
        score: 5,
        description: 'DROP DATABASE injection'
      },
      {
        name: 'truncate-table',
        pattern: /truncate\s+table/gi,
        score: 4,
        description: 'TRUNCATE TABLE injection'
      },
      {
        name: 'delete-from',
        pattern: /delete\s+from/gi,
        score: 4,
        description: 'DELETE FROM injection'
      },
      
      // Schema manipulation
      {
        name: 'alter-table',
        pattern: /alter\s+table/gi,
        score: 4,
        description: 'ALTER TABLE injection'
      },
      {
        name: 'create-table',
        pattern: /create\s+table/gi,
        score: 4,
        description: 'CREATE TABLE injection'
      },
      {
        name: 'create-database',
        pattern: /create\s+database/gi,
        score: 4,
        description: 'CREATE DATABASE injection'
      },
      
      // Conditional statements
      {
        name: 'if-statement',
        pattern: /if\s*\(/gi,
        score: 3,
        description: 'IF statement injection'
      },
      {
        name: 'case-statement',
        pattern: /case\s+when/gi,
        score: 3,
        description: 'CASE statement injection'
      },
      
      // String functions
      {
        name: 'concat-function',
        pattern: /concat\s*\(/gi,
        score: 2,
        description: 'CONCAT function injection'
      },
      {
        name: 'substring-function',
        pattern: /substring\s*\(/gi,
        score: 2,
        description: 'SUBSTRING function injection'
      },
      {
        name: 'ascii-function',
        pattern: /ascii\s*\(/gi,
        score: 2,
        description: 'ASCII function injection'
      },
      {
        name: 'char-function',
        pattern: /char\s*\(/gi,
        score: 2,
        description: 'CHAR function injection'
      },
      
      // Mathematical functions
      {
        name: 'count-function',
        pattern: /count\s*\(/gi,
        score: 2,
        description: 'COUNT function injection'
      },
      {
        name: 'length-function',
        pattern: /length\s*\(/gi,
        score: 2,
        description: 'LENGTH function injection'
      },
      
      // Common SQL keywords
      {
        name: 'select-asterisk',
        pattern: /select\s+\*/gi,
        score: 2,
        description: 'SELECT * injection'
      },
      {
        name: 'insert-into',
        pattern: /insert\s+into/gi,
        score: 3,
        description: 'INSERT INTO injection'
      },
      {
        name: 'update-set',
        pattern: /update\s+.*\s+set/gi,
        score: 3,
        description: 'UPDATE SET injection'
      },
      
      // Order by injection
      {
        name: 'order-by',
        pattern: /order\s+by/gi,
        score: 2,
        description: 'ORDER BY injection'
      },
      {
        name: 'group-by',
        pattern: /group\s+by/gi,
        score: 2,
        description: 'GROUP BY injection'
      },
      {
        name: 'having-clause',
        pattern: /having\s+/gi,
        score: 2,
        description: 'HAVING clause injection'
      },
      
      // Limit and offset
      {
        name: 'limit-offset',
        pattern: /limit\s+\d+.*offset/gi,
        score: 2,
        description: 'LIMIT OFFSET injection'
      },
      
      // Common SQL operators
      {
        name: 'like-operator',
        pattern: /like\s+['"]%/gi,
        score: 2,
        description: 'LIKE operator with wildcard'
      },
      {
        name: 'in-operator',
        pattern: /in\s*\(/gi,
        score: 2,
        description: 'IN operator injection'
      },
      {
        name: 'between-operator',
        pattern: /between\s+/gi,
        score: 2,
        description: 'BETWEEN operator injection'
      },
      
      // Subqueries
      {
        name: 'subquery-select',
        pattern: /\(\s*select\s+/gi,
        score: 3,
        description: 'Subquery SELECT injection'
      },
      {
        name: 'exists-subquery',
        pattern: /exists\s*\(/gi,
        score: 2,
        description: 'EXISTS subquery injection'
      },
      
      // Common SQL injection payloads
      {
        name: 'admin-bypass',
        pattern: /admin'--/gi,
        score: 3,
        description: 'Admin bypass attempt'
      },
      {
        name: 'or-true',
        pattern: /or\s+true/gi,
        score: 3,
        description: 'OR TRUE injection'
      },
      {
        name: 'or-false',
        pattern: /or\s+false/gi,
        score: 3,
        description: 'OR FALSE injection'
      }
    ];
  }

  /**
   * Analyze request for SQL injection threats
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
            type: 'sqli',
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
        module: 'sqli'
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
    
    // Check for union with information schema
    if (text.includes('union') && text.includes('information_schema')) {
      threats.push({
        type: 'sqli',
        pattern: 'union-information-schema',
        description: 'UNION with INFORMATION_SCHEMA access',
        score: 5,
        matched: 'UNION with INFORMATION_SCHEMA access'
      });
    }
    
    // Check for time-based injection with sleep
    if (text.includes('sleep') && (text.includes('union') || text.includes('or'))) {
      threats.push({
        type: 'sqli',
        pattern: 'time-based-union',
        description: 'Time-based injection with UNION',
        score: 5,
        matched: 'Time-based injection with UNION'
      });
    }
    
    // Check for stacked queries
    if (text.includes(';') && (text.includes('select') || text.includes('drop'))) {
      threats.push({
        type: 'sqli',
        pattern: 'stacked-queries',
        description: 'Stacked queries injection',
        score: 4,
        matched: 'Stacked queries injection'
      });
    }
    
    // Check for comment injection with SQL keywords
    if ((text.includes('--') || text.includes('#')) && 
        (text.includes('select') || text.includes('union'))) {
      threats.push({
        type: 'sqli',
        pattern: 'comment-sql-keywords',
        description: 'Comment injection with SQL keywords',
        score: 4,
        matched: 'Comment injection with SQL keywords'
      });
    }
    
    return threats;
  }
}

module.exports = SQLiModule;
