# Node-WAF

Open Source Web Application Firewall for Node.js - A comprehensive, modular, and community-driven solution against OWASP Top 10 attack vectors.

## 🚀 Features

- **Adaptive Learning Mode**: Learns from application traffic to minimize false positive rates
- **Modular Architecture**: Choose security modules based on your needs
- **OWASP Top 10 Protection**: XSS, SQLi, NoSQLi, ReDoS and more
- **Multi-Framework Support**: Express, Koa, Fastify
- **Community Rules**: Continuously updated rule sets
- **Prometheus Integration**: Metrics and monitoring
- **Zero Configuration**: Ready to use with default settings

## 📦 Installation

```bash
npm install @mertcanureten/node-waf
```

## 🎯 Quick Start

```javascript
const express = require('express');
const waf = require('@mertcanureten/node-waf');

const app = express();

// Enable WAF
app.use(waf());

app.get('/', (req, res) => {
  res.json({ message: 'Secure API!' });
});

app.listen(3000);
```

## 🔧 Advanced Usage

```javascript
const waf = require('@mertcanureten/node-waf');

app.use(waf({
  modules: ['xss', 'sqli', 'ratelimit'],
  adaptiveLearning: true,
  dryRun: false,
  threshold: 10
}));
```

## 📊 Monitoring

```javascript
// Stats endpoint
app.get('/waf/stats', waf.stats());

// Prometheus metrics
app.get('/metrics', waf.metrics());
```

## 🛡️ Supported Attack Types

- **XSS (Cross-Site Scripting)**
- **SQL Injection**
- **NoSQL Injection**
- **GraphQL Injection**
- **ReDoS (Regular Expression Denial of Service)**
- **Rate Limiting**
- **Header Security**

## 📈 Roadmap

- [x] v0.1 - Express middleware and basic rules
- [x] v0.2 - Anomaly scoring and config file support
- [x] v0.3 - Adaptive learning mode and Prometheus
- [ ] v1.0 - Multi-framework support and community rules

## 🤝 Contributing

This project is open source! We welcome your contributions.

## 📄 License

MIT License

## 🔗 Links

- [GitHub](https://github.com/mertcanureten/node-waf)
- [NPM](https://www.npmjs.com/package/@mertcanureten/node-waf)
- [Documentation](https://github.com/mertcanureten/node-waf#readme)
