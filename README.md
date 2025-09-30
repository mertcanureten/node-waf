# Node-WAF

Node.js için Açık Kaynak Web Application Firewall - OWASP Top 10 saldırı vektörlerine karşı kapsamlı, modüler ve community-driven çözüm.

## 🚀 Özellikler

- **Adaptive Learning Mode**: Uygulama trafiğini öğrenerek false positive oranını minimize eder
- **Modüler Yapı**: İhtiyacınıza göre güvenlik modüllerini seçin
- **OWASP Top 10 Koruması**: XSS, SQLi, NoSQLi, ReDoS ve daha fazlası
- **Çoklu Framework Desteği**: Express, Koa, Fastify
- **Community Rules**: Sürekli güncellenen kural setleri
- **Prometheus Entegrasyonu**: Metrikler ve monitoring
- **Sıfır Konfigürasyon**: Varsayılan ayarlarla hemen kullanıma hazır

## 📦 Kurulum

```bash
npm install node-waf
```

## 🎯 Hızlı Başlangıç

```javascript
const express = require('express');
const waf = require('node-waf');

const app = express();

// WAF'i etkinleştir
app.use(waf());

app.get('/', (req, res) => {
  res.json({ message: 'Güvenli API!' });
});

app.listen(3000);
```

## 🔧 Gelişmiş Kullanım

```javascript
const waf = require('node-waf');

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

## 🛡️ Desteklenen Saldırı Türleri

- **XSS (Cross-Site Scripting)**
- **SQL Injection**
- **NoSQL Injection**
- **GraphQL Injection**
- **ReDoS (Regular Expression Denial of Service)**
- **Rate Limiting**
- **Header Security**

## 📈 Roadmap

- [x] v0.1 - Express middleware ve temel kurallar
- [x] v0.2 - Anomaly scoring ve config dosyası desteği
- [x] v0.3 - Adaptive learning mode ve Prometheus
- [ ] v1.0 - Multi-framework support ve community rules

## 🤝 Katkıda Bulunma

Bu proje açık kaynak! Katkılarınızı bekliyoruz.

## 📄 Lisans

MIT License

## 🔗 Bağlantılar

- [GitHub](https://github.com/node-waf/node-waf)
- [NPM](https://www.npmjs.com/package/node-waf)
- [Dokümantasyon](https://node-waf.dev)
