import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import dns from 'dns';
import { URL } from 'url';
import axios from 'axios';
import * as cheerio from 'cheerio';
import punycode from 'punycode';
import levenshtein from 'fast-levenshtein';
import whois from 'whois';

// Configuration
const PORT = process.env.PORT || 3000;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 100; // 100 requests per window

// Known brands for phishing detection
const KNOWN_BRANDS = [
  'paypal', 'facebook', 'google', 'amazon', 'apple',
  'microsoft', 'netflix', 'instagram', 'twitter', 'linkedin',
  'ebay', 'wellsfargo', 'bankofamerica', 'chase', 'citibank'
];

// Initialize Express app
const app = express();

// Security middleware
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX
});
app.use(limiter);

// Logging
app.use(morgan('combined'));

// Body parsing
app.use(express.json({ limit: '10kb' }));

// Simple CommonJS-compatible Soundex function
const soundex = (s) => {
  if (!s) return '';
  s = s.toUpperCase().replace(/[^A-Z]/g, '');
  const firstLetter = s[0];
  const codes = { B:1, F:1, P:1, V:1, C:2, G:2, J:2, K:2, Q:2, S:2, X:2, Z:2, D:3, T:3, L:4, M:5, N:5, R:6 };
  let result = firstLetter;
  let lastCode = codes[firstLetter] || '';
  for (let i = 1; i < s.length; i++) {
    const c = s[i];
    const code = codes[c] || '';
    if (code !== lastCode) result += code;
    lastCode = code;
  }
  return (result + '0000').slice(0, 4);
};

// Helper functions
const validateUrl = (url) => {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Invalid protocol. Only HTTP/HTTPS URLs are allowed');
    }
    return true;
  } catch (err) {
    throw new Error(`Invalid URL: ${err.message}`);
  }
};

const resolveDns = async (domain) => {
  try {
    const ip = await dns.promises.lookup(domain);
    const mx = await dns.promises.resolveMx(domain).catch(() => []);
    return { ip: ip.address, hasMxRecords: mx.length > 0 };
  } catch (err) {
    return { ip: null, hasMxRecords: false };
  }
};

const detectPhishing = (domain) => {
  const domainParts = domain.replace('www.', '').split('.')[0];
  const results = [];

  KNOWN_BRANDS.forEach(brand => {
    const distance = levenshtein.get(domainParts, brand);
    const length = Math.max(domainParts.length, brand.length);
    const similarity = (1 - distance / length) * 100;

    const domainSoundex = soundex(domainParts);
    const brandSoundex = soundex(brand);
    const soundexMatch = domainSoundex === brandSoundex;

    const isPunycode = punycode.toASCII(domainParts) !== domainParts;

    if (similarity > 70 || soundexMatch || isPunycode) {
      results.push({ brand, similarity, soundexMatch, isPunycode });
    }
  });

  return results.length > 0 ? results[0] : null;
};

const followRedirects = async (url) => {
  let currentUrl = url;
  let redirectCount = 0;
  let finalUrl = url;
  let https = false;

  try {
    const response = await axios.head(currentUrl, {
      maxRedirects: 10,
      validateStatus: null,
      timeout: 5000
    });

    finalUrl = response.request.res.responseUrl || currentUrl;
    redirectCount = response.request._redirectable._redirectCount;
    https = new URL(finalUrl).protocol === 'https:';

    return { finalUrl, redirects: redirectCount, https };
  } catch (err) {
    return { finalUrl: currentUrl, redirects: 0, https: new URL(currentUrl).protocol === 'https:' };
  }
};

const analyzeContent = async (url) => {
  try {
    const response = await axios.get(url, {
      timeout: 5000,
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });

    const $ = cheerio.load(response.data);
    const title = $('title').text().trim();
    const description = $('meta[name="description"]').attr('content') || '';
    const forms = $('form').length;
    const scripts = $('script[src]').length;

    const phishingKeywords = ['login', 'password', 'verify', 'secure', 'account', 'banking', 'update'];
    const containsPhishingKeywords = phishingKeywords.some(keyword =>
      title.toLowerCase().includes(keyword) || description.toLowerCase().includes(keyword)
    );

    const favicon = $('link[rel="icon"], link[rel="shortcut icon"]').attr('href');
    let faviconHost = null;
    if (favicon) {
      try { faviconHost = new URL(favicon, url).hostname; } catch { faviconHost = null; }
    }

    return { title, description, forms, scripts, containsPhishingKeywords, faviconHost };
  } catch {
    return { title: null, description: null, forms: 0, scripts: 0, containsPhishingKeywords: false, faviconHost: null };
  }
};

const checkDomainAge = async (domain) => {
  try {
    const whoisData = await whois(domain);
    if (whoisData.creationDate) return new Date(whoisData.creationDate).toISOString().split('T')[0];
    return 'Unknown';
  } catch { return 'Unknown'; }
};

const scanVirusTotal = async (url) => {
  if (!VIRUSTOTAL_API_KEY) return null;
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(url)}`, {
      headers: { 'x-apikey': VIRUSTOTAL_API_KEY }, timeout: 5000
    });
    return response.data.data.attributes.last_analysis_stats;
  } catch { return null; }
};

const calculateScore = (analysis) => {
  let score = 100;
  if (!analysis.https) score -= 20;
  if (analysis.redirects > 2) score -= 10;
  if (analysis.relatedToKnownBrand) score -= 30;
  if (analysis.containsPhishingKeywords) score -= 25;
  if (analysis.faviconHost && analysis.faviconHost !== new URL(analysis.finalUrl).hostname) score -= 15;
  return Math.max(0, score);
};

const generateRecommendation = (score) => {
  if (score > 75) return 'This URL appears safe';
  if (score > 50) return 'Use caution with this URL';
  if (score > 25) return 'Warning: Potential risk with this URL';
  return 'Do not click this link. High risk detected';
};

// Main endpoint
app.post('/analyze', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });
    validateUrl(url);

    const result = { originalUrl: url, verdict: 'clean', score: 100, confidence: 0, aiFlagged: false, warnings: [], meta: {} };

    const redirectAnalysis = await followRedirects(url);
    Object.assign(result, redirectAnalysis);

    const domain = new URL(result.finalUrl).hostname;
    const dnsInfo = await resolveDns(domain);
    Object.assign(result, { domain, ipAddress: dnsInfo.ip, hasMxRecords: dnsInfo.hasMxRecords });

    const phishingDetection = detectPhishing(domain);
    if (phishingDetection) {
      result.relatedToKnownBrand = phishingDetection.brand;
      result.warnings.push({ type: 'brand', message: `Domain is similar to ${phishingDetection.brand} (${phishingDetection.similarity.toFixed(1)}% similarity)` });
    }

    const contentAnalysis = await analyzeContent(result.finalUrl);
    Object.assign(result.meta, {
      title: contentAnalysis.title,
      description: contentAnalysis.description,
      formCount: contentAnalysis.forms,
      scriptCount: contentAnalysis.scripts
    });

    if (contentAnalysis.containsPhishingKeywords) {
      result.containsPhishingKeywords = true;
      result.warnings.push({ type: 'content', message: 'Login/password related keywords detected' });
    }

    if (contentAnalysis.faviconHost && contentAnalysis.faviconHost !== domain) {
      result.faviconWarning = true;
      result.warnings.push({ type: 'favicon', message: `Favicon is hosted on different domain (${contentAnalysis.faviconHost})` });
    }

    result.domainAge = await checkDomainAge(domain);

    if (VIRUSTOTAL_API_KEY) result.virusTotal = await scanVirusTotal(result.finalUrl);

    result.score = calculateScore(result);
    result.confidence = 100 - result.warnings.length * 5;
    result.verdict = result.score > 75 ? 'clean' : result.score > 50 ? 'suspicious' : 'malicious';
    result.recommendation = generateRecommendation(result.score);
    result.aiFlagged = result.score < 50 || (result.relatedToKnownBrand && result.containsPhishingKeywords);

    return res.json(result);

  } catch (err) {
    console.error('Analysis error:', err);
    return res.status(400).json({ error: err.message || 'Failed to analyze URL', details: err.response?.data || null });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Smart URL Safety Checker API running on port ${PORT}`);
});
