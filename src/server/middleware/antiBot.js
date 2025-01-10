// antiBot.js
import { getIPDetails } from './ipUtils.js';

const SUSPICIOUS_UA_PATTERNS = [
  // Basic bot patterns
  /bot(?!source)/i, /crawler/i, /spider/i, /headless/i,
  // Tools and libraries
  /python|node-fetch|axios|request|http/i,
  /curl|wget|postman|insomnia|HTTrack/i,
  // Automation frameworks
  /selenium|puppeteer|cypress|playwright|phantom/i,
  /webdriver|chromedriver|geckodriver/i,
  // Empty or suspicious
  /^$|\(.*\)$|\s+/,
  // Known bad bots
  /zgrab|masscan|nikto|nmap|nuclei|burp|acunetix/i,
  // Suspicious clients
  /facebook|whatsapp|telegram|viber/i
];

const LEGITIMATE_BOT_SIGNATURES = [
  {
    name: /googlebot/i,
    hostname: /\.googlebot\.com$/i,
    reverse: /google\.com$/i
  },
  {
    name: /bingbot/i,
    hostname: /\.msn\.com$/i,
    reverse: /msn\.com$/i
  },
  {
    name: /yandex/i,
    hostname: /\.yandex\.(ru|com)$/i,
    reverse: /yandex\.(ru|com)$/i
  }
];

const BROWSER_FEATURES = [
  'localStorage',
  'sessionStorage',
  'indexedDB',
  'webGL',
  'canvas',
  'permissions',
  'serviceWorker',
];

const REQUIRED_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
  'user-agent'
];

const SUSPICIOUS_HEADERS = [
  'headless',
  'selenium',
  'driver',
  'webdriver',
  'puppeteer',
  'cypress',
  'playwright',
  'phantom',
  'automation',
  'chrome-automation',
  'safari-automation'
];

export function createBotProtection() {
  const clientScores = new Map();
  const accessAttempts = new Map();
  const verifiedClients = new Map();
  const blockedPatterns = new Set();
  
  async function verifyLegitimateBot(userAgent, clientIP) {
    try {
      // Find matching bot signature
      const botSignature = LEGITIMATE_BOT_SIGNATURES.find(bot => 
        bot.name.test(userAgent)
      );
      
      if (!botSignature) return false;

      // Get IP details including reverse DNS
      const ipDetails = await getIPDetails(clientIP);
      if (!ipDetails.hostname) return false;

      // Verify hostname matches expected pattern
      return botSignature.hostname.test(ipDetails.hostname) &&
             botSignature.reverse.test(ipDetails.hostname);
    } catch (error) {
      console.error('Bot verification error:', error);
      return false;
    }
  }

  function generateClientFingerprint(req) {
    const components = [
      req.headers['user-agent'],
      req.headers['accept-language'],
      req.headers['accept-encoding'],
      req.headers['sec-ch-ua'],
      req.headers['sec-ch-ua-platform'],
      req.headers['sec-ch-ua-mobile']
    ].filter(Boolean);

    return components.join('|');
  }

  return {
    async checkBot(req, res, next) {
      const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || 
                      req.headers['x-real-ip'] || 
                      req.socket.remoteAddress;
                      
      const userAgent = req.headers['user-agent'] || '';
      const path = req.path.toLowerCase();
      
      // Skip checks for static assets and admin panel
      if ((!path.endsWith('.html') && !path.endsWith('/')) || 
          path.includes('/admin')) {
        return next();
      }

      // Block direct page access
      if (path.includes('/pages/')) {
        return res.redirect('/');
      }

      try {
        const fingerprint = generateClientFingerprint(req);
        const key = `${clientIP}:${fingerprint}`;

        // Check if client is already verified
        if (verifiedClients.has(key)) {
          const verified = verifiedClients.get(key);
          if (Date.now() - verified.timestamp < 3600000) { // 1 hour
            return next();
          }
          verifiedClients.delete(key);
        }

        // Initialize scoring
        if (!clientScores.has(key)) {
          clientScores.set(key, 0);
        }
        
        // Track attempts
        if (!accessAttempts.has(key)) {
          accessAttempts.set(key, {
            count: 0,
            firstAttempt: Date.now(),
            patterns: new Set()
          });
        }

        const attempts = accessAttempts.get(key);
        let score = clientScores.get(key);

        // Check for legitimate bots first
        if (await verifyLegitimateBot(userAgent, clientIP)) {
          verifiedClients.set(key, {
            timestamp: Date.now(),
            type: 'legitimate_bot'
          });
          return next();
        }

        // Behavior Pattern Analysis
        attempts.count++;
        attempts.patterns.add(path);

        // Suspicious access patterns
        if (attempts.count > 8 && 
            (Date.now() - attempts.firstAttempt) < 30000) { // 8 attempts within 30 seconds
          score += 40;
        }

        if (attempts.patterns.size > 5 && 
            (Date.now() - attempts.firstAttempt) < 60000) { // 5 different paths within 1 minute
          score += 30;
        }

        // User Agent Analysis
        if (!userAgent) {
          score += 50;
        } else {
          // Check for suspicious patterns
          for (const pattern of SUSPICIOUS_UA_PATTERNS) {
            if (pattern.test(userAgent)) {
              score += 25;
              break;
            }
          }

          // Check for inconsistent browser strings
          const browserInfo = {
            chrome: /chrome/i.test(userAgent),
            safari: /safari/i.test(userAgent),
            firefox: /firefox/i.test(userAgent),
            mobile: /mobile/i.test(userAgent)
          };

          if ((browserInfo.chrome && browserInfo.safari && !browserInfo.mobile) || 
              (browserInfo.firefox && browserInfo.safari)) {
            score += 30;
          }
        }

        // Header Analysis
        const headers = new Set(Object.keys(req.headers).map(h => h.toLowerCase()));
        
        // Check for required headers
        const missingHeaders = REQUIRED_HEADERS.filter(h => !headers.has(h));
        if (missingHeaders.length > 0) {
          score += 10 * missingHeaders.length;
        }

        // Check for suspicious headers
        SUSPICIOUS_HEADERS.forEach(header => {
          if (headers.has(header.toLowerCase())) {
            score += 25;
          }
        });

        // Modern Browser Feature Detection
        const modernHeaders = [
          'sec-ch-ua',
          'sec-ch-ua-mobile',
          'sec-ch-ua-platform',
          'sec-fetch-dest',
          'sec-fetch-mode',
          'sec-fetch-site'
        ];

        const missingModernHeaders = modernHeaders.filter(h => !headers.has(h));
        if (missingModernHeaders.length === modernHeaders.length) {
          score += 20; // Missing all modern headers is suspicious
        }

        // Connection Information
        if (!req.headers.connection || 
            !['keep-alive', 'upgrade'].includes(req.headers.connection.toLowerCase())) {
          score += 10;
        }

        // Accept Header Analysis
        const accept = req.headers.accept || '';
        if (!accept.includes('text/html') || !accept.includes('image/')) {
          score += 15;
        }

        // Language Header Analysis
        const acceptLanguage = req.headers['accept-language'] || '';
        if (!acceptLanguage || acceptLanguage === '*') {
          score += 15;
        }

        // Update client score with decay
        const oldScore = clientScores.get(key);
        const decayedScore = Math.max(0, oldScore - 5); // Natural score decay
        const newScore = Math.min(100, decayedScore + score);
        clientScores.set(key, newScore);

        // Check if score exceeds threshold
        if (newScore >= 100) {
          console.log(`Bot detected: ${key} (Score: ${newScore})`);
          blockedPatterns.add(fingerprint);
          return res.status(403).redirect('/');
        }

        // If score is very low, add to verified clients
        if (newScore < 20 && attempts.count > 3) {
          verifiedClients.set(key, {
            timestamp: Date.now(),
            type: 'verified_human'
          });
        }

        // Cleanup old entries periodically (5% chance per request)
        if (Math.random() < 0.05) {
          const now = Date.now();
          for (const [k, attempt] of accessAttempts.entries()) {
            if (now - attempt.firstAttempt > 3600000) { // 1 hour
              accessAttempts.delete(k);
              clientScores.delete(k);
            }
          }

          // Clean up verified clients older than 2 hours
          for (const [k, verified] of verifiedClients.entries()) {
            if (now - verified.timestamp > 7200000) {
              verifiedClients.delete(k);
            }
          }

          // Clear old blocked patterns
          if (blockedPatterns.size > 1000) {
            blockedPatterns.clear();
          }
        }

        next();
      } catch (error) {
        console.error('Bot detection error:', error);
        next();
      }
    },

    resetScores() {
      clientScores.clear();
      accessAttempts.clear();
      verifiedClients.clear();
      blockedPatterns.clear();
    },

    getStats() {
      return {
        clientScores: clientScores.size,
        accessAttempts: accessAttempts.size,
        verifiedClients: verifiedClients.size,
        blockedPatterns: blockedPatterns.size
      };
    }
  };
}