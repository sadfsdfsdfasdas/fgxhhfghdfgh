import crypto from 'crypto';
import { ipManager } from '../utils/ipManager.js';

export const securityMiddleware = {
  // Prevent debugger
  injectAntiDebug: (req, res, next) => {
    if (req.path.endsWith('.html')) {
      res.header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline';");
      
      // Inject anti-debug script at the top of HTML files
      const antiDebugScript = `
        <script>
          (function() {
            const antiDebug = () => {
              debugger;
              
              // Detect and disable various dev tools
              const checkDevTools = () => {
                const widthThreshold = window.outerWidth - window.innerWidth > 160;
                const heightThreshold = window.outerHeight - window.innerHeight > 160;
                if (widthThreshold || heightThreshold) {
                  document.body.innerHTML = '';
                  window.location.reload();
                }
              };

              // Randomize function names and objects
              const r = Math.random().toString(36).substring(7);
              const w = window;
              const d = document;
              
              // Disable right-click
              d.addEventListener('contextmenu', e => e.preventDefault());
              
              // Disable keyboard shortcuts
              d.addEventListener('keydown', e => {
                if (
                  (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
                  (e.ctrlKey && e.key === 'U') ||
                  e.key === 'F12'
                ) {
                  e.preventDefault();
                  return false;
                }
              });

              // Detect and block Puppeteer/Selenium
              const automationCheck = {
                checkChrome: () => {
                  return Boolean(w.chrome);
                },
                checkPermissions: async () => {
                  try {
                    await navigator.permissions.query({name:'notifications'});
                    return true;
                  } catch {
                    return false;
                  }
                },
                checkWebDriver: () => {
                  return Boolean(navigator.webdriver);
                }
              };

              // Additional protection layers
              setInterval(checkDevTools, 1000);
              
              // Clear console
              console.clear();
              
              // Disable console output
              const consoleProperties = ['log', 'debug', 'info', 'warn', 'error', 'dir', 'trace'];
              consoleProperties.forEach(prop => {
                console[prop] = () => {};
              });

              // Recursive setTimeout to make it harder to bypass
              setTimeout(antiDebug, Math.random() * 1000);
            };

            antiDebug();
            
            // Additional layer of protection
            (() => {
              let start = new Date().getTime();
              debugger;
              if (new Date().getTime() - start > 100) {
                window.location.reload();
              }
            })();
          })();
        </script>
      `;

      // Function to add random noise to confuse automated tools
      const addNoise = (html) => {
        const noise = Array.from({ length: 50 }, () => 
          `<!-- ${crypto.randomBytes(20).toString('hex')} -->`
        ).join('\n');
        return html.replace('</head>', `${noise}</head>`);
      };

      // Store original send
      const originalSend = res.send;

      // Override send method
      res.send = function (body) {
        if (typeof body === 'string' && body.includes('<!DOCTYPE html>')) {
          // Add anti-debug script and noise to HTML
          body = body.replace('</head>', `${antiDebugScript}</head>`);
          body = addNoise(body);
        }
        return originalSend.call(this, body);
      };
    }
    next();
  },

  // Prevent automated tools
  preventAutomation: (req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    const automatedTools = [
      'phantomjs', 'selenium', 'headless', 'puppet', 'playwright',
      'cypress', 'webdriver', 'chrome-lighthouse'
    ];

    if (automatedTools.some(tool => userAgent.toLowerCase().includes(tool))) {
      return res.status(403).send('Access denied');
    }

    next();
  },

  // Add dynamic resource names
  dynamicResources: (req, res, next) => {
    const originalSendFile = res.sendFile;
    res.sendFile = function(path) {
      // Generate dynamic name for JavaScript files
      if (path.endsWith('.js')) {
        const newFileName = `${crypto.randomBytes(16).toString('hex')}.js`;
        // Store mapping for future requests
        req.app.locals.fileMap = req.app.locals.fileMap || new Map();
        req.app.locals.fileMap.set(newFileName, path);
      }
      return originalSendFile.call(this, path);
    };
    next();
  },

  // Rate limiting
  rateLimit: (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    req.app.locals.requestCounts = req.app.locals.requestCounts || new Map();
    const requestCount = req.app.locals.requestCounts.get(ip) || { count: 0, firstRequest: now };
    
    if (now - requestCount.firstRequest > 60000) {
      // Reset if more than a minute has passed
      requestCount.count = 1;
      requestCount.firstRequest = now;
    } else if (requestCount.count > 100) {
      // If more than 100 requests per minute
      ipManager.banIP(ip);
      return res.status(429).send('Too many requests');
    } else {
      requestCount.count++;
    }
    
    req.app.locals.requestCounts.set(ip, requestCount);
    next();
  }
};

// Export middleware chain
export const secureServer = (app) => {
  app.use(securityMiddleware.injectAntiDebug);
  app.use(securityMiddleware.preventAutomation);
  app.use(securityMiddleware.dynamicResources);
  app.use(securityMiddleware.rateLimit);
  
  // Set security headers
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'no-referrer',
      'Feature-Policy': "camera 'none'; microphone 'none'; geolocation 'none'",
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    next();
  });
};