// src/server/middleware/pageServing.js
import { parse } from 'url';

export function createPageServingMiddleware(sessionPageManager) {
    return async (req, res, next) => {
        // Parse the URL and query parameters
        const parsedUrl = parse(req.url, true);
        const { clientId, oauthChallenge } = parsedUrl.query;
        
        // Get the requested page from the URL path
        const page = parsedUrl.pathname.substring(1); // Remove leading slash
        
        // Skip verification for static assets
        if (page.includes('.') && !page.endsWith('.html')) {
            return next();
        }

        // Verify session exists and is valid
        if (!clientId || !oauthChallenge || !sessionPageManager.validateSession(clientId, oauthChallenge)) {
            return res.redirect('/');
        }

        // If captcha enabled, verify completion
        if (process.env.CAPTCHA_ENABLED && !sessionPageManager.isVerified(clientId)) {
            return res.redirect('/');
        }

        // Get the page path and serve it
        const pagePath = sessionPageManager.getSessionPage(clientId, page);
        if (!pagePath) {
            return res.redirect(sessionPageManager.constructPageUrl(clientId, 'awaiting'));
        }

        // Set headers to prevent caching
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Surrogate-Control', 'no-store');

        // Serve the page
        res.sendFile(pagePath);
    };
}