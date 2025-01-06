// src/server/middleware/ipBlocker.js
import { ipManager } from '../utils/ipManager.js';

// Helper function to clean and standardize IP addresses
function cleanIPAddress(ip) {
    // Remove IPv6 prefix for IPv4 addresses
    ip = ip.replace(/^::ffff:/, '');
    
    // Handle IP addresses that might come in arrays or comma-separated lists
    if (ip.includes(',')) {
        // Take the first IP in the list (usually the real client IP)
        ip = ip.split(',')[0].trim();
    }
    
    return ip;
}

export function createIPBlocker(settings) {
    return function ipBlockerMiddleware(req, res, next) {
        // Get IP from various possible headers
        let clientIP = req.headers['x-forwarded-for'] || 
                      req.headers['x-real-ip'] || 
                      req.connection.remoteAddress ||
                      req.socket.remoteAddress;
        
        // Clean and standardize the IP
        const cleanIP = cleanIPAddress(clientIP);
        
        // Store clean IP in request object for later use
        req.cleanIP = cleanIP;
        
        // Check if IP is banned
        if (ipManager.isIPBanned(cleanIP)) {
            console.log(`Blocked banned IP: ${cleanIP}`);
            return res.redirect(settings.redirectUrl || 'https://google.com');
        }

        next();
    };
}