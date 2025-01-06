import { getIPDetails } from '../utils/ipUtils.js';

// VPN/Proxy check using enhanced IP detection
export async function checkVPN(ip, settings) {
    try {
        const details = await getIPDetails(ip);
        
        // Log the details for debugging
        console.log('IP Details:', {
            ip: details.ip,
            isVPN: details.isVPN,
            isProxy: details.isProxy,
            isTor: details.isTor,
            location: `${details.city}, ${details.region}, ${details.country}`
        });

        // Detect any proxy-like service
        const isProxyService = details.isVPN || details.isProxy || details.isTor;

        if (isProxyService && settings?.vpnBlockEnabled) {
            console.log(`VPN/Proxy detected for IP ${ip} - protection active`);
            return {
                blocked: true,
                details,
                redirectUrl: settings.redirectUrl || 'https://google.com'
            };
        }

        return {
            blocked: false,
            details,
            redirectUrl: null
        };
    } catch (error) {
        console.error('VPN check error:', error);
        // Fail open - don't block users if the check fails
        return {
            blocked: false,
            details: null,
            error: error.message
        };
    }
}

export function checkBot(userAgent) {
    if (!userAgent) return true;
    
    const botPatterns = [
        /bot/i,
        /crawler/i,
        /spider/i,
        /headless/i,
        /selenium/i,
        /puppet/i,
        /playwright/i,
        /cypress/i,
        /chrome-lighthouse/i,
        /pingdom/i,
        /pagespeed/i
    ];

    return botPatterns.some(pattern => pattern.test(userAgent));
}

// Enhanced bot behavior detection
export function checkBotBehavior(req) {
    const suspiciousHeaders = [
        'headless',
        'selenium',
        'webdriver',
        'phantom',
        'nightmare'
    ];

    // Check for suspicious headers
    for (const header of suspiciousHeaders) {
        if (req.headers[header]) {
            console.log(`Suspicious header detected: ${header}`);
            return true;
        }
    }

    // Add additional checks as needed
    const isHighFrequency = checkRequestFrequency(req);
    const hasInvalidFingerprint = checkBrowserFingerprint(req);

    return isHighFrequency || hasInvalidFingerprint;
}

// Implement request frequency checking
function checkRequestFrequency(req) {
    // TODO: Implement rate limiting logic
    return false;
}

// Implement browser fingerprint validation
function checkBrowserFingerprint(req) {
    // TODO: Implement fingerprint validation logic
    return false;
}

export const antiBotUtils = {
    checkRequestFrequency,
    checkBrowserFingerprint
};