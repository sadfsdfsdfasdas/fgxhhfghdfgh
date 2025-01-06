// src/server/utils/SessionPageManager.js
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';

class SessionPageManager {
    constructor(pagesPath) {
        this.pagesPath = pagesPath;
        this.sessions = new Map();
        this.urlToSession = new Map();
        this.verifiedSessions = new Set();
        this.sessionPages = new Map();
        this.initializePageMappings();
    }

    initializePageMappings() {
        // Map URLs to their corresponding HTML files
        this.pageMap = new Map(
            fs.readdirSync(this.pagesPath)
                .filter(file => file.endsWith('.html'))
                .map(file => [
                    file.replace('.html', ''),
                    path.join(this.pagesPath, file)
                ])
        );
    }

    generateSessionId() {
        return crypto.randomUUID();
    }

    initializePages() {
        const pages = fs.readdirSync(this.pagesPath)
            .filter(file => file.endsWith('.html'))
            .map(file => ({
                path: join(this.pagesPath, file),
                name: file.replace('.html', '')
            }));
    
        console.log('Initializing pages:', pages.map(p => p.name));
    
        for (const page of pages) {
            this.pageMap.set(page.name, page.path);
        }
        
        // Also store with .html extension for flexibility
        for (const page of pages) {
            this.pageMap.set(page.name + '.html', page.path);
        }
    }

    createSession(clientIP, userAgent) {
        const sessionId = this.generateSessionId();
        const oauthChallenge = crypto.randomUUID();
        
        const session = {
            id: sessionId,
            oauthChallenge,
            clientIP,
            userAgent,
            createdAt: Date.now(),
            lastAccessed: Date.now(),
            currentPage: 'awaiting',
            verified: false
        };

        this.sessions.set(sessionId, session);
        return session;
    }

    validateSession(clientId, oauthChallenge) {
        const session = this.sessions.get(clientId);
        return session && session.oauthChallenge === oauthChallenge;
    }

    verifySession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.verified = true;
            this.verifiedSessions.add(sessionId);
        }
    }

    isVerified(sessionId) {
        return this.verifiedSessions.has(sessionId);
    }

    getSessionPage(clientId, page) {
        const session = this.sessions.get(clientId);
        if (!session) return null;

        const pagePath = this.pageMap.get(page);
        if (!pagePath) return null;

        session.lastAccessed = Date.now();
        session.currentPage = page;

        return pagePath;
    }

    constructPageUrl(sessionId, page) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;

        return `/${page}?client_id=${sessionId}&oauth_challenge=${session.oauthChallenge}`;
    }

    cleanupSessions(maxAge = 30 * 60 * 1000) { // 30 minutes default
        const now = Date.now();
        for (const [sessionId, session] of this.sessions.entries()) {
            if (now - session.lastAccessed > maxAge) {
                this.sessions.delete(sessionId);
                this.verifiedSessions.delete(sessionId);
            }
        }
    }

    // For handling page transitions
    isValidPageTransition(fromPage, toPage) {
        // Add logic here for valid page transitions if needed
        return true;
    }
}

export default SessionPageManager;