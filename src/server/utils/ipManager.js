// src/server/utils/ipManager.js
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BANNED_IPS_FILE = path.join(__dirname, '../data/banned-ips.json');

// Ensure data directory exists
const dataDir = path.join(__dirname, '../data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

class IPManager {
    constructor() {
        this.bannedIPs = new Set();
        this.ipMap = new Map(); // For additional IP metadata
        this.loadBannedIPs();
    }

    loadBannedIPs() {
        try {
            // Create file if it doesn't exist
            if (!fs.existsSync(BANNED_IPS_FILE)) {
                fs.writeFileSync(BANNED_IPS_FILE, JSON.stringify({ bannedIPs: [], metadata: {} }));
            }

            const data = JSON.parse(fs.readFileSync(BANNED_IPS_FILE, 'utf8'));
            this.bannedIPs = new Set(data.bannedIPs);
            
            // Load metadata if exists
            if (data.metadata) {
                Object.entries(data.metadata).forEach(([ip, meta]) => {
                    this.ipMap.set(ip, meta);
                });
            }

            console.log(`Loaded ${this.bannedIPs.size} banned IPs`);
        } catch (error) {
            console.error('Error loading banned IPs:', error);
            this.bannedIPs = new Set();
            this.ipMap = new Map();
        }
    }

    saveBannedIPs() {
        try {
            const metadata = {};
            this.ipMap.forEach((meta, ip) => {
                metadata[ip] = meta;
            });

            const data = {
                bannedIPs: Array.from(this.bannedIPs),
                metadata
            };

            // Write to temporary file first
            const tempFile = `${BANNED_IPS_FILE}.temp`;
            fs.writeFileSync(tempFile, JSON.stringify(data, null, 2));
            
            // Rename temp file to actual file (atomic operation)
            fs.renameSync(tempFile, BANNED_IPS_FILE);
            
            console.log('Banned IPs saved successfully');
        } catch (error) {
            console.error('Error saving banned IPs:', error);
        }
    }

    isIPBanned(ip) {
        // Clean IP before checking
        ip = ip.replace(/^::ffff:/, '');
        return this.bannedIPs.has(ip);
    }

    banIP(ip, metadata = {}) {
        // Clean IP before banning
        ip = ip.replace(/^::ffff:/, '');
        
        this.bannedIPs.add(ip);
        this.ipMap.set(ip, {
            bannedAt: new Date().toISOString(),
            ...metadata
        });

        this.saveBannedIPs();
        return true;
    }

    unbanIP(ip) {
        // Clean IP before unbanning
        ip = ip.replace(/^::ffff:/, '');
        
        const result = this.bannedIPs.delete(ip);
        this.ipMap.delete(ip);
        this.saveBannedIPs();
        return result;
    }

    getAllBannedIPs() {
        return Array.from(this.bannedIPs);
    }

    getIPMetadata(ip) {
        return this.ipMap.get(ip) || null;
    }

    clearBannedIPs() {
        this.bannedIPs.clear();
        this.ipMap.clear();
        this.saveBannedIPs();
    }
}

// Create and export a singleton instance
export const ipManager = new IPManager();