import React, { useState, useEffect } from 'react';
import { useAdminSocket } from './contexts/AdminSocket';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Dashboard from './components/Dashboard';
import SessionList from './components/SessionList';
import Settings from './components/Settings';
import BannedIPs from './components/BannedIPs';
import LoginPage from './pages/LoginPage';
import MacOSLayout from './components/MacOSLayout';
import { LogOut } from 'lucide-react';

const AppContent = () => {
  const { isConnected } = useAdminSocket();
  const { isAuthenticated, logout } = useAuth();
  const [activeView, setActiveView] = useState('dashboard');
  const [isAppearing, setIsAppearing] = useState(false);

  useEffect(() => {
    if (isAuthenticated) {
      setTimeout(() => setIsAppearing(true), 300);
    } else {
      setIsAppearing(false);
    }
  }, [isAuthenticated]);

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  if (!isConnected) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#0A0A0A]">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-100 mb-2">Connecting to server...</h1>
          <p className="text-gray-400">Please wait while we establish connection</p>
        </div>
      </div>
    );
  }

  return (
    <MacOSLayout activeView={activeView} onViewChange={setActiveView}>
      <div className={`
        transition-all duration-700 ease-out px-6 py-6
        ${isAppearing ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}
      `}>
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold text-gray-100">
            {activeView === 'dashboard' ? 'Dashboard' : 'Settings'}
          </h1>
          <button
            onClick={logout}
            className="group relative px-4 py-2 rounded-xl 
                     bg-red-500/10 hover:bg-red-500/20
                     border border-red-500/20 hover:border-red-500/30
                     transition-all duration-300
                     flex items-center space-x-2"
          >
            <LogOut className="w-5 h-5 text-red-400" />
            <span className="text-red-400">Logout</span>
            
            {/* Hover glow effect */}
            <div className="absolute inset-0 rounded-xl bg-red-400/20 blur-lg 
                          opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
          </button>
        </div>

        {activeView === 'dashboard' ? (
          <div className="space-y-6">
            <Dashboard />
            <SessionList />
          </div>
        ) : (
          <div className="space-y-6">
            <Settings />
          </div>
        )}
      </div>
    </MacOSLayout>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}