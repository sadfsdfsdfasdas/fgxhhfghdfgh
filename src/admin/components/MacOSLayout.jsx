import React from 'react';
import { LayoutDashboard, Settings, LogOut } from 'lucide-react';

const MacOSLayout = ({ children, activeView, onViewChange }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0A0A0A] to-[#1A1A1A] text-gray-100">
      {/* Main Content Area with subtle grain texture */}
      <div className="min-h-screen pb-24 overflow-auto bg-[url('/noise.png')] bg-repeat">
        {children}
      </div>

      {/* Dock */}
      <div className="fixed bottom-6 left-1/2 -translate-x-1/2 flex justify-center">
        <div className="flex gap-4 p-3 rounded-2xl bg-white/15 backdrop-blur-2xl border border-white/20 shadow-2xl">
          <button
            onClick={() => onViewChange('dashboard')}
            className={`
              group relative p-3 rounded-xl transition-all duration-300
              hover:bg-white/25
              ${activeView === 'dashboard' 
                ? 'bg-white/25 shadow-lg' 
                : 'hover:scale-105'}
            `}
          >
            {/* Glow effect */}
            <div className={`
              absolute inset-0 rounded-xl blur opacity-40 transition-opacity duration-300
              bg-blue-400/50 ${activeView === 'dashboard' ? 'opacity-100' : 'opacity-0'}
            `} />
            
            <LayoutDashboard 
              className={`relative z-10 w-8 h-8 transition-all duration-300
                ${activeView === 'dashboard' 
                  ? 'text-blue-400 scale-110' 
                  : 'text-gray-300 group-hover:text-white'}`} 
            />

            {/* Dock tooltip */}
            <div className="absolute -top-8 left-1/2 -translate-x-1/2 px-3 py-1 rounded-md
                          bg-black/90 text-white text-sm opacity-0 group-hover:opacity-100
                          transition-opacity duration-200 pointer-events-none backdrop-blur-xl">
              Dashboard
            </div>
          </button>

          <button
            onClick={() => onViewChange('settings')}
            className={`
              group relative p-3 rounded-xl transition-all duration-300
              hover:bg-white/25
              ${activeView === 'settings' 
                ? 'bg-white/25 shadow-lg' 
                : 'hover:scale-105'}
            `}
          >
            {/* Glow effect */}
            <div className={`
              absolute inset-0 rounded-xl blur opacity-40 transition-opacity duration-300
              bg-blue-400/50 ${activeView === 'settings' ? 'opacity-100' : 'opacity-0'}
            `} />
            
            <Settings 
              className={`relative z-10 w-8 h-8 transition-all duration-300
                ${activeView === 'settings' 
                  ? 'text-blue-400 scale-110' 
                  : 'text-gray-300 group-hover:text-white'}`} 
            />

            {/* Dock tooltip */}
            <div className="absolute -top-8 left-1/2 -translate-x-1/2 px-3 py-1 rounded-md
                          bg-black/90 text-white text-sm opacity-0 group-hover:opacity-100
                          transition-opacity duration-200 pointer-events-none backdrop-blur-xl">
              Settings
            </div>
          </button>
        </div>
      </div>
    </div>
  );
};

export default MacOSLayout;