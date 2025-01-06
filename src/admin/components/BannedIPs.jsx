import React from 'react';
import { useAdminSocket } from '../contexts/AdminSocket';
import { Ban, Unlock, Shield, AlertTriangle } from 'lucide-react';

export default function BannedIPs() {
  const { bannedIPs, unbanIP } = useAdminSocket();

  return (
    <div className="relative h-full"> {/* Removed mt-8 and added h-full */}
      {/* Background blur effect with pulsing glow */}
      <div className="absolute inset-0 rounded-2xl bg-white/5 blur-xl" />
      <div className="absolute inset-0 rounded-2xl bg-gradient-to-b from-white/[0.08] to-transparent backdrop-blur-xl animate-pulse-subtle" />
      
      {/* Frosted glass card */}
      <div className="relative rounded-2xl border border-white/20 
                    backdrop-blur-xl bg-white/5 p-6
                    transition-all duration-500
                    hover:shadow-[0_0_30px_rgba(255,255,255,0.05)]">
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 rounded-lg bg-white/10 backdrop-blur-xl">
            <Shield className="h-5 w-5 text-red-400" />
          </div>
          <h2 className="text-xl font-semibold text-white">Banned IPs</h2>
        </div>
        
        <div className="space-y-2">
          {Array.from(bannedIPs).length > 0 ? (
            Array.from(bannedIPs).map((ip) => (
              <div key={ip} className="group relative">
                {/* Enhanced background glow on hover */}
                <div className="absolute inset-0 rounded-xl transition-all duration-500
                             bg-gradient-to-r from-red-500/5 via-red-500/0 to-transparent
                             opacity-0 group-hover:opacity-100
                             blur-xl" />
                
                {/* IP Item */}
                <div className="relative flex items-center justify-between p-4 
                             rounded-xl border border-white/10 backdrop-blur-lg
                             transition-all duration-300
                             hover:border-red-500/20
                             active:scale-[0.98]">
                  <div className="flex items-center space-x-3">
                    <div className="p-2 rounded-lg bg-white/5 group-hover:bg-white/10 
                                transition-colors duration-300">
                      <Ban className="h-4 w-4 text-red-400" />
                    </div>
                    <span className="text-gray-100 font-medium">{ip}</span>
                  </div>
                  
                  {/* Unban Button with enhanced effects */}
                  <button
                    onClick={() => unbanIP(ip)}
                    className="flex items-center space-x-2 px-3 py-1.5 rounded-lg
                             bg-white/5 hover:bg-white/10 
                             border border-white/10 hover:border-blue-500/20
                             transition-all duration-300
                             group/btn
                             active:scale-95"
                    title="Unban this IP address"
                  >
                    <Unlock className="h-4 w-4 text-blue-400 group-hover/btn:text-blue-300" />
                    <span className="text-sm text-blue-400 group-hover/btn:text-blue-300">Unban</span>
                  </button>
                </div>
              </div>
            ))
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-gray-400">
              <div className="p-4 rounded-full bg-white/5 mb-4">
                <AlertTriangle className="h-8 w-8 text-gray-500" />
              </div>
              <p className="text-lg font-medium">No Banned IPs</p>
              <p className="text-sm text-gray-500 mt-1 text-center">
                IPs that get banned will appear here<br />
                You can ban IPs from the Active Sessions panel
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}