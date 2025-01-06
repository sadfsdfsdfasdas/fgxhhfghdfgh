import React, { useState, useEffect } from 'react';
import { useAdminSocket } from '../contexts/AdminSocket';
import { Globe, Shield, Bot, Link, FileCode, Skull } from 'lucide-react';
import BannedIPs from './BannedIPs';

const SettingToggle = ({ icon: Icon, title, description, enabled, onToggle, color }) => {
  const [isHovered, setIsHovered] = useState(false);
  const [isPressed, setIsPressed] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);
  const [hasChanged, setHasChanged] = useState(false);

  useEffect(() => {
    if (hasChanged) {
      const timer = setTimeout(() => setHasChanged(false), 1000);
      return () => clearTimeout(timer);
    }
  }, [hasChanged]);

  useEffect(() => {
    if (isAnimating) {
      const timer = setTimeout(() => setIsAnimating(false), 750);
      return () => clearTimeout(timer);
    }
  }, [isAnimating]);

  const getIconColor = () => {
    if (!enabled) return 'text-white/50';
    if (Icon === Skull) return enabled ? 'text-red-500' : 'text-white/50';
    switch (color) {
      case 'green': return 'text-green-400';
      case 'blue': return 'text-blue-400';
      case 'purple': return 'text-purple-400';
      case 'red': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getIconAnimation = () => {
    if (Icon === Skull && enabled) {
      return 'animate-pulse hover:animate-bounce';
    }
    return enabled ? 'animate-pulse-subtle' : '';
  };

  const handleToggle = () => {
    setHasChanged(true);
    setIsAnimating(true);
    onToggle();
  };

  return (
    <div 
      className="group relative px-4 py-3.5 transition-all duration-500 hover:bg-white/[0.03]"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {/* Special skull glow effect */}
      {enabled && Icon === Skull && (
        <div className="absolute inset-0 bg-red-500/5 animate-pulse-slow" />
      )}

      {/* Status change animation */}
      {hasChanged && (
        <div className={`
          absolute inset-0 bg-${color}-500/20
          animate-[fadeOut_1s_ease-out]
        `} />
      )}

      {/* Active state glow with enhanced animations */}
      {enabled && (
        <>
          <div className={`
            absolute inset-0 blur-2xl transition-all duration-1000
            bg-gradient-to-r ${
              Icon === Skull ? 'from-red-500/20 to-orange-500/10' :
              color === 'green' ? 'from-green-500/10' : 
              color === 'blue' ? 'from-blue-500/10' : 
              color === 'purple' ? 'from-purple-500/10' : 
              'from-red-500/10'} to-transparent
            animate-pulse-subtle
            ${isAnimating ? 'scale-110 opacity-75' : 'scale-100 opacity-50'}
          `} />
          <div className={`
            absolute inset-0 blur-md
            bg-gradient-to-r ${
              Icon === Skull ? 'from-red-500/30 to-orange-500/20' :
              color === 'green' ? 'from-green-500/20' : 
              color === 'blue' ? 'from-blue-500/20' : 
              color === 'purple' ? 'from-purple-500/20' : 
              'from-red-500/20'} to-transparent
            transition-opacity duration-500
            ${isAnimating ? 'opacity-100' : 'opacity-0'}
          `} />
        </>
      )}

      <div className="flex flex-col lg:flex-row lg:items-center justify-between space-y-3 lg:space-y-0">
        <div className="flex items-center space-x-3">
          <div className={`
            p-2 rounded-lg backdrop-blur-sm
            ${enabled ? Icon === Skull ? 'bg-red-500/20' : 'bg-white/10' : 'bg-white/5'}
            transform transition-all duration-300
            ${isHovered ? 'scale-110 rotate-3' : 'scale-100 rotate-0'}
            ${isPressed ? 'scale-95' : ''}
            group-hover:shadow-lg ${Icon === Skull && enabled ? 'group-hover:shadow-red-500/20' : 'group-hover:shadow-white/5'}
          `}>
            <Icon className={`
              w-5 h-5 
              ${getIconColor()}
              transition-all duration-500
              transform
              ${isAnimating ? 'scale-125 rotate-180' : 'scale-100'}
              ${getIconAnimation()}
              group-hover:scale-110
              ${hasChanged && enabled ? 'animate-bounce' : ''}
              ${Icon === Skull && enabled ? 'animate-pulse' : ''}
            `} />
          </div>
          <div className="transition-transform duration-300 group-hover:translate-x-1">
            <h3 className="text-sm font-medium text-white/90">{title}</h3>
            <p className="text-xs text-white/50 mt-0.5 transition-opacity duration-300
                       group-hover:text-white/60">
              {description}
            </p>
          </div>
        </div>

        {/* Toggle switch */}
        <button
          onClick={handleToggle}
          onMouseDown={() => setIsPressed(true)}
          onMouseUp={() => setIsPressed(false)}
          className={`
            relative w-12 h-7 rounded-full overflow-hidden
            transition-all duration-500 ease-[cubic-bezier(0.34,1.56,0.64,1)]
            ${enabled ? 
              Icon === Skull ? 'bg-red-500 hover:bg-red-400 shadow-lg shadow-red-500/30' :
              `bg-${color}-500 hover:bg-${color}-400 shadow-lg shadow-${color}-500/20` : 
              'bg-white/10 hover:bg-white/15'}
            ${isPressed ? 'scale-95' : 'scale-100'}
            ${isAnimating ? 'ring-2' : ''}
            ${Icon === Skull && enabled ? 'ring-red-400/50' :
              enabled ? `ring-${color}-400/50` : 'ring-white/20'}
            backdrop-blur-xl
            lg:ml-4
          `}
        >
          {/* Animation ripple effect */}
          {isAnimating && (
            <div className={`
              absolute inset-0 
              bg-gradient-to-r from-white/20 to-transparent
              animate-ripple
            `} />
          )}
          
          {/* Toggle handle */}
          <div className={`
            absolute top-1 w-5 h-5 rounded-full 
            transition-all duration-500 ease-[cubic-bezier(0.34,1.56,0.64,1)]
            ${enabled ? 
              'left-6 bg-white shadow-lg scale-110' : 
              'left-1 bg-white/90 scale-100'}
            ${isHovered && 'shadow-lg'}
            ${isAnimating && 'animate-pulse'}
          `}>
            {/* Inner glow */}
            <div className={`
              absolute inset-0 rounded-full
              bg-gradient-to-r from-white/50 to-white/20
              transition-opacity duration-300
              ${isHovered ? 'opacity-100' : 'opacity-0'}
            `} />
          </div>
        </button>
      </div>
    </div>
  );
};

const InputField = ({ icon: Icon, label, value, onChange, type = "text" }) => {
  const [isFocused, setIsFocused] = useState(false);
  const [isHovered, setIsHovered] = useState(false);

  return (
    <div className="group px-4 py-3.5 hover:bg-white/[0.03] transition-all duration-300"
         onMouseEnter={() => setIsHovered(true)}
         onMouseLeave={() => setIsHovered(false)}>
      <div className="flex flex-col lg:flex-row lg:items-center space-y-2 lg:space-y-0 lg:space-x-3">
        <div className={`
          p-2 rounded-lg backdrop-blur-sm
          transform transition-all duration-300
          ${isFocused ? 'bg-blue-500/10 scale-110 rotate-3' : 
            isHovered ? 'bg-white/10 scale-105' : 'bg-white/5 scale-100'}
        `}>
          <Icon className={`
            w-5 h-5 transition-all duration-300
            ${isFocused ? 'text-blue-400' : 'text-white/50'}
            ${isHovered && !isFocused && 'text-white/70'}
          `} />
        </div>
        <div className="flex-1 transition-transform duration-300 group-hover:translate-x-1">
          <label className="block text-sm font-medium text-white/90 mb-1.5">{label}</label>
          <input
            type={type}
            value={value}
            onChange={onChange}
            onFocus={() => setIsFocused(true)}
            onBlur={() => setIsFocused(false)}
            className={`
              w-full px-3 py-1.5 rounded-lg
              bg-white/5 border border-white/10 
              text-white/90 placeholder-white/30
              transition-all duration-300
              backdrop-blur-sm
              ${isFocused ? 
                'border-blue-500/50 ring-2 ring-blue-500/20 bg-white/10' : 
                'hover:border-white/20'}
            `}
            placeholder={`Enter ${label.toLowerCase()}`}
          />
        </div>
      </div>
    </div>
  );
};

const Card = ({ title, children }) => (
  <div className="relative rounded-2xl overflow-hidden group">
    {/* Background layers */}
    <div className="absolute inset-0 bg-white/[0.08] backdrop-blur-xl" />
    <div className="absolute inset-0 bg-gradient-to-b from-white/[0.05] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
    
    <div className="relative">
      <div className="px-4 py-3 border-b border-white/[0.06]">
        <h2 className="text-lg font-medium text-white/90 transition-transform duration-300 group-hover:translate-x-1">
          {title}
        </h2>
      </div>
      <div className="divide-y divide-white/[0.06]">
        {children}
      </div>
    </div>
  </div>
);

export default function Settings() {
  const { settings, updateSettings } = useAdminSocket();

  const handleToggle = (key) => {
    updateSettings({ ...settings, [key]: !settings[key] });
  };

  return (
    <div className="space-y-6 lg:space-y-0 lg:grid lg:grid-cols-12 lg:gap-6 px-4 lg:px-0">
      {/* Main Settings Column */}
      <div className="lg:col-span-8 space-y-6">
        {/* Security Settings Card */}
        <Card title="Security Settings">
          <SettingToggle
            icon={Globe}
            title="Website Status"
            description="Enable or disable the website"
            enabled={settings.websiteEnabled}
            onToggle={() => handleToggle('websiteEnabled')}
            color="green"
          />
          <SettingToggle
            icon={Shield}
            title="VPN/Proxy Blocking"
            description="Block access from VPN/Proxy connections"
            enabled={settings.vpnBlockEnabled}
            onToggle={() => handleToggle('vpnBlockEnabled')}
            color="blue"
          />
          <SettingToggle
            icon={Bot}
            title="Anti-Bot Protection"
            description="Enable bot detection and blocking"
            enabled={settings.antiBotEnabled}
            onToggle={() => handleToggle('antiBotEnabled')}
            color="purple"
          />
          <SettingToggle
            icon={Skull}
            title="Skulpt Button"
            description="Doesn't do anything"
            enabled={settings.captchaEnabled}
            onToggle={() => handleToggle('captchaEnabled')}
            color="red"
          />
        </Card>

        {/* Configuration Card */}
        <Card title="Configuration">
          <InputField
            icon={Link}
            label="Redirect URL"
            value={settings.redirectUrl}
            onChange={(e) => updateSettings({ ...settings, redirectUrl: e.target.value })}
            type="url"
          />
          <InputField
            icon={FileCode}
            label="Default Landing Page"
            value={settings.defaultLandingPage}
            onChange={(e) => updateSettings({ ...settings, defaultLandingPage: e.target.value })}
          />
        </Card>
      </div>

      {/* Banned IPs Column */}
      <div className="lg:col-span-4">
        <BannedIPs />
      </div>
    </div>
  );
}