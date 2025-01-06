import React, { useState, useEffect } from 'react';
import { useAdminSocket } from '../contexts/AdminSocket';
import { X, AlertCircle, CheckCircle, Info } from 'lucide-react';

export default function NotificationBar({ onClose }) {
  const [notifications, setNotifications] = useState([]);
  const { sessions, settings, bannedIPs } = useAdminSocket();

  useEffect(() => {
    // Listen for changes and create notifications
    const newNotification = (type, message) => {
      const notification = {
        id: Date.now(),
        type,
        message,
        timestamp: new Date().toLocaleTimeString()
      };
      setNotifications(prev => [notification, ...prev].slice(0, 50)); // Keep last 50 notifications
    };

    // Session notifications
    const sessionListener = (session) => {
      newNotification('info', `New session: ${session.id} from ${session.ip}`);
    };

    // Settings notifications
    const settingsListener = (newSettings) => {
      const changes = Object.entries(newSettings)
        .filter(([key, value]) => settings[key] !== value)
        .map(([key, value]) => `${key}: ${value}`);
      
      if (changes.length > 0) {
        newNotification('success', `Settings updated: ${changes.join(', ')}`);
      }
    };

    // IP ban notifications
    const banListener = (ip) => {
      newNotification('warning', `IP banned: ${ip}`);
    };

    return () => {
      // Cleanup if needed
    };
  }, [settings]);

  const getNotificationIcon = (type) => {
    switch (type) {
      case 'success':
        return <CheckCircle className="h-5 w-5 text-ios-green" />;
      case 'warning':
        return <AlertCircle className="h-5 w-5 text-ios-red" />;
      case 'info':
      default:
        return <Info className="h-5 w-5 text-ios-blue" />;
    }
  };

  return (
    <div className="card">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold">Notifications</h2>
        <button
          onClick={onClose}
          className="p-1 hover:bg-gray-100 rounded-lg"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      <div className="space-y-2 max-h-96 overflow-y-auto">
        {notifications.map((notification) => (
          <div
            key={notification.id}
            className={`p-3 rounded-lg flex items-start space-x-3 ${
              notification.type === 'success' ? 'bg-green-50' :
              notification.type === 'warning' ? 'bg-red-50' : 'bg-blue-50'
            }`}
          >
            {getNotificationIcon(notification.type)}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900">
                {notification.message}
              </p>
              <p className="text-xs text-gray-500">
                {notification.timestamp}
              </p>
            </div>
          </div>
        ))}

        {notifications.length === 0 && (
          <div className="text-center py-4 text-gray-500">
            No notifications yet
          </div>
        )}
      </div>
    </div>
  );
}