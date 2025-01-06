import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = () => {
    const authData = JSON.parse(localStorage.getItem('adminAuth'));
    if (authData && authData.expiresAt && new Date().getTime() < authData.expiresAt) {
      setIsAuthenticated(true);
    } else {
      localStorage.removeItem('adminAuth');
      setIsAuthenticated(false);
    }
    setIsLoading(false);
  };

  const login = (accessKey) => {
    return new Promise((resolve, reject) => {
      // In a real app, you'd verify this with the backend
      if (accessKey === import.meta.env.VITE_ADMIN_KEY) {
        const expiresAt = new Date().getTime() + (24 * 60 * 60 * 1000); // 24 hours
        localStorage.setItem('adminAuth', JSON.stringify({
          expiresAt,
        }));
        setIsAuthenticated(true);
        resolve();
      } else {
        reject(new Error('Invalid access key'));
      }
    });
  };

  const logout = () => {
    localStorage.removeItem('adminAuth');
    setIsAuthenticated(false);
  };

  if (isLoading) {
    return null;
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};