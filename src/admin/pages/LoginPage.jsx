import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { AlertCircle, Check, Lock } from 'lucide-react';
import startupSound from './startup.mp3';

const LoginPage = () => {
  const [accessKey, setAccessKey] = useState('');
  const [error, setError] = useState('');
  const [isShaking, setIsShaking] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const { login } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const audioRef = useRef(new Audio(startupSound));

  // Initialize audio
  useEffect(() => {
    audioRef.current.preload = 'auto';
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    await handleLogin();
  };

  const handleLogin = async () => {
    if (!accessKey.trim() || isLoading || isSuccess) return;
    
    setError('');
    setIsLoading(true);

    try {
      await login(accessKey);
      setIsSuccess(true);
      // Play startup sound on success
      audioRef.current.play().catch(err => console.error('Audio play error:', err));
      if (window.navigator.vibrate) {
        window.navigator.vibrate([10, 30, 10]);
      }
    } catch (err) {
      setError(err.message);
      setIsShaking(true);
      if (window.navigator.vibrate) {
        window.navigator.vibrate(50);
      }
      setTimeout(() => setIsShaking(false), 500);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-[#1A1A1A] flex items-center justify-center px-4">
      <div className={`
        w-full max-w-md transform transition-all duration-500
        ${isShaking ? 'animate-shake' : ''}
        ${isSuccess ? 'scale-110 opacity-0' : 'scale-100 opacity-100'}
      `}>
        <div className="relative group">
          <div className="absolute inset-0 bg-white/5 rounded-2xl blur-lg transition-all duration-300 group-hover:bg-white/10" />
          <div className={`
            relative bg-white/10 backdrop-blur-xl rounded-2xl border border-white/20 p-8
            transition-all duration-500
            ${isSuccess ? 'translate-y-10' : 'translate-y-0'}
          `}>
            {/* Success overlay */}
            <div className={`
              absolute inset-0 bg-blue-500 rounded-2xl flex items-center justify-center
              transition-all duration-300 pointer-events-none
              ${isSuccess ? 'opacity-100 scale-100' : 'opacity-0 scale-95'}
            `}>
              <Check className="w-16 h-16 text-white" />
            </div>

            {/* Form content */}
            <div className={`transition-opacity duration-300 ${isSuccess ? 'opacity-0' : 'opacity-100'}`}>
              <div className="text-center mb-8">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-white/10 mb-4">
                  <Lock className="w-8 h-8 text-blue-400" />
                </div>
                <h2 className="text-2xl font-semibold text-gray-100 mb-2">
                  Pickle Panel
                </h2>
                <p className="text-gray-400">
                  Please enter your access key to continue
                </p>
              </div>

              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <div className={`
                    relative rounded-lg border backdrop-blur-xl
                    transition-all duration-300 
                    ${error ? 'border-red-500/50 bg-red-500/5' : 'border-white/10 bg-white/5'}
                    ${isLoading ? 'opacity-50' : ''}
                  `}>
                    <input
                      type="password"
                      value={accessKey}
                      onChange={(e) => setAccessKey(e.target.value)}
                      onKeyPress={(e) => {
                        if (e.key === 'Enter') {
                          handleLogin();
                        }
                      }}
                      className="
                        block w-full px-4 py-3 rounded-lg
                        bg-transparent text-gray-100
                        placeholder-gray-500
                        focus:outline-none
                      "
                      placeholder="Enter access key"
                      disabled={isLoading || isSuccess}
                    />
                  </div>
                  {error && (
                    <div className="mt-2 flex items-center text-red-400 text-sm">
                      <AlertCircle className="w-4 h-4 mr-1" />
                      {error}
                    </div>
                  )}
                </div>

                <button
                  onClick={handleLogin}
                  type="button"
                  className={`
                    w-full py-3 px-4 rounded-lg
                    bg-blue-500 text-white font-medium
                    transition-all duration-300
                    hover:bg-blue-600 cursor-pointer
                    focus:outline-none focus:ring-2 focus:ring-blue-500/50
                    disabled:opacity-50 disabled:cursor-not-allowed
                    active:scale-[0.99]
                  `}
                  disabled={isLoading || isSuccess}
                >
                  {isLoading ? 'Verifying...' : 'Continue'}
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;