/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/admin/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ios: {
          gray: '#f2f2f7',
          blue: '#007aff',
          green: '#34c759',
          red: '#ff3b30',
          yellow: '#ffcc00',
          orange: '#ff9500',
          purple: '#5856d6',
          pink: '#ff2d55'
        }
      },
      keyframes: {
        shake: {
          '0%, 100%': { transform: 'translateX(0)' },
          '20%': { transform: 'translateX(-2px)' },
          '40%': { transform: 'translateX(2px)' },
          '60%': { transform: 'translateX(-2px)' },
          '80%': { transform: 'translateX(2px)' }
        },
        scaleUp: {
          '0%': { transform: 'scale(0.95)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' }
        },
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' }
        },
        ripple: {
          '0%': { transform: 'scale(0)', opacity: '1' },
          '100%': { transform: 'scale(4)', opacity: '0' }
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' }
        },
        fadeOut: {
          '0%': { opacity: '1' },
          '100%': { opacity: '0' }
        },
        'pulse-subtle': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.5' }
        },
        highlight: {
          '0%': { backgroundColor: 'rgba(59, 130, 246, 0)' },
          '10%': { backgroundColor: 'rgba(59, 130, 246, 0.08)' },
          '90%': { backgroundColor: 'rgba(59, 130, 246, 0.08)' },
          '100%': { backgroundColor: 'rgba(59, 130, 246, 0)' }
        },
        'shift-bg': {
          '0%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
          '100%': { backgroundPosition: '0% 50%' }
        }
      },
      animation: {
        shake: 'shake 0.5s cubic-bezier(.36,.07,.19,.97) both',
        scaleUp: 'scaleUp 0.5s ease-out forwards',
        slideUp: 'slideUp 0.7s ease-out forwards',
        'pulse-subtle': 'pulse-subtle 6s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 8s linear infinite',
        'ripple': 'ripple 1s ease-out',
        'bounce-subtle': 'bounce 2s ease-in-out',
        'fadeIn': 'fadeIn 0.2s ease-out',
        'fadeOut': 'fadeOut 1s ease-out',
        'highlight': 'highlight 8s ease-out forwards',
        'shift-background': 'shift-bg 15s ease infinite'
      },
      transitionTimingFunction: {
        'spring': 'cubic-bezier(0.34,1.56,0.64,1)',
      },
      // Add new background blur utilities for layered glass effects
      backdropBlur: {
        'xs': '2px',
        'xxl': '32px',
      }
    }
  },
  plugins: []
}