/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Deep navy/black background
        background: {
          DEFAULT: '#0a0a0f',
          primary: '#0a0a0f',
          secondary: '#0f0f16',
          tertiary: '#1a1a24',
        },
        // Electric cyan
        cyan: {
          DEFAULT: '#00f0ff',
          hover: '#00c8d4',
          soft: 'rgba(0, 240, 255, 0.1)',
        },
        // Neon magenta
        magenta: {
          DEFAULT: '#ff00a0',
          hover: '#d60085',
          soft: 'rgba(255, 0, 160, 0.1)',
        },
        // Acid green
        success: {
          DEFAULT: '#39ff14',
          hover: '#2ed410',
          soft: 'rgba(57, 255, 20, 0.1)',
        },
        // Warning amber
        warning: {
          DEFAULT: '#ffb000',
          hover: '#d69600',
          soft: 'rgba(255, 176, 0, 0.1)',
        },
        // Critical crimson
        critical: {
          DEFAULT: '#ff003c',
          hover: '#d60032',
          soft: 'rgba(255, 0, 60, 0.1)',
        },
        // Text colors
        text: {
          primary: '#ffffff',
          secondary: '#b0b0b8',
          tertiary: '#6a6a75',
          dim: 'rgba(255, 255, 255, 0.7)',
        },
        // Border
        border: {
          DEFAULT: '#1f1f2e',
          hover: '#2f2f42',
          glow: 'rgba(0, 240, 255, 0.3)',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
        sans: ['"Inter"', '"SF Pro"', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
      },
      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1rem' }], // 12px - minimum for non-essential
        'sm': ['0.875rem', { lineHeight: '1.25rem' }], // 14px - WCAG AAA minimum
        'base': ['1rem', { lineHeight: '1.5rem' }],
        'lg': ['1.125rem', { lineHeight: '1.75rem' }],
        'xl': ['1.25rem', { lineHeight: '1.75rem' }],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px rgba(0, 240, 255, 0.5), 0 0 40px rgba(0, 240, 255, 0.3)',
        'glow-magenta': '0 0 20px rgba(255, 0, 160, 0.5), 0 0 40px rgba(255, 0, 160, 0.3)',
        'glow-green': '0 0 20px rgba(57, 255, 20, 0.5), 0 0 40px rgba(57, 255, 20, 0.3)',
        'glow-critical': '0 0 20px rgba(255, 0, 60, 0.5), 0 0 40px rgba(255, 0, 60, 0.3)',
        'panel': '0 4px 24px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.05)',
      },
      backgroundImage: {
        'grid-pattern': `linear-gradient(rgba(0, 240, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 240, 255, 0.03) 1px, transparent 1px)`,
        'scanline': 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 0, 0, 0.1) 2px, rgba(0, 0, 0, 0.1) 4px)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'flicker': 'flicker 0.15s infinite',
        'scan': 'scan 8s linear infinite',
        'blink': 'blink 1s step-end infinite',
        'progress': 'progress 1.5s ease-in-out infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 240, 255, 0.3)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 240, 255, 0.6), 0 0 30px rgba(0, 240, 255, 0.4)' },
        },
        flicker: {
          '0%, 100%': { opacity: '1' },
          '41%': { opacity: '1' },
          '42%': { opacity: '0.8' },
          '43%': { opacity: '1' },
          '45%': { opacity: '0.3' },
          '46%': { opacity: '1' },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        blink: {
          '0%, 50%': { opacity: '1' },
          '51%, 100%': { opacity: '0' },
        },
        progress: {
          '0%': { backgroundPosition: '0% 50%' },
          '100%': { backgroundPosition: '100% 50%' },
        },
      },
    },
  },
  plugins: [],
  corePlugins: {
    preflight: true,
  },
}
