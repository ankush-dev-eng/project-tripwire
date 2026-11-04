/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: '#14181B',
          light: '#181E22',
          dark: '#0E1113',
        },
        basalt: {
          DEFAULT: '#1D2327',
          light: '#252C31',
          border: '#2A3339',
        },
        bone: {
          DEFAULT: '#F2EFE8',
          muted: '#C8C4B7',
        },
        stone: {
          DEFAULT: '#D9D4C7',
          muted: '#8A8578',
          dark: '#3A3F44',
        },
        sage: {
          DEFAULT: '#6F8F7B',
          light: '#8BAA96',
          bg: 'rgba(111, 143, 123, 0.12)',
        },
        moss: {
          DEFAULT: '#4F7A5A',
          light: '#659672',
          bg: 'rgba(79, 122, 90, 0.12)',
        },
        brass: {
          DEFAULT: '#C79A3B',
          light: '#DDB357',
          bg: 'rgba(199, 154, 59, 0.12)',
        },
        copper: {
          DEFAULT: '#B5693E',
          light: '#CF8052',
          bg: 'rgba(181, 105, 62, 0.12)',
        },
        brick: {
          DEFAULT: '#A8403A',
          light: '#C4544D',
          bg: 'rgba(168, 64, 58, 0.12)',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}

