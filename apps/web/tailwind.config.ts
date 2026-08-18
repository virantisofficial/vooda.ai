import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        dark: {
          50: "#e8eaed",
          100: "#c4c8d0",
          200: "#9ea4b0",
          300: "#787f90",
          400: "#5b6478",
          500: "#3e4960",
          600: "#384258",
          700: "#30394e",
          800: "#283044",
          900: "#1a2138",
          950: "#111828",
        },
        brand: {
          50: "#e0f7fa",
          100: "#b2ebf2",
          200: "#80deea",
          300: "#4dd0e1",
          400: "#26c6da",
          500: "#00bcd4",
          600: "#00acc1",
          700: "#0097a7",
          800: "#00838f",
          900: "#006064",
        },
        accent: {
          orange: "#f97316",
          red: "#ef4444",
          pink: "#ec4899",
          purple: "#a855f7",
          cyan: "#22d3ee",
          green: "#22c55e",
          yellow: "#eab308",
        },
        severity: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#22c55e",
          info: "#6b7280",
        },
      },
      backgroundImage: {
        "gradient-cta": "linear-gradient(135deg, #a855f7 0%, #ec4899 100%)",
        "gradient-card": "linear-gradient(135deg, rgba(30,41,59,0.8) 0%, rgba(30,41,59,0.4) 100%)",
        "gradient-sidebar": "linear-gradient(180deg, #1a2138 0%, #111828 100%)",
      },
      boxShadow: {
        "card": "0 1px 3px rgba(0,0,0,0.3), 0 1px 2px rgba(0,0,0,0.2)",
        "card-hover": "0 4px 12px rgba(0,0,0,0.4), 0 2px 4px rgba(0,0,0,0.3)",
        "glow-cyan": "0 0 20px rgba(34,211,238,0.15)",
        "glow-orange": "0 0 20px rgba(249,115,22,0.15)",
        "glow-red": "0 0 20px rgba(239,68,68,0.15)",
      },
    },
  },
  plugins: [],
};
export default config;
