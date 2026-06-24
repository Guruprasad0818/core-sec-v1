import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["SFMono-Regular", "Consolas", "Liberation Mono", "Menlo", "monospace"],
        sans: ["var(--font-inter)", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Helvetica", "Arial", "sans-serif"],
      },
      colors: {
        // Premium brand accent (active nav, loading states, non-severity chart
        // lines) - kept distinct from the red/amber/emerald/blue severity
        // vocabulary used by Badge so the two purposes never collide visually.
        brand: {
          DEFAULT: "#6366F1", // indigo-500
          light: "#818CF8", // indigo-400
        },
      },
      boxShadow: {
        "glow-critical": "0 0 0 1px rgba(239,68,68,0.15), 0 0 18px rgba(239,68,68,0.25)",
        "glow-emerald": "0 0 0 1px rgba(16,185,129,0.12), 0 0 16px rgba(16,185,129,0.2)",
        "glow-brand": "0 0 14px rgba(99,102,241,0.45)",
      },
    },
  },
  plugins: [],
};

export default config;
