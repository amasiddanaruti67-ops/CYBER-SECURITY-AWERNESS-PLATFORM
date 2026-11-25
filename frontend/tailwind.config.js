/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#F4F7FB",
        panel: "#FFFFFF",
        line: "#E2E8F0",
        cyan: "#087E8B",
        amber: "#A16207",
        danger: "#C6284D",
      },
      fontFamily: {
        sans: ["Segoe UI", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["Cascadia Mono", "Consolas", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
