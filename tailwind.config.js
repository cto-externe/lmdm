/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./internal/webui/templates/**/*.templ",
    "./internal/webui/components/**/*.templ",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50:  "#eef3f8",
          500: "#2563eb",
          600: "#1d4ed8",
          700: "#1e40af",
        },
      },
    },
  },
  plugins: [],
};
