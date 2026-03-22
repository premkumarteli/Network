import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react-chartjs-2') || id.includes('chart.js')) {
              return 'charts'
            }
            if (id.includes('framer-motion')) {
              return 'motion'
            }
            if (id.includes('react-router-dom')) {
              return 'router'
            }
            if (id.includes('axios') || id.includes('socket.io-client')) {
              return 'network'
            }
          }
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/socket.io': {
        target: 'http://127.0.0.1:8000',
        ws: true,
      }
    }
  }
})
