import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// 👇 ESSA LINHA RESOLVE O __dirname NO VITE
const __dirname = new URL('.', import.meta.url).pathname

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})