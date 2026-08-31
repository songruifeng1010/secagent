/// <reference types="vitest" />
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'

const projectRoot = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig({
  // 使用配置文件位置作为根目录，避免 Windows、符号链接或映射盘启动时
  // 将测试文件错误解析为驱动器根目录下的 /src。
  root: projectRoot,
  plugins: [vue()],
  // 相对路径打包：产物使用 ./assets/... 而非 /assets/...
  // 这样在 OpenIM 的 /secagentx/ 子路径部署时资源能正确加载，
  // 避免绝对路径 /assets/ 被 OpenIM 站点根拦截（返回其 index.html）
  base: './',
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.{test,spec}.{js,ts}'],
    setupFiles: [],
  },
  build: {
    // 启用 CSS 代码分割，避免 CSS 文件过大
    cssCodeSplit: true,
    // 启用 Tree Shaking，减小打包体积
    minify: 'oxc',
    // 生产禁用源码映射
    sourcemap: false,
    rollupOptions: {
      output: {
        // Vite 8/Rolldown 使用函数式分包；同时兼容 Windows 与 POSIX 路径。
        manualChunks(id) {
          const path = id.replaceAll('\\', '/')
          if (path.includes('/node_modules/echarts/') || path.includes('/node_modules/zrender/')) {
            return 'vendor-charts'
          }
          if (path.includes('/node_modules/naive-ui/')) return 'vendor-ui'
          if (path.includes('/node_modules/@vicons/')) return 'vendor-icons'
          if (
            path.includes('/node_modules/vue/') ||
            path.includes('/node_modules/@vue/') ||
            path.includes('/node_modules/vue-router/') ||
            path.includes('/node_modules/pinia/')
          ) {
            return 'vendor-vue'
          }
          return undefined
        },
      },
    },
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
})
