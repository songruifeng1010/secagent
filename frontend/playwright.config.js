// ═══════════════════════════════════════════════════════════
// Playwright E2E Test Configuration
// ═══════════════════════════════════════════════════════════
import { defineConfig, devices } from '@playwright/test'
import { E2E_PASSWORD } from './e2e/test-config.js'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['list'],
  ],

  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // 启动前端 dev server + 后端 API 作为测试环境
  webServer: [
    {
      command: 'node ./node_modules/vite/bin/vite.js',
      url: 'http://localhost:3000',
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
    },
    {
      command: 'cd .. && python -m backend.interface.api_server',
      url: 'http://localhost:8000/api/health',
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
      env: {
        SECAGENTX_PORT: '8000',
        SECAGENTX_JWT_SECRET: 'e2e-test-secret-at-least-32-chars-long!',
        SECAGENTX_PASSWORD: E2E_PASSWORD,
        FIREWALL_BACKEND: 'mock',
        LLM_PROVIDER: 'mock',
        SECAGENTX_ACTIVE_PROVIDER: 'mock',
        SECAGENTX_LLM_API_BASE: 'mock://local',
        SECAGENTX_LLM_MODEL: 'mock-llm',
        SECAGENTX_LLM_ALLOW_NO_KEY: 'true',
      },
    },
  ],
})
