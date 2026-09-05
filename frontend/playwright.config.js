// ═══════════════════════════════════════════════════════════
// Playwright E2E Test Configuration
// ═══════════════════════════════════════════════════════════
import { defineConfig, devices } from '@playwright/test'

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
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:3100',
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
      command: `"${process.execPath}" ./node_modules/vite/bin/vite.js --host 127.0.0.1 --port 3100`,
      url: 'http://127.0.0.1:3100',
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
      env: {
        E2E_UI_PORT: '3100',
        E2E_API_PORT: '8010',
      },
    },
    {
      command: 'cd .. && python -m backend.interface.api_server',
      url: 'http://127.0.0.1:8010/api/health',
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
      env: {
        SECAGENTX_PORT: '8010',
        SECAGENTX_CORS_ORIGINS: 'http://127.0.0.1:3100,http://localhost:3100,http://127.0.0.1:8010',
        E2E_UI_PORT: '3100',
        E2E_API_PORT: '8010',
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
