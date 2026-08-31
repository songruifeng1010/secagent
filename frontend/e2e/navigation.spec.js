// ═══════════════════════════════════════════════════════════════
// SecAgentX E2E: 导航路由测试
// ═══════════════════════════════════════════════════════════════
import { test, expect } from '@playwright/test'
import { E2E_PASSWORD } from './test-config.js'

test.describe('导航', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.fill('input[placeholder*="用户"]', 'admin')
    await page.fill('input[type="password"]', E2E_PASSWORD)
    await page.getByRole('button', { name: /登\s*录/ }).click()
    await page.waitForURL(/\/dashboard$/)
  })

  const NAV_LINKS = [
    { path: '/agents', label: 'Agent' },
    { path: '/events', label: '事件' },
    { path: '/dashboard', label: '仪表' },
    { path: '/knowledge/mitre', label: '知识' },
    { path: '/settings', label: '设置' },
  ]

  for (const link of NAV_LINKS) {
    test(`导航到 ${link.path}`, async ({ page }) => {
      await page.goto(link.path)
      await page.waitForTimeout(2000)
      expect(page.url()).toContain(link.path)
    })
  }
})
