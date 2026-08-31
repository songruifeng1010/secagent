// ═══════════════════════════════════════════════════════════════
// SecAgentX E2E: 仪表盘页面
// ═══════════════════════════════════════════════════════════════
import { test, expect } from '@playwright/test'
import { E2E_PASSWORD } from './test-config.js'

test.describe('仪表盘', () => {
  test.beforeEach(async ({ page }) => {
    // 使用浏览器安全会话登录后访问仪表盘
    await page.goto('/login')
    await page.fill('input[placeholder*="用户"]', 'admin')
    await page.fill('input[type="password"]', E2E_PASSWORD)
    await page.getByRole('button', { name: /登\s*录/ }).click()
    await page.waitForURL(/\/dashboard$/)
  })

  test('仪表盘显示核心指标', async ({ page }) => {
    await page.goto('/dashboard')
    await expect(page.getByText('事件总数', { exact: true })).toBeVisible({ timeout: 10000 })
    await expect(page.getByText('Agent 数', { exact: true })).toBeVisible()
  })

  test('导航到事件列表', async ({ page }) => {
    await page.getByRole('menuitem', { name: '事件', exact: true }).click()
    await expect(page).toHaveURL(/\/events/)
    await expect(page.getByText('安全事件', { exact: true })).toBeVisible({ timeout: 10000 })
  })
})
