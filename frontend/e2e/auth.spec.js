// ═══════════════════════════════════════════════════════════════
// SecAgentX E2E: 登录/登出流程
// ═══════════════════════════════════════════════════════════════
import { test, expect } from '@playwright/test'
import { E2E_PASSWORD } from './test-config.js'

test.describe('认证流程', () => {
  test('未登录重定向到登录页', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveURL(/\/login/)
  })

  test('登录成功跳转到首页', async ({ page }) => {
    await page.goto('/login')
    await page.fill('input[placeholder*="用户"]', 'admin')
    await page.fill('input[type="password"]', E2E_PASSWORD)
    await page.getByRole('button', { name: /登\s*录/ }).click()
    await expect(page).toHaveURL(/\/dashboard$/)
  })

  test('错误密码提示', async ({ page }) => {
    await page.goto('/login')
    await page.fill('input[placeholder*="用户"]', 'admin')
    await page.fill('input[type="password"]', 'wrong-password')
    await page.getByRole('button', { name: /登\s*录/ }).click()
    await expect(page.locator('text=密码错误')).toBeVisible()
  })
})
