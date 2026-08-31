// ═══════════════════════════════════════════════════════════════
// SecAgentX E2E: 聊天交互
// ═══════════════════════════════════════════════════════════════
import { test, expect } from '@playwright/test'
import { E2E_PASSWORD } from './test-config.js'

test.describe('Chat 聊天', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.fill('input[placeholder*="用户"]', 'admin')
    await page.fill('input[type="password"]', E2E_PASSWORD)
    await page.getByRole('button', { name: /登\s*录/ }).click()
    await page.waitForURL(/\/dashboard$/)
    await page.goto('/')
  })

  test('聊天页面加载并显示快速回复按钮', async ({ page }) => {
    await expect(page.locator('.quick-btn').first()).toBeVisible({ timeout: 10000 })
    expect(await page.locator('.quick-btn').count()).toBeGreaterThanOrEqual(3)
  })

  test('输入框可输入发送', async ({ page }) => {
    const input = page.locator('textarea')
    await expect(input).toBeVisible()
    await input.fill('测试消息')
    await expect(input).toHaveValue('测试消息')
  })

  test('发送按钮状态绑定', async ({ page }) => {
    const sendBtn = page.locator('.send-btn')
    await expect(sendBtn).toBeDisabled()
    await page.locator('textarea').fill('测试')
    await expect(sendBtn).toBeEnabled()
  })

  test('WebSocket 连接状态显示', async ({ page }) => {
    await page.waitForTimeout(3000)
    const statusBar = page.locator('.ws-status-bar')
    await expect(statusBar).toBeVisible()
  })
})
