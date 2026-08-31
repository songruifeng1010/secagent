// ═══════════════════════════════════════════════════════════════
// SecAgentX E2E: 知识库浏览
// ═══════════════════════════════════════════════════════════════
import { test, expect } from '@playwright/test'
import { E2E_PASSWORD } from './test-config.js'

test.describe('知识库', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.fill('input[placeholder*="用户"]', 'admin')
    await page.fill('input[type="password"]', E2E_PASSWORD)
    await page.getByRole('button', { name: /登\s*录/ }).click()
    await page.waitForURL(/\/dashboard$/)
  })

  test('知识库页面加载', async ({ page }) => {
    await page.goto('/knowledge/mitre')
    await expect(page.locator('text=ATT&CK 知识库')).toBeVisible({ timeout: 15000 })
  })

  test('CVE 标签页可搜索', async ({ page }) => {
    await page.goto('/knowledge/cve')
    await page.waitForTimeout(2000)
    const searchInput = page.locator('input[placeholder*="CVE"]')
    await expect(searchInput).toBeVisible({ timeout: 10000 })
  })

  test('合规法规标签页有内容', async ({ page }) => {
    await page.goto('/knowledge/owasp')
    await page.waitForTimeout(2000)
    await expect(page.locator('text=合规')).toBeVisible({ timeout: 10000 })
  })
})
