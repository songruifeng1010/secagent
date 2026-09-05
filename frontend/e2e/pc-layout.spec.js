import { test, expect } from '@playwright/test'

// 125% 缩放对应较小的 CSS 可视区；此处验证重排，不冒充浏览器原生缩放测试。
for (const [width, height] of [[1280, 720], [1366, 768], [1440, 900], [1920, 1080], [1024, 576], [1093, 614]]) {
  test(`PC 对话控件在 ${width}×${height} 可视区内`, async ({ page }) => {
    await page.setViewportSize({ width, height })
    await page.goto('/')
    const input = page.locator('.chat-input')
    await expect(input).toBeVisible()
    await expect(page.locator('.workspace-dot')).toHaveClass(/connected/)
    await input.fill('检查布局')
    for (const selector of ['.chat-input', '.send-btn', '.workspace-tools', '.new-conv-btn']) {
      const box = await page.locator(selector).boundingBox()
      expect(box).not.toBeNull()
      expect(box.x).toBeGreaterThanOrEqual(0)
      expect(box.y).toBeGreaterThanOrEqual(0)
      expect(box.x + box.width).toBeLessThanOrEqual(width + 1)
      expect(box.y + box.height).toBeLessThanOrEqual(height + 1)
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
  })
}
