import { expect, test } from '@playwright/test'

test.describe('本机无登录控制台', () => {
  test('直接进入对话控制台，不显示登录流程', async ({ page }) => {
    await page.goto('/')

    await expect(page.getByText('仅本机模式 · 无登录')).toHaveCount(0)
    await expect(page.locator('.chat-input')).toBeVisible()
    await expect(page.getByRole('button', { name: '新建研判' })).toBeVisible()
    await expect(page).not.toHaveURL(/login/)
  })

  test('旧登录地址会回到控制台', async ({ page }) => {
    await page.goto('/login')

    await expect(page).toHaveURL(/\/$/)
    await expect(page.locator('.chat-input')).toBeVisible()
  })

  test('高风险处置 API 拒绝未确认的封禁请求', async ({ request }) => {
    const response = await request.post(`${process.env.E2E_API_URL || 'http://127.0.0.1:8010'}/api/dispatch`, {
      data: { action: 'block', ip: '203.0.113.42' },
    })

    expect(response.status()).toBe(409)
    await expect(response.json()).resolves.toMatchObject({
      detail: expect.stringContaining('确认'),
    })
  })

  test('封禁按钮必须显示二次确认对话框', async ({ page }) => {
    await page.route('**/api/events/e2e-001', async (route) => {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          id: 'e2e-001', title: '测试来源地址', severity: '高危', status: 'open',
          source_ip: '203.0.113.42', confidence: 0.91, techniques: [], iocs: [],
          recommendation: [], raw_data: {}, created_at: '2026-09-03T00:00:00Z',
        }),
      })
    })

    await page.goto('/events/e2e-001')
    await expect(page.getByRole('button', { name: '封禁来源 IP' })).toBeVisible()
    await page.getByRole('button', { name: '封禁来源 IP' }).click()
    const dialog = page.locator('.n-dialog')
    await expect(dialog.getByText('确认封禁来源 IP')).toBeVisible()
    await expect(dialog).toContainText('203.0.113.42')
    await expect(dialog.getByRole('button', { name: '确认封禁' })).toBeVisible()
  })
})
