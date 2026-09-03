import { beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch } from '../utils/http.js'

function response(status, body) {
  return { status, ok: status >= 200 && status < 300, json: vi.fn().mockResolvedValue(body), text: vi.fn().mockResolvedValue(JSON.stringify(body)) }
}

describe('本机控制台 HTTP 客户端', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('直接请求 API，不刷新令牌或使用 Cookie', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(response(200, { ok: true }))
    await expect(apiFetch('/agents')).resolves.toEqual({ ok: true })
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0][0]).toContain('/api/agents')
    expect(fetch.mock.calls[0][1].credentials).toBeUndefined()
  })

  it('网络失败最多按调用方请求重试两次', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'))
    await expect(apiFetch('/events', { retries: 99 })).rejects.toThrow('fetch failed')
    expect(fetch).toHaveBeenCalledTimes(3)
  })
})
