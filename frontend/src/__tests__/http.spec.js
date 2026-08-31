import { beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch } from '../utils/http.js'

function response(status, body) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: vi.fn().mockResolvedValue(body),
    text: vi.fn().mockResolvedValue(JSON.stringify(body)),
  }
}

describe('apiFetch token refresh', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  it('refreshes the HttpOnly cookie session and replays the request once', async () => {
    localStorage.setItem('secagentx_authenticated', '1')
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(response(401, {}))
      .mockResolvedValueOnce(response(200, {
        status: 'ok',
      }))
      .mockResolvedValueOnce(response(200, { ok: true }))

    await expect(apiFetch('/events')).resolves.toEqual({ ok: true })
    expect(fetch).toHaveBeenCalledTimes(3)
    expect(localStorage.getItem('secagentx_authenticated')).toBe('1')
    expect(localStorage.getItem('secagentx_token')).toBeNull()
    expect(localStorage.getItem('secagentx_refresh_token')).toBeNull()
    expect(fetch.mock.calls[1][0]).toContain('/api/auth/web/refresh')
  })

  it('caps caller-requested network retries at two', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'))

    await expect(apiFetch('/events', { retries: 99 })).rejects.toThrow('fetch failed')
    expect(fetch).toHaveBeenCalledTimes(3)
  })
})
