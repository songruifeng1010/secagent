/** 本机控制台的统一 HTTP 客户端：无 Cookie、无 CSRF、无令牌刷新。 */
const DEFAULT_TIMEOUT = 15000
const MAX_RETRIES = 2

function resolveApiBase() {
  const injected = import.meta.env && import.meta.env.VITE_API_BASE
  if (injected) return injected
  if (typeof window !== 'undefined' && window.location.pathname.startsWith('/secagentx/')) return '/secapi'
  return '/api'
}
const API_BASE = resolveApiBase()

export function buildApiUrl(path) {
  if (/^https?:\/\//.test(path)) return path
  if (API_BASE && path.startsWith(API_BASE)) return path
  return `${API_BASE}${path}`
}

export async function apiFetch(url, options = {}) {
  const { timeout = DEFAULT_TIMEOUT, retries = 0, ...fetchOptions } = options
  const maxRetries = Math.min(Math.max(Number.isInteger(retries) ? retries : 0, 0), MAX_RETRIES)
  let retryCount = 0
  while (true) {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)
    try {
      const response = await fetch(buildApiUrl(url), {
        ...fetchOptions,
        headers: { 'Content-Type': 'application/json', ...(fetchOptions.headers || {}) },
        signal: controller.signal,
      })
      clearTimeout(timeoutId)
      if (!response.ok) {
        const text = await response.text().catch(() => '')
        try {
          const data = JSON.parse(text)
          throw new Error(data.message || data.detail || data.error?.message || `HTTP ${response.status}`)
        } catch (error) {
          if (error.message !== 'Unexpected end of JSON input') throw error
          throw new Error(`HTTP ${response.status}${text ? `: ${text.slice(0, 100)}` : ''}`)
        }
      }
      return await response.json()
    } catch (error) {
      clearTimeout(timeoutId)
      if ((error.name === 'AbortError' || error instanceof TypeError) && retryCount < maxRetries) {
        retryCount += 1
        continue
      }
      if (error.name === 'AbortError') throw new Error(`请求超时 (${timeout}ms): ${url}`)
      throw error
    }
  }
}

export async function apiFetchWithLoading(url, loadingRef, options = {}) {
  if (loadingRef) loadingRef.value = true
  try { return await apiFetch(url, options) } finally { if (loadingRef) loadingRef.value = false }
}

export default apiFetch
