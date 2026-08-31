/**
 * SecAgentX 统一 HTTP 客户端
 *
 * 功能：
 * - 自动超时控制（默认 15 秒）
 * - 统一错误处理
 * - Web HttpOnly Cookie 会话与 CSRF 自动附加
 * - 请求失败重试（可选）
 */

const DEFAULT_TIMEOUT = 15000  // 15 秒默认超时
const MAX_RETRIES = 2         // 最大重试次数
const SESSION_MARKER = 'secagentx_authenticated'

function readCookie(name) {
  if (typeof document === 'undefined') return ''
  const prefix = `${encodeURIComponent(name)}=`
  return document.cookie.split(';').map(v => v.trim())
    .find(v => v.startsWith(prefix))?.slice(prefix.length) || ''
}

export function hasWebSession() {
  try { return localStorage.getItem(SESSION_MARKER) === '1' } catch { return false }
}

export function markWebSession(active) {
  try {
    if (active) localStorage.setItem(SESSION_MARKER, '1')
    else localStorage.removeItem(SESSION_MARKER)
    // v3.0 浏览器令牌不再保留；CLI Bearer 认证不受影响。
    localStorage.removeItem('secagentx_token')
    localStorage.removeItem('secagentx_refresh_token')
  } catch {}
}

/**
 * API 基础路径前缀 — 运行时自适应
 *
 * 两套部署环境共用同一份构建产物：
 *  1. FastAPI 直连（:8000 托管 dist）           → /api   前缀，后端直接处理
 *  2. OpenIM 集成（80 端口，页面挂 /secagentx/）→ /secapi 前缀，nginx 反代 /secapi→8000
 *
 * 判断逻辑：页面 URL 以 /secagentx/ 开头 → /secapi；否则 → /api。
 * 构建时 VITE_API_BASE 仍可显式覆盖（特殊部署用）。
 */
function resolveApiBase() {
  const injected = import.meta.env && import.meta.env.VITE_API_BASE
  if (injected) return injected
  if (typeof window !== 'undefined' && window.location.pathname.startsWith('/secagentx/')) {
    return '/secapi'
  }
  return '/api'
}
const API_BASE = resolveApiBase()

/**
 * 拼接 API 完整路径
 * 兼容绝对地址（http(s)://）与相对路径
 */
export function buildApiUrl(path) {
  if (/^https?:\/\//.test(path)) return path
  // 若 path 已含前缀（如 /secapi/api/events）则不重复拼接
  if (API_BASE && path.startsWith(API_BASE)) return path
  return `${API_BASE}${path}`
}

/**
 * 统一 API 请求函数
 * @param {string} url - API 路径（如 /api/events）
 * @param {object} options - fetch 选项
 * @param {number} options.timeout - 超时时间（毫秒）
 * @param {number} options.retries - 重试次数
 * @returns {Promise<any>} 解析后的 JSON 数据
 */
export async function apiFetch(url, options = {}) {
  const { timeout = DEFAULT_TIMEOUT, retries = 0, ...fetchOptions } = options
  const maxRetries = Math.min(Math.max(Number.isInteger(retries) ? retries : 0, 0), MAX_RETRIES)

  const headers = {
    'Content-Type': 'application/json',
    ...(fetchOptions.headers || {}),
  }
  const method = String(fetchOptions.method || 'GET').toUpperCase()
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrf = decodeURIComponent(readCookie('secagentx_csrf'))
    if (csrf) headers['X-CSRF-Token'] = csrf
  }

  let networkRetryCount = 0
  let refreshAttempted = false
  while (true) {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)

    try {
      const resp = await fetch(buildApiUrl(url), {
        ...fetchOptions,
        headers,
        credentials: fetchOptions.credentials || 'same-origin',
        signal: controller.signal,
      })
      clearTimeout(timeoutId)

      // 401 未授权 → 尝试刷新 Token
      if (resp.status === 401) {
        const refreshed = !refreshAttempted && await tryRefreshToken()
        refreshAttempted = true
        if (refreshed) {
          // 每个业务请求最多因 401 刷新并重放一次。
          continue
        }
        // 刷新失败 → 跳转登录
        markWebSession(false)
        window.location.href = '/login'
        throw new Error('登录已过期，请重新登录')
      }

      // 其他错误
      if (!resp.ok) {
        const errorBody = await resp.text().catch(() => '')
        let errorMsg
        try {
          const errJson = JSON.parse(errorBody)
          errorMsg = errJson.message || errJson.detail || `HTTP ${resp.status}`
        } catch {
          errorMsg = `HTTP ${resp.status}${errorBody ? ': ' + errorBody.substring(0, 100) : ''}`
        }
        throw new Error(errorMsg)
      }

      return await resp.json()
    } catch (e) {
      clearTimeout(timeoutId)
      if (e.name === 'AbortError') {
        if (networkRetryCount < maxRetries) {
          networkRetryCount += 1
          console.warn(`[apiFetch] 请求超时，重试第 ${networkRetryCount} 次: ${url}`)
          continue
        }
        throw new Error(`请求超时 (${timeout}ms): ${url}`)
      }

      // 网络错误可重试
      if (e.name === 'TypeError' && e.message.includes('fetch')) {
        if (networkRetryCount < maxRetries) {
          networkRetryCount += 1
          console.warn(`[apiFetch] 网络错误，重试第 ${networkRetryCount} 次: ${url}`)
          continue
        }
      }

      throw e
    }
  }
}

/**
 * 尝试刷新 JWT Token
 */
let refreshPromise = null

async function refreshTokens() {
  try {
    const resp = await fetch(buildApiUrl('/api/auth/web/refresh'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    })
    if (resp.ok) {
      const data = await resp.json()
      if (data.status === 'ok') {
        markWebSession(true)
        return true
      }
    }
  } catch (e) {
    console.warn('[apiFetch] 刷新 Token 失败:', e)
  }
  return false
}

export async function logoutWebSession() {
  try {
    await fetch(buildApiUrl('/api/auth/web/logout'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    })
  } finally {
    markWebSession(false)
  }
}

async function tryRefreshToken() {
  // 合并并发 401，避免同一 refresh token 被并发使用而触发重放防护。
  if (!refreshPromise) {
    refreshPromise = refreshTokens().finally(() => {
      refreshPromise = null
    })
  }
  return refreshPromise
}

/**
 * 带 Loading 状态的包装器
 * @param {string} url - API 路径
 * @param {object} loadingRef - ref 对象，请求期间设为 true
 * @param {object} options - fetch 选项
 */
export async function apiFetchWithLoading(url, loadingRef, options = {}) {
  if (loadingRef) loadingRef.value = true
  try {
    return await apiFetch(url, options)
  } finally {
    if (loadingRef) loadingRef.value = false
  }
}

export default apiFetch
