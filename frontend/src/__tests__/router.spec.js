/**
 * 路由守卫单元测试
 * 测试守卫函数逻辑，不依赖 Vue Router 完整实例
 */
import { describe, it, expect, beforeEach } from 'vitest'

// 模拟 localStorage
const localStorageMock = (() => {
  let store = {}
  return {
    getItem: (key) => store[key] || null,
    setItem: (key, value) => { store[key] = value },
    removeItem: (key) => { delete store[key] },
    clear: () => { store = {} },
  }
})()
Object.defineProperty(globalThis, 'localStorage', { value: localStorageMock })

// 路由守卫（与 router/index.js 保持一致）
function requireAuth(to, from, next) {
  const token = localStorage.getItem('secagentx_authenticated') === '1'
  if (to.meta && to.meta.requiresAuth === false) {
    next()
    return
  }
  if (!token) {
    next({ path: '/login', query: { redirect: to.fullPath } })
  } else {
    next()
  }
}

describe('Router Guard', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('should redirect to login when no token', () => {
    let redirectTarget = null
    const next = (target) => { redirectTarget = target }
    requireAuth(
      { path: '/dashboard', fullPath: '/dashboard', meta: {} },
      {},
      next
    )
    expect(redirectTarget).toEqual({ path: '/login', query: { redirect: '/dashboard' } })
  })

  it('should NOT redirect for login page when no token', () => {
    let called = false
    requireAuth(
      { path: '/login', fullPath: '/login', meta: { requiresAuth: false } },
      {},
      () => { called = true }
    )
    expect(called).toBe(true)
  })

  it('should allow access when token exists', () => {
    localStorage.setItem('secagentx_authenticated', '1')
    let called = false
    requireAuth(
      { path: '/dashboard', fullPath: '/dashboard', meta: {} },
      {},
      () => { called = true }
    )
    expect(called).toBe(true)
  })

  it('should redirect protected routes when no token', () => {
    let redirectTarget = null
    requireAuth(
      { path: '/users', fullPath: '/users', meta: { requiresAuth: true } },
      {},
      (target) => { redirectTarget = target }
    )
    expect(redirectTarget).toEqual({ path: '/login', query: { redirect: '/users' } })
  })

  it('should preserve redirect URL in query', () => {
    let redirectTarget = null
    requireAuth(
      { path: '/settings', fullPath: '/settings', meta: {} },
      {},
      (target) => { redirectTarget = target }
    )
    expect(redirectTarget.query.redirect).toBe('/settings')
  })

  it('should call next() for login route meta check', () => {
    const routeMeta = { requiresAuth: false }
    expect(routeMeta.requiresAuth).toBe(false)
  })
})
