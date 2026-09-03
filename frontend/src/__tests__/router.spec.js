import { describe, expect, it } from 'vitest'
import router from '../router/index.js'

describe('本机控制台路由', () => {
  it('不注册登录或用户管理页面', () => {
    const paths = router.getRoutes().map(route => route.path)
    expect(paths).not.toContain('/login')
    expect(paths).not.toContain('/users')
  })

  it('保留无需凭据即可访问的工作台页面', () => {
    const paths = router.getRoutes().map(route => route.path)
    expect(paths).toContain('/dashboard')
    expect(paths).toContain('/settings')
  })
})
