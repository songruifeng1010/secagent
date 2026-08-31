import { createRouter, createWebHistory } from 'vue-router'
import { hasWebSession } from '../utils/http.js'

/**
 * 路由 base — 运行时自适应（与 http.js 前缀逻辑一致）
 *
 *  - OpenIM 集成环境：页面挂在 /secagentx/ 下，路由 base 须为 /secagentx/
 *    否则 SPA 跳转会丢失前缀（如变成 /agents），刷新即被 nginx 拦回 OpenIM 首页
 *  - FastAPI 直连：base 为 /
 */
function resolveRouterBase() {
  const injected = import.meta.env && import.meta.env.VITE_BASE_PATH
  if (injected) return injected
  if (typeof window !== 'undefined' && window.location.pathname.startsWith('/secagentx/')) {
    return '/secagentx/'
  }
  return '/'
}

/**
 * 路由守卫：检查是否已登录
 * 未登录时跳转到 /login，并携带目标路径
 */
function requireAuth(to, from, next) {
  if (to.meta.requiresAuth !== false && !hasWebSession()) {
    next({ path: '/login', query: { redirect: to.fullPath } })
  } else {
    next()
  }
}

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/LoginView.vue'),
    meta: { requiresAuth: false },
  },
  {
    path: '/',
    name: 'chat',
    component: () => import('../views/ChatView.vue'),
  },
  {
    path: '/agents',
    name: 'agents',
    component: () => import('../views/AgentsView.vue'),
  },
  {
    path: '/events',
    name: 'events',
    component: () => import('../views/EventsView.vue'),
  },
  {
    path: '/knowledge',
    name: 'knowledge',
    component: () => import('../views/KnowledgeView.vue'),
  },
  {
    path: '/knowledge/mitre',
    name: 'knowledge-mitre',
    component: () => import('../views/KnowledgeView.vue'),
  },
  {
    path: '/knowledge/owasp',
    name: 'knowledge-owasp',
    component: () => import('../views/KnowledgeView.vue'),
  },
  {
    path: '/knowledge/cve',
    name: 'knowledge-cve',
    component: () => import('../views/KnowledgeView.vue'),
  },
  {
    path: '/knowledge/rules',
    name: 'knowledge-rules',
    component: () => import('../views/KnowledgeView.vue'),
  },
  {
    path: '/attack-chain',
    name: 'attack-chain',
    component: () => import('../views/AttackChainView.vue'),
  },
  {
    path: '/dashboard',
    name: 'dashboard',
    component: () => import('../views/DashboardView.vue'),
  },
  {
    path: '/events/:id',
    name: 'event-detail',
    component: () => import('../views/EventDetailView.vue'),
    props: true,
  },
  {
    path: '/users',
    name: 'users',
    component: () => import('../views/UsersView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('../views/SettingsView.vue'),
    meta: { requiresAuth: true },
  },
]

const router = createRouter({
  history: createWebHistory(resolveRouterBase()),
  routes,
})

// 注册全局路由守卫
router.beforeEach(requireAuth)

export default router
