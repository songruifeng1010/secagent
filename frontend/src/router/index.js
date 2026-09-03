import { createRouter, createWebHistory } from 'vue-router'

function resolveRouterBase() {
  const injected = import.meta.env && import.meta.env.VITE_BASE_PATH
  if (injected) return injected
  if (typeof window !== 'undefined' && window.location.pathname.startsWith('/secagentx/')) return '/secagentx/'
  return '/'
}

const routes = [
  { path: '/', name: 'chat', component: () => import('../views/ChatView.vue') },
  { path: '/agents', name: 'agents', component: () => import('../views/AgentsView.vue') },
  { path: '/events', name: 'events', component: () => import('../views/EventsView.vue') },
  { path: '/events/:id', name: 'event-detail', component: () => import('../views/EventDetailView.vue'), props: true },
  { path: '/knowledge', name: 'knowledge', component: () => import('../views/KnowledgeView.vue') },
  { path: '/knowledge/:section', name: 'knowledge-section', component: () => import('../views/KnowledgeView.vue') },
  { path: '/attack-chain', name: 'attack-chain', component: () => import('../views/AttackChainView.vue') },
  { path: '/dashboard', name: 'dashboard', component: () => import('../views/DashboardView.vue') },
  { path: '/settings', name: 'settings', component: () => import('../views/SettingsView.vue') },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

export default createRouter({ history: createWebHistory(resolveRouterBase()), routes })
