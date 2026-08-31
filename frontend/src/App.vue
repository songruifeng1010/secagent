<template>
  <n-config-provider :theme="customTheme" :locale="zhCN" :date-locale="dateZhCN">
    <n-message-provider>
      <n-notification-provider>
        <n-dialog-provider>
          <n-layout position="absolute" style="height: 100vh; background: var(--bg-primary);">
            <!-- 顶部导航栏 -->
            <n-layout-header bordered style="height: var(--header-height); display: flex; align-items: center; padding: 0 20px; background: var(--bg-card); border-bottom: 1px solid var(--border-primary);">
              <!-- Logo 区域 -->
              <div style="display: flex; align-items: center; gap: 10px;">
                <div style="width: 28px; height: 28px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 14px; color: white; letter-spacing: 1px;">
                  SX
                </div>
                <span style="color: var(--accent); font-size: 16px; font-weight: 700; letter-spacing: 1.5px;">SecAgentX</span>
                <span style="color: var(--text-muted); font-size: 11px; font-weight: 400; padding-left: 10px; border-left: 1px solid var(--border-primary);">AI 安全智能体</span>
              </div>
              <div style="flex:1" />
              <!-- 右侧状态区 -->
              <template v-if="!isLoginPage">
                <!-- 连接状态指示灯 - 使用 store 的统一状态 -->
                <div style="display: flex; align-items: center; gap: 6px; margin-right: 16px;">
                  <div :style="{
                    width: '7px', height: '7px', borderRadius: '50%',
                    background: chatStore.wsConnected ? 'var(--success)' : 'var(--error)',
                    boxShadow: chatStore.wsConnected ? '0 0 8px rgba(34,197,94,0.5)' : 'none',
                    animation: chatStore.wsConnected ? 'pulse-dot 2s infinite' : 'none',
                  }"></div>
                  <span style="color: var(--text-muted); font-size: 11px; font-weight: 500;">
                    {{ chatStore.wsConnected ? '已连接' : '未连接' }}
                  </span>
                </div>
                <!-- 用户信息 -->
                <div v-if="currentUser" style="display: flex; align-items: center; gap: 8px; padding: 4px 12px 4px 4px; border-radius: var(--radius-full); background: var(--bg-elevated); border: 1px solid var(--border-primary);">
                  <div style="width: 26px; height: 26px; border-radius: 50%; background: linear-gradient(135deg, var(--accent), var(--accent-hover)); display: flex; align-items: center; justify-content: center; color: white; font-size: 11px; font-weight: 700;">
                    {{ (currentUser.display_name || currentUser.username).charAt(0).toUpperCase() }}
                  </div>
                  <span style="color: var(--text-secondary); font-size: 12px; font-weight: 500; line-height: 1;">
                    {{ currentUser.display_name || currentUser.username }}
                    <span style="color: var(--text-muted); font-weight: 400; font-size: 10px; margin-left: 4px;">{{ currentUser.role }}</span>
                  </span>
                </div>
                <n-button text size="small" @click="handleLogout" style="color: var(--text-muted); font-size: 11px; margin-left: 4px;">
                  退出
                </n-button>
              </template>
            </n-layout-header>

            <!-- 主体区域（登录页不渲染侧边栏菜单，避免"点了跳不走"的困惑） -->
            <n-layout v-if="!isLoginPage" position="absolute" style="top: var(--header-height); bottom: 0; background: var(--bg-primary);" has-sider>
              <n-layout-sider bordered :width="220" :collapsed-width="64" show-trigger="bar" style="background: var(--bg-card); border-right: 1px solid var(--border-primary);">
                <n-menu :value="currentRoute" :options="menuOptions" @update:value="onMenuChange" style="background: var(--bg-card); padding-top: 4px;" />
              </n-layout-sider>
              <n-layout style="background: var(--bg-primary);">
                <!-- 页面过渡动画 - 只用透明度，杜绝 out-in 白帧 -->
                <router-view v-slot="{ Component, route: r }">
                  <transition name="fade" mode="default">
                    <component :is="Component" :key="r.path" />
                  </transition>
                </router-view>
              </n-layout>
            </n-layout>
            <!-- 登录页：主体直接渲染登录视图 -->
            <n-layout v-else position="absolute" style="top: 0; bottom: 0; background: var(--bg-primary);">
              <router-view />
            </n-layout>
          </n-layout>
        </n-dialog-provider>
      </n-notification-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { ref, computed, h, onMounted, onUnmounted, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { darkTheme, zhCN, dateZhCN, NConfigProvider, useMessage } from 'naive-ui'
import { useChatStore } from './stores/chat.js'
import { apiFetch, hasWebSession, logoutWebSession } from './utils/http.js'
import {
  GridOutline,
  ChatbubblesOutline,
  CubeOutline,
  WarningOutline,
  GitNetworkOutline,
  ShieldCheckmarkOutline,
  BugOutline,
  DocumentTextOutline,
  SettingsOutline,
  PeopleOutline,
} from '@vicons/ionicons5'

const router = useRouter()
const route = useRoute()
const chatStore = useChatStore()

// useMessage 降级（provider 在子组件中）
let message
try {
  message = useMessage()
} catch (e) {
  message = { error: console.warn, success: console.log, warning: console.warn, info: console.log }
}

const isLoginPage = computed(() => route.path === '/login')
const currentUser = ref(null)
const userPermissions = ref([])

const currentRoute = computed(() => route.path)

function loadUser() {
  try {
    const u = localStorage.getItem('secagentx_user')
    if (u) currentUser.value = JSON.parse(u)
    const p = localStorage.getItem('secagentx_permissions')
    if (p) userPermissions.value = JSON.parse(p)
  } catch (e) {
    currentUser.value = null
  }
}

async function fetchPermissions() {
  try {
    if (!hasWebSession()) return
    const data = await apiFetch('/api/users/me')
    if (data.permissions) {
      userPermissions.value = data.permissions
      localStorage.setItem('secagentx_permissions', JSON.stringify(data.permissions))
    }
  } catch (e) { /* ignore */ }
}

function hasPermission(perm) {
  return userPermissions.value.includes(perm)
}

loadUser()

// 设计系统主题 — 复用 tokens.css 变量
const customTheme = {
  ...darkTheme,
  common: {
    ...darkTheme.common,
    primaryColor: '#dc2626',
    primaryColorHover: '#ef4444',
    primaryColorPressed: '#b91c1c',
    primaryColorSuppl: '#dc2626',
    bodyColor: '#0f1117',
    cardColor: '#171923',
    modalColor: '#171923',
    popoverColor: '#171923',
    tableColor: '#171923',
    borderColor: '#2a2d38',
    dividerColor: '#2a2d38',
    actionColor: '#171923',
    tabColor: '#171923',
    inputColor: '#171923',
    inputColorDisabled: '#171923',
    hoverColor: '#1f2230',
    closeColor: '#64748b',
    closeColorHover: '#e2e8f0',
    textColor1: '#f1f5f9',
    textColor2: '#cbd5e1',
    textColor3: '#94a3b8',
    textColorDisabled: '#64748b',
    placeholderColor: '#475569',
    invertedColor: '#0f1117',
    progressRailColor: '#2a2d38',
    railColor: '#2a2d38',
    fontWeightStrong: '600',
  },
}

// 带 SVG 图标的菜单 — 使用 ionicons5 渲染
function renderIcon(icon) {
  return () => h(icon, { style: 'width:18px;height:18px;' })
}

const menuOptions = computed(() => {
  const items = [
    { label: '总览', key: '/dashboard', icon: renderIcon(GridOutline) },
    { label: '对话', key: '/', icon: renderIcon(ChatbubblesOutline) },
    { label: 'Agent 状态', key: '/agents', icon: renderIcon(CubeOutline) },
    { label: '事件', key: '/events', icon: renderIcon(WarningOutline) },
    { label: 'ATT&CK 知识库', key: '/knowledge/mitre', icon: renderIcon(GitNetworkOutline) },
    { label: 'OWASP 知识库', key: '/knowledge/owasp', icon: renderIcon(ShieldCheckmarkOutline) },
    { label: 'CVE 漏洞库', key: '/knowledge/cve', icon: renderIcon(BugOutline) },
    { label: '检测规则', key: '/knowledge/rules', icon: renderIcon(DocumentTextOutline) },
  ]
  if (hasPermission('admin:users')) {
    items.push({ label: '系统设置', key: '/settings', icon: renderIcon(SettingsOutline) })
    items.push({ label: '用户管理', key: '/users', icon: renderIcon(PeopleOutline) })
  }
  return items
})

function onMenuChange(key) {
  router.push(key)
}

async function handleLogout() {
  chatStore.disconnectWebSocket()
  await logoutWebSession().catch(() => {})
  localStorage.removeItem('secagentx_user')
  localStorage.removeItem('secagentx_permissions')
  router.push('/login')
}

// 路由变化时管理 WebSocket 生命周期（登录页断连，其他页连接）
watch(() => route.path, (newPath) => {
  if (newPath === '/login') {
    chatStore.disconnectWebSocket()
  } else {
    chatStore.connectWebSocket()
  }
})

onMounted(() => {
  if (hasWebSession()) { chatStore.connectWebSocket(); fetchPermissions() }
})

onUnmounted(() => {
  chatStore.disconnectWebSocket()
})
</script>
