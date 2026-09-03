<template>
  <n-config-provider :theme="customTheme" :locale="zhCN" :date-locale="dateZhCN">
    <n-message-provider><n-notification-provider><n-dialog-provider>
      <n-layout position="absolute" style="height:100vh;background:var(--bg-primary);">
        <n-layout-header bordered style="height:var(--header-height);display:flex;align-items:center;padding:0 20px;background:var(--bg-card);border-bottom:1px solid var(--border-primary);">
          <div style="display:flex;align-items:center;gap:10px;">
            <div style="width:28px;height:28px;border-radius:8px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:white;letter-spacing:1px;">SX</div>
            <span style="color:var(--accent);font-size:16px;font-weight:700;letter-spacing:1.5px;">SecAgentX</span>
            <span style="color:var(--text-muted);font-size:11px;padding-left:10px;border-left:1px solid var(--border-primary);">AI 安全智能体</span>
          </div>
          <div style="flex:1" />
          <span style="color:var(--warning);font-size:11px;margin-right:16px;">仅本机模式 · 无登录</span>
          <div style="display:flex;align-items:center;gap:6px;">
            <div :style="{width:'7px',height:'7px',borderRadius:'50%',background:chatStore.wsConnected ? 'var(--success)' : 'var(--error)'}"></div>
            <span style="color:var(--text-muted);font-size:11px;">{{ chatStore.wsConnected ? '已连接' : '未连接' }}</span>
          </div>
        </n-layout-header>
        <n-layout position="absolute" style="top:var(--header-height);bottom:0;background:var(--bg-primary);" has-sider>
          <n-layout-sider bordered :width="220" :collapsed-width="64" show-trigger="bar" style="background:var(--bg-card);border-right:1px solid var(--border-primary);">
            <n-menu :value="currentRoute" :options="menuOptions" @update:value="onMenuChange" style="background:var(--bg-card);padding-top:4px;" />
          </n-layout-sider>
          <n-layout style="background:var(--bg-primary);"><router-view v-slot="{ Component, route: r }"><transition name="fade" mode="default"><component :is="Component" :key="r.path" /></transition></router-view></n-layout>
        </n-layout>
      </n-layout>
    </n-dialog-provider></n-notification-provider></n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { darkTheme, zhCN, dateZhCN, NConfigProvider } from 'naive-ui'
import { useChatStore } from './stores/chat.js'

const router = useRouter()
const route = useRoute()
const chatStore = useChatStore()
const currentRoute = computed(() => route.path)
const customTheme = { ...darkTheme, common: { ...darkTheme.common, primaryColor: '#dc2626', primaryColorHover: '#ef4444', primaryColorPressed: '#b91c1c', primaryColorSuppl: '#dc2626', bodyColor: '#0f1117', cardColor: '#171923', modalColor: '#171923', popoverColor: '#171923', tableColor: '#171923', borderColor: '#2a2d38', dividerColor: '#2a2d38', actionColor: '#171923', inputColor: '#171923', hoverColor: '#1f2230', textColor1: '#f1f5f9', textColor2: '#cbd5e1', textColor3: '#94a3b8' } }
const menuOptions = [
  { label: '总览', key: '/dashboard' },
  { label: '对话', key: '/' },
  { label: 'Agent 状态', key: '/agents' },
  { label: '事件', key: '/events' },
  { label: 'ATT&CK 知识库', key: '/knowledge/mitre' },
  { label: 'OWASP 知识库', key: '/knowledge/owasp' },
  { label: 'CVE 漏洞库', key: '/knowledge/cve' },
  { label: '检测规则', key: '/knowledge/rules' },
  { label: '系统设置', key: '/settings' },
]
function onMenuChange(key) { router.push(key) }
onMounted(() => chatStore.connectWebSocket())
onUnmounted(() => chatStore.disconnectWebSocket())
</script>
