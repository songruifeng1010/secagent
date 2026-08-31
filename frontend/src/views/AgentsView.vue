<template>
  <div class="agents-page">
    <!-- 页面标题 -->
    <div class="page-header">
      <div class="header-left">
        <div class="page-title">Agent Runtime</div>
        <div class="page-desc">多智能体运行时状态监控 · 实时延迟 / Token 消耗</div>
      </div>
      <div class="header-right">
        <span class="agent-total">{{ agents.length }} Agents</span>
        <button class="refresh-btn" :class="{ loading }" @click="fetchRuntime">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" :class="{ spinning: loading }">
            <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
          </svg>
          刷新
        </button>
      </div>
    </div>

    <!-- Agent 卡片网格 -->
    <div v-if="loading && agents.length === 0" class="agent-grid">
      <div v-for="i in 4" :key="i" class="skeleton-agent" />
    </div>
    <div v-else class="agent-grid">
      <div v-for="agent in agents" :key="agent.agent_id" class="agent-card" :class="'card-' + agent.status">
        <!-- 顶部：名称 + 状态 -->
        <div class="agent-top">
          <div class="agent-avatar" :style="{ background: agentColor(agent.agent) }">
            {{ agent.agent.charAt(0) }}
          </div>
          <div class="agent-meta">
            <div class="agent-name">{{ agent.agent }}</div>
            <div class="agent-id">{{ agent.agent_id }}</div>
          </div>
          <div class="agent-status" :class="'status-' + agent.status">
            <div class="status-dot" :class="agent.status" />
            {{ statusLabel(agent.status) }}
          </div>
        </div>

        <!-- 指标三栏 -->
        <div class="agent-metrics">
          <div class="metric-col">
            <div class="metric-label">LATENCY</div>
            <div class="metric-value latency-val">{{ agent.latency }}<span class="metric-unit">ms</span></div>
          </div>
          <div class="metric-col">
            <div class="metric-label">TOKENS</div>
            <div class="metric-value token-val">{{ formatNumber(agent.tokens) }}<span class="metric-unit">tok</span></div>
          </div>
          <div class="metric-col">
            <div class="metric-label">TASKS</div>
            <div class="metric-value task-val">{{ agent.total_tasks }}</div>
          </div>
        </div>

        <!-- 底部进度条 -->
        <div class="agent-footer">
          <div class="progress-row">
            <span class="progress-label">延迟</span>
            <div class="progress-track">
              <div class="progress-fill" :style="{ width: Math.min(100, (agent.latency / 500) * 100) + '%', background: latencyBarColor(agent.latency) }" />
            </div>
            <span class="progress-val">{{ agent.latency }}ms</span>
          </div>
          <div class="footer-stats">
            <div class="stat-item">
              <span class="stat-label">累计 Token</span>
              <span class="stat-value" style="color: var(--info);">{{ formatNumber(agent.total_tokens) }}</span>
            </div>
            <div class="stat-item">
              <span class="stat-label">总任务数</span>
              <span class="stat-value" style="color: var(--text-primary);">{{ agent.total_tasks }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 系统概览 -->
    <div class="overview-card">
      <div class="overview-grid">
        <div v-for="item in overview" :key="item.label" class="overview-item">
          <div class="overview-value" :style="{ color: item.color }">{{ item.value }}</div>
          <div class="overview-label">{{ item.label }}</div>
        </div>
      </div>
    </div>

    <!-- 离线提示 -->
    <div v-if="offline" class="offline-banner">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      <span>后端未连接，无法获取实时数据</span>
      <button class="retry-btn" @click="fetchRuntime">重新连接</button>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { apiFetch } from '../utils/http.js'

const loading = ref(true)
const offline = ref(false)
const agents = ref([])

const overview = computed(() => {
  const a = agents.value
  if (!a.length) return []
  const totalTokens = a.reduce((s, x) => s + (x.total_tokens || 0), 0)
  const totalTasks = a.reduce((s, x) => s + (x.total_tasks || 0), 0)
  const avgLatency = a.length ? Math.round(a.reduce((s, x) => s + (x.latency || 0), 0) / a.length) : 0
  const running = a.filter(x => x.status === 'running').length
  return [
    { label: 'Agent 总数', value: a.length, color: 'var(--info)' },
    { label: '运行中', value: running, color: running > 0 ? 'var(--success)' : 'var(--text-muted)' },
    { label: '平均延迟', value: avgLatency + 'ms', color: 'var(--warning)' },
    { label: '累计 Token', value: formatNumber(totalTokens), color: 'var(--color-intel)' },
  ]
})

function statusLabel(s) {
  return { running: '运行中', completed: '已完成', idle: '空闲', busy: '忙碌', error: '错误' }[s] || s
}

function agentColor(name) {
  const colors = { '安全分析师': 'var(--color-analyst)', '威胁情报员': 'var(--color-intel)', '应急响应员': 'var(--color-responder)', '知识智能体': 'var(--color-knowledge)', '告警误报剔除专家': 'var(--color-filter)' }
  return colors[name] || 'var(--color-intel)'
}

function latencyBarColor(ms) {
  if (ms < 200) return 'var(--success)'
  if (ms < 400) return 'var(--warning)'
  return 'var(--error)'
}

function formatNumber(n) {
  if (!n && n !== 0) return '0'
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K'
  return String(n)
}

async function fetchRuntime() {
  loading.value = true
  offline.value = false
  try {
    const data = await apiFetch('/api/agents/runtime')
    if (data.agents?.length) { agents.value = data.agents; return }
    throw new Error('no data')
  } catch {
    offline.value = true
    agents.value = []
  } finally {
    loading.value = false
  }
}

onMounted(fetchRuntime)
</script>

<style scoped>
.agents-page { padding: 24px; height: calc(100vh - var(--header-height)); overflow-y: auto; }
.page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }
.page-title { font-size: 20px; font-weight: 700; color: var(--text-primary); letter-spacing: 0.5px; }
.page-desc { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
.header-right { display: flex; align-items: center; gap: 10px; }
.agent-total { font-size: 11px; font-weight: 500; padding: 3px 10px; border-radius: var(--radius-full); background: var(--bg-elevated); color: var(--text-tertiary); }
.refresh-btn { display: inline-flex; align-items: center; gap: 5px; padding: 6px 12px; border: 1px solid var(--border-primary); border-radius: var(--radius-sm); background: transparent; color: var(--text-tertiary); font-size: 12px; cursor: pointer; transition: all var(--transition-fast); }
.refresh-btn:hover { border-color: var(--accent); color: var(--accent); }
.refresh-btn.loading { opacity: 0.6; pointer-events: none; }
.spinning { animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.agent-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 16px; margin-bottom: 24px; }
.skeleton-agent { height: 180px; border-radius: var(--radius-md); background: linear-gradient(90deg, var(--border-primary) 25%, var(--bg-card-hover) 50%, var(--border-primary) 75%); background-size: 200% 100%; animation: skeleton-pulse 1.8s ease-in-out infinite; }
.agent-card { border-radius: var(--radius-md); border: 1px solid var(--border-primary); overflow: hidden; transition: all var(--transition-fast); }
.agent-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); }
.agent-card.card-running { border-color: rgba(34,197,94,0.2); }
.agent-top { padding: 16px 20px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--border-primary); }
.agent-avatar { width: 36px; height: 36px; border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; font-size: 15px; font-weight: 700; color: white; flex-shrink: 0; }
.agent-meta { flex: 1; }
.agent-name { font-size: 14px; font-weight: 600; color: var(--text-primary); }
.agent-id { font-size: 11px; color: var(--text-muted); margin-top: 1px; font-family: var(--font-mono); }
.agent-status { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 500; padding: 4px 10px; border-radius: var(--radius-full); }
.status-running { background: var(--success-bg); color: var(--success); }
.status-completed { background: var(--info-bg); color: var(--info); }
.status-idle { background: var(--bg-elevated); color: var(--text-muted); }
.status-busy { background: var(--warning-bg); color: var(--warning); }
.status-error { background: var(--error-bg); color: var(--error); }
.status-dot { width: 6px; height: 6px; border-radius: 50%; }
.status-dot.running { background: var(--success); animation: pulse-dot 2s infinite; }
.status-dot.completed { background: var(--info); }
.status-dot.idle { background: var(--text-muted); }
.agent-metrics { display: grid; grid-template-columns: 1fr 1fr 1fr; }
.metric-col { padding: 14px 12px; text-align: center; border-right: 1px solid var(--border-primary); }
.metric-col:last-child { border-right: none; }
.metric-label { font-size: 10px; font-weight: 600; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 6px; }
.metric-value { font-size: 16px; font-weight: 700; }
.metric-unit { font-size: 11px; font-weight: 400; color: var(--text-tertiary); margin-left: 2px; }
.latency-val { color: var(--warning); } .token-val { color: var(--info); } .task-val { color: var(--text-primary); }
.agent-footer { padding: 12px 20px; background: var(--bg-primary); border-top: 1px solid var(--border-primary); }
.progress-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.progress-label { font-size: 10px; color: var(--text-muted); min-width: 28px; }
.progress-track { flex: 1; height: 4px; border-radius: 2px; background: var(--bg-elevated); overflow: hidden; }
.progress-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
.progress-val { font-size: 10px; color: var(--text-tertiary); min-width: 36px; text-align: right; }
.footer-stats { display: flex; gap: 20px; }
.stat-item { display: flex; align-items: center; gap: 8px; }
.stat-label { font-size: 10px; color: var(--text-muted); }
.stat-value { font-size: 12px; font-weight: 600; }
.overview-card { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); padding: 20px; margin-bottom: 16px; }
.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
.overview-item { text-align: center; }
.overview-value { font-size: 22px; font-weight: 700; }
.overview-label { font-size: 11px; color: var(--text-muted); margin-top: 4px; }
.offline-banner { display: flex; align-items: center; gap: 10px; padding: 12px 16px; background: var(--warning-bg); border: 1px solid rgba(234,179,8,0.2); border-radius: var(--radius-sm); color: var(--warning); font-size: 13px; }
.retry-btn { margin-left: auto; padding: 4px 12px; border-radius: var(--radius-sm); border: 1px solid rgba(234,179,8,0.3); background: transparent; color: var(--warning); font-size: 12px; cursor: pointer; }
.retry-btn:hover { background: rgba(234,179,8,0.1); }
</style>
