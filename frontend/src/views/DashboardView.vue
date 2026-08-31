<template>
  <div class="dashboard">
    <!-- ========== KPI 行 ========== -->
    <div class="kpi-grid">
      <div class="kpi-card" v-for="kpi in kpiList" :key="kpi.label">
        <div class="kpi-icon" :style="{ background: kpi.iconBg }">
          <component :is="kpi.icon" :style="{ width: '20px', height: '20px', color: kpi.iconColor }" />
        </div>
        <div class="kpi-body">
          <div class="kpi-label">{{ kpi.label }}</div>
          <div class="kpi-value">{{ kpi.value }}</div>
        </div>
        <div v-if="kpi.badge" class="kpi-badge" :style="{ background: kpi.badgeBg, color: kpi.badgeColor }">
          {{ kpi.badge }}
        </div>
      </div>
    </div>

    <!-- ========== Agent 运行时 ========== -->
    <div class="section-card">
      <div class="section-header">
        <div class="section-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--text-tertiary);">
            <rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>
          </svg>
          <span>Agent Runtime</span>
          <span class="agent-count-badge">{{ agentRuntime.length }} Agents</span>
        </div>
      </div>
      <div v-if="loading.agents" class="skeleton-row-list">
        <div v-for="i in 4" :key="i" class="skeleton-agent" />
      </div>
      <div v-else class="agent-grid">
        <div v-for="agent in agentRuntime" :key="agent.agent_id" class="agent-card">
          <div class="agent-dot" :class="agent.status" />
          <div class="agent-info">
            <div class="agent-name">{{ agent.agent }}</div>
            <div class="agent-id">{{ agent.agent_id }}</div>
          </div>
          <div class="agent-metrics">
            <div class="metric">
              <span class="metric-value" style="color: var(--warning);">{{ agent.latency }}<span class="metric-unit">ms</span></span>
            </div>
            <div class="metric">
              <span class="metric-value" style="color: var(--info);">{{ formatNumber(agent.tokens) }}<span class="metric-unit">tok</span></span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ========== 图表 + 事件 ========== -->
    <div class="bottom-grid">
      <!-- 趋势图 -->
      <div class="section-card chart-card">
        <div class="section-header">
          <div class="section-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--text-tertiary);">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
            <span>事件趋势 (24h)</span>
          </div>
        </div>
        <div ref="chartRef" class="chart-container" />
      </div>

      <!-- 最近事件 -->
      <div class="section-card">
        <div class="section-header">
          <div class="section-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--text-tertiary);">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
            <span>最近事件</span>
            <span class="agent-count-badge">{{ recentEvents.length }} 条</span>
          </div>
        </div>
        <div v-if="loading.events" class="skeleton-row-list">
          <div v-for="i in 5" :key="i" class="skeleton-row" />
        </div>
        <div v-else class="event-list">
          <div v-for="evt in recentEvents" :key="evt.id || evt.title" class="event-row">
            <div class="event-dot" :style="{ background: severityColor(evt.severity) }" />
            <div class="event-title">{{ evt.title }}</div>
            <div class="event-severity" :style="{ color: severityColor(evt.severity) }">{{ evt.severity }}</div>
          </div>
          <div v-if="recentEvents.length === 0" class="empty-state">暂无事件数据</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted, h, markRaw } from 'vue'
import * as echarts from 'echarts'
import { PulseOutline, CubeOutline, AlertCircleOutline, ServerOutline } from '@vicons/ionicons5'
import { apiFetch } from '../utils/http.js'

// ─── 状态 ───
const loading = reactive({ agents: true, events: true })
const agentRuntime = ref([])
const recentEvents = ref([])
const chartRef = ref(null)
let chartInstance = null
let resizeObserver = null

// ─── KPI 使用真实 API 数据 ───
const kpiList = reactive([
  { label: '事件总数', value: '-', icon: markRaw(PulseOutline), iconBg: 'rgba(59,130,246,0.12)', iconColor: '#3b82f6', badge: '' },
  { label: 'Agent 数', value: '-', icon: markRaw(CubeOutline), iconBg: 'rgba(139,92,246,0.12)', iconColor: '#8b5cf6', badge: '' },
  { label: '工具就绪', value: '-', icon: markRaw(ServerOutline), iconBg: 'rgba(34,197,94,0.12)', iconColor: '#22c55e', badge: 'Ready' },
  { label: 'ATT&CK 技术', value: '-', icon: markRaw(AlertCircleOutline), iconBg: 'rgba(251,191,36,0.12)', iconColor: '#fbbf24', badge: 'MITRE' },
])

function severityColor(s) {
  return { '紧急': '#ef4444', '高危': '#f97316', '中危': '#eab308', '低危': '#22c55e' }[s] || '#64748b'
}

function formatNumber(n) {
  if (!n && n !== 0) return '-'
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K'
  return String(n)
}

// ─── 数据加载（仅真实 API） ───
async function loadData() {
  try {
    const [healthRes, statsRes, agentsRes, eventsRes, mitreRes] = await Promise.all([
      apiFetch('/api/health'),
      apiFetch('/api/stats'),
      apiFetch('/api/agents/runtime'),
      apiFetch('/api/events'),
      apiFetch('/api/mitre/dashboard'),
    ])

    // KPI
    const health = healthRes || {}
    const stats = statsRes || {}
    const agents = health.agents || []
    kpiList[0].value = stats.total_tasks ?? 0
    kpiList[1].value = agents.length || 0
    kpiList[2].value = stats.tools_count ?? 0
    kpiList[3].value = mitreRes.total_techniques || 0

    // Agent Runtime
    const agentsData = agentsRes.agents || []
    if (agentsData.length > 0) {
      agentRuntime.value = agentsData
    }
    loading.agents = false

    // Events
    const eventsData = eventsRes.events || []
    if (eventsData.length > 0) {
      recentEvents.value = eventsData.slice(0, 10)
    }
    loading.events = false

  } catch (e) {
    loading.agents = false
    loading.events = false
  }
}

// ─── ECharts（基于真实事件数据） ───
function initChart() {
  if (!chartRef.value) return
  chartInstance = echarts.init(chartRef.value, 'dark')
  const hours = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0') + ':00')

  // 从真实事件统计每小时事件数
  const hourlyData = new Array(24).fill(0)
  for (const evt of recentEvents.value) {
    const match = (evt.created_at || '').match(/(\d{2}):/)
    if (match) {
      const h = parseInt(match[1])
      if (h >= 0 && h < 24) hourlyData[h]++
    }
  }

  const option = {
    tooltip: { trigger: 'axis', backgroundColor: '#2a2d38', borderColor: '#2a2d38', textStyle: { color: '#e2e8f0' } },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
    xAxis: {
      type: 'category',
      data: hours,
      axisLine: { lineStyle: { color: '#2a2d38' } },
      axisLabel: { color: '#64748b', fontSize: 10, interval: 3 },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: '#2a2d38', type: 'dashed' } },
      axisLabel: { color: '#64748b', fontSize: 10 },
      minInterval: 1,
    },
    series: [{
      name: '告警',
      type: 'bar',
      barWidth: 12,
      itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: '#3b82f6' }, { offset: 1, color: '#1d4ed8' }]), borderRadius: [4, 4, 0, 0] },
      data: hourlyData,
    }],
    legend: { data: ['告警'], textStyle: { color: '#94a3b8', fontSize: 11 }, top: 0, right: 0 },
  }
  chartInstance.setOption(option)

  // 自适应
  resizeObserver = new ResizeObserver(() => {
    chartInstance?.resize()
  })
  resizeObserver.observe(chartRef.value)
}

onMounted(() => {
  loadData().then(() => setTimeout(initChart, 100))
})

onUnmounted(() => {
  chartInstance?.dispose()
  resizeObserver?.disconnect()
})
</script>

<style scoped>
.dashboard {
  padding: 20px;
  height: calc(100vh - var(--header-height));
  overflow-y: auto;
}

/* ─── KPI Grid ─── */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 16px;
}

.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-md);
  padding: 18px 20px;
  display: flex;
  align-items: center;
  gap: 14px;
  position: relative;
  transition: all var(--transition-fast);
}

.kpi-card:hover {
  border-color: var(--border-hover);
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}

.kpi-icon {
  width: 42px;
  height: 42px;
  border-radius: var(--radius-sm);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.kpi-body {
  flex: 1;
  min-width: 0;
}

.kpi-label {
  font-size: 11px;
  color: var(--text-muted);
  font-weight: 500;
  margin-bottom: 2px;
}

.kpi-value {
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}

.kpi-badge {
  position: absolute;
  top: 10px;
  right: 10px;
  font-size: 9px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: var(--radius-full);
  letter-spacing: 0.5px;
}

/* ─── Section Card ─── */
.section-card {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-md);
  padding: 16px 20px;
  margin-bottom: 16px;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-secondary);
}

.agent-count-badge {
  font-size: 10px;
  font-weight: 500;
  padding: 1px 8px;
  border-radius: var(--radius-full);
  background: var(--bg-elevated);
  color: var(--text-muted);
}

/* ─── Agent Grid ─── */
.agent-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
}

.agent-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-primary);
  background: var(--bg-primary);
  transition: all var(--transition-fast);
}

.agent-card:hover {
  border-color: var(--border-hover);
  background: var(--bg-card-hover);
}

.agent-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.agent-dot.idle { background: var(--text-muted); }
.agent-dot.running { background: var(--success); animation: pulse-dot 2s infinite; }
.agent-dot.completed { background: var(--info); }
.agent-dot.busy { background: var(--warning); }

.agent-info {
  flex: 1;
  min-width: 0;
}

.agent-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.agent-id {
  font-size: 10px;
  color: var(--text-muted);
  margin-top: 1px;
}

.agent-metrics {
  display: flex;
  gap: 12px;
  flex-shrink: 0;
}

.metric-value {
  font-size: 12px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}

.metric-unit {
  font-size: 10px;
  font-weight: 400;
  color: var(--text-muted);
  margin-left: 1px;
}

/* ─── 双栏布局 ─── */
.bottom-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.chart-card {
  grid-column: 1;
}

.chart-container {
  width: 100%;
  height: 240px;
}

/* ─── 事件列表 ─── */
.event-list {
  max-height: 280px;
  overflow-y: auto;
}

.event-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 4px;
  border-bottom: 1px solid var(--border-primary);
  cursor: pointer;
  transition: background var(--transition-fast);
}

.event-row:last-child { border-bottom: none; }
.event-row:hover { background: var(--bg-card-hover); border-radius: 4px; }

.event-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}

.event-title {
  flex: 1;
  font-size: 12px;
  color: var(--text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.event-severity {
  font-size: 11px;
  font-weight: 600;
  flex-shrink: 0;
}

.empty-state {
  text-align: center;
  padding: 24px;
  color: var(--text-muted);
  font-size: 12px;
}

/* ─── 响应式 ─── */
@media (max-width: 1024px) {
  .kpi-grid { grid-template-columns: repeat(2, 1fr); }
  .agent-grid { grid-template-columns: repeat(2, 1fr); }
  .bottom-grid { grid-template-columns: 1fr; }
}

@media (max-width: 640px) {
  .dashboard { padding: 12px; }
  .kpi-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }
  .kpi-card { padding: 12px 14px; }
  .kpi-value { font-size: 18px; }
  .agent-grid { grid-template-columns: 1fr; }
}

/* ─── Skeleton ─── */
.skeleton-row-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.skeleton-agent {
  height: 52px;
  border-radius: var(--radius-sm);
  background: linear-gradient(90deg, var(--border-primary) 25%, var(--bg-card-hover) 50%, var(--border-primary) 75%);
  background-size: 200% 100%;
  animation: skeleton-pulse 1.8s ease-in-out infinite;
}

.skeleton-row {
  height: 32px;
  border-radius: 4px;
  background: linear-gradient(90deg, var(--border-primary) 25%, var(--bg-card-hover) 50%, var(--border-primary) 75%);
  background-size: 200% 100%;
  animation: skeleton-pulse 1.8s ease-in-out infinite;
}
</style>
