<template>
  <div class="events-page">
    <!-- 顶部标题 + 搜索过滤栏 -->
    <div class="events-header">
      <div class="header-top">
        <div class="header-left">
          <div class="page-title">安全事件</div>
          <span class="event-count">{{ filteredEvents.length }} 条</span>
        </div>
      </div>

      <!-- 过滤行 -->
      <div class="filter-bar">
        <div class="search-box">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input v-model="searchQuery" class="search-input" placeholder="搜索事件标题、IP..." />
        </div>

        <select v-model="severityFilter" class="filter-select">
          <option value="">全部风险</option>
          <option value="紧急">紧急</option>
          <option value="高危">高危</option>
          <option value="中危">中危</option>
          <option value="低危">低危</option>
        </select>

        <select v-model="statusFilter" class="filter-select">
          <option value="">全部状态</option>
          <option value="open">OPEN</option>
          <option value="investigating">INVESTIGATING</option>
          <option value="resolved">RESOLVED</option>
        </select>

        <button class="refresh-btn" :class="{ spinning: loading }" @click="fetchEvents">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" :class="{ spin: loading }">
            <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- Skeleton -->
    <div v-if="loading && events.length === 0" class="table-skeleton">
      <div v-for="i in 5" :key="i" class="skeleton-row" :style="{ animationDelay: i * 0.08 + 's' }">
        <div class="sk-cell w-16" /><div class="sk-cell w-40" /><div class="sk-cell w-20" /><div class="sk-cell w-24" /><div class="sk-cell w-20" /><div class="sk-cell w-16" />
      </div>
    </div>

    <!-- 事件表格 -->
    <div v-else class="table-card">
      <table class="event-table">
        <thead>
          <tr>
            <th class="col-time">Time</th>
            <th class="col-event">Event</th>
            <th class="col-attack">ATT&amp;CK</th>
            <th class="col-conf">Confidence</th>
            <th class="col-assoc">Associations</th>
            <th class="col-status">Status</th>
            <th class="col-risk">Risk</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in filteredEvents" :key="row.id || row.title" class="event-row" @click="goToDetail(row)">
            <td class="col-time"><span class="time-text">{{ timeOnly(row.created_at) }}</span></td>
            <td class="col-event">
              <div class="event-cell">
                <span class="severity-dot" :style="{ background: severityColor(row.severity) }" />
                <span class="event-title-text">{{ row.title }}</span>
                <code v-if="row.source_ip" class="ip-tag">{{ row.source_ip }}</code>
              </div>
            </td>
            <td class="col-attack"><span v-if="primaryTech(row.techniques).id !== '-'" class="attack-id">{{ primaryTech(row.techniques).id }}</span><span v-else class="attack-na">-</span></td>
            <td class="col-conf">
              <div class="conf-cell">
                <div class="conf-bar"><div class="conf-fill" :style="{ width: Math.round((row.confidence || 0) * 100) + '%', background: confBarColor(row.confidence) }" /></div>
                <span class="conf-text" :style="{ color: confTextColor(row.confidence) }">{{ Math.round((row.confidence || 0) * 100) }}%</span>
              </div>
            </td>
            <td class="col-assoc">
              <div class="assoc-cell">
                <span v-if="row.cve_id" class="badge badge-cve" title="关联漏洞">{{ row.cve_id }}</span>
                <span v-if="row.actor_name" class="badge badge-apt" title="威胁组织">{{ row.actor_name }}</span>
                <span v-if="row.malware_name" class="badge badge-malware" title="恶意软件">{{ row.malware_name }}</span>
                <span v-if="row.threat_level === 'high'" class="badge badge-high" title="高置信度威胁">HIGH</span>
              </div>
            </td>
            <td class="col-status"><span class="status-tag" :class="'st-' + row.status">{{ statusLabel(row.status) }}</span></td>
            <td class="col-risk"><span class="risk-text" :style="{ color: severityColor(row.severity) }">{{ severityEng(row.severity) }}</span></td>
          </tr>
          <tr v-if="filteredEvents.length === 0">
            <td colspan="7" class="empty-row">暂无匹配事件</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { apiFetch } from '../utils/http.js'

const router = useRouter()
const events = ref([])
const loading = ref(true)
const searchQuery = ref('')
const severityFilter = ref('')
const statusFilter = ref('')

const filteredEvents = computed(() => {
  let list = events.value
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    list = list.filter(e => (e.title || '').toLowerCase().includes(q) || (e.source_ip || '').toLowerCase().includes(q))
  }
  if (severityFilter.value) list = list.filter(e => e.severity === severityFilter.value)
  if (statusFilter.value) list = list.filter(e => e.status === statusFilter.value)
  return list
})

async function fetchEvents() {
  loading.value = true
  try {
    const data = await apiFetch('/api/events')
    if (data.events?.length) {
      events.value = data.events.map(e => ({
        ...e,
        confidence: e.confidence ?? 0,
        techniques: e.techniques?.length ? e.techniques : [],
      }))
      loading.value = false
      return
    }
  } catch (e) { /* fallback to API error - empty */ }
  events.value = []
  loading.value = false
}

function timeOnly(dt) { const m = (dt || '').match(/(\d{2}:\d{2})/); return m ? m[1] : dt }

function primaryTech(techs) {
  if (!techs?.length) return { id: '-', confidence: 0 }
  return techs.reduce((a, b) => (a.confidence || 0) > (b.confidence || 0) ? a : b)
}

function severityColor(s) { return { '紧急': 'var(--error)', '高危': '#f97316', '中危': 'var(--warning)', '低危': 'var(--success)' }[s] || 'var(--text-muted)' }
function severityEng(s) { return { '紧急': 'CRITICAL', '高危': 'HIGH', '中危': 'MEDIUM', '低危': 'LOW' }[s] || (s || '').toUpperCase() }
function statusLabel(s) { return { open: 'OPEN', investigating: 'INVESTIGATING', resolved: 'RESOLVED' }[s] || (s || '').toUpperCase() }
function confBarColor(c) { if (c >= 0.8) return 'var(--success)'; if (c >= 0.6) return 'var(--warning)'; return 'var(--error)' }
function confTextColor(c) { if (c >= 0.8) return 'var(--success)'; if (c >= 0.6) return 'var(--warning)'; return 'var(--error)' }

function goToDetail(row) { router.push(`/events/${row.id}`) }

onMounted(fetchEvents)
</script>

<style scoped>
.events-page { padding: 20px; height: calc(100vh - var(--header-height)); display: flex; flex-direction: column; }
.events-header { margin-bottom: 16px; flex-shrink: 0; }
.header-top { display: flex; align-items: center; margin-bottom: 12px; }
.header-left { display: flex; align-items: center; gap: 10px; }
.page-title { font-size: 18px; font-weight: 700; color: var(--text-primary); }
.event-count { font-size: 11px; font-weight: 500; padding: 2px 10px; border-radius: var(--radius-full); background: var(--bg-elevated); color: var(--text-tertiary); }

/* ─── 过滤栏 ─── */
.filter-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.search-box { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 200px; max-width: 360px; padding: 6px 12px; background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); color: var(--text-muted); transition: border-color var(--transition-fast); }
.search-box:focus-within { border-color: var(--accent); }
.search-input { flex: 1; background: transparent; border: none; outline: none; color: var(--text-primary); font-size: 13px; }
.search-input::placeholder { color: var(--text-muted); }

.filter-select { padding: 6px 28px 6px 10px; background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); color: var(--text-secondary); font-size: 12px; outline: none; cursor: pointer; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 8px center; }
.filter-select:hover { border-color: var(--border-hover); }
.filter-select option { background: var(--bg-card); color: var(--text-primary); }

.refresh-btn { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); color: var(--text-muted); cursor: pointer; transition: all var(--transition-fast); }
.refresh-btn:hover { border-color: var(--accent); color: var(--accent); }
.refresh-btn.spinning { opacity: 0.6; }
.spin { animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ─── Skeleton ─── */
.table-skeleton { flex: 1; }
.skeleton-row { display: flex; gap: 12px; padding: 14px 16px; border-bottom: 1px solid var(--border-primary); animation: skeleton-pulse 1.8s ease-in-out infinite; }
.sk-cell { height: 14px; border-radius: 4px; background: var(--bg-card-hover); }
.w-16 { width: 60px; } .w-20 { width: 80px; } .w-24 { width: 100px; } .w-40 { width: 200px; }

/* ─── 表格卡片 ─── */
.table-card { flex: 1; background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); overflow-y: auto; }
.event-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.event-table thead { position: sticky; top: 0; z-index: 1; }
.event-table th { text-align: left; padding: 10px 14px; font-size: 10px; font-weight: 600; color: var(--text-muted); letter-spacing: 0.5px; background: var(--bg-elevated); border-bottom: 1px solid var(--border-primary); text-transform: uppercase; }
.event-table td { padding: 10px 14px; border-bottom: 1px solid var(--border-primary); color: var(--text-secondary); }
.event-row { cursor: pointer; transition: background var(--transition-fast); }
.event-row:hover { background: var(--bg-card-hover); }
.event-row:last-child td { border-bottom: none; }

.col-time { width: 60px; } .col-event { min-width: 200px; } .col-attack { width: 80px; } .col-conf { width: 120px; } .col-assoc { min-width: 120px; } .col-status { width: 120px; } .col-risk { width: 80px; }

.time-text { color: var(--text-muted); font-size: 12px; font-weight: 500; font-variant-numeric: tabular-nums; font-family: var(--font-mono); }

.event-cell { display: flex; align-items: center; gap: 8px; }
.severity-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.event-title-text { color: var(--text-primary); font-weight: 500; }
.ip-tag { font-size: 10px; color: var(--text-muted); background: var(--bg-elevated); padding: 1px 6px; border-radius: 3px; font-family: var(--font-mono); }

.attack-id { color: var(--warning); font-weight: 700; font-size: 12px; font-family: var(--font-mono); letter-spacing: 0.5px; }
.attack-na { color: var(--text-muted); font-size: 11px; }

.conf-cell { display: flex; align-items: center; gap: 8px; }
.conf-bar { flex: 1; max-width: 60px; height: 6px; border-radius: 3px; background: var(--bg-elevated); overflow: hidden; }
.conf-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
.conf-text { font-size: 12px; font-weight: 700; font-variant-numeric: tabular-nums; }

.status-tag { font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: var(--radius-full); letter-spacing: 0.5px; }
.st-open { background: var(--error-bg); color: var(--error); }
.st-investigating { background: var(--warning-bg); color: var(--warning); }
.st-resolved { background: var(--success-bg); color: var(--success); }

/* ─── 关联信息徽章 ─── */
.assoc-cell { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
.badge { font-size: 9px; font-weight: 600; padding: 1px 6px; border-radius: 3px; letter-spacing: 0.3px; white-space: nowrap; }
.badge-cve { background: #fef2f2; color: #dc2626; border: 1px solid #fca5a5; }
.badge-apt { background: #f0f9ff; color: #0369a1; border: 1px solid #7dd3fc; }
.badge-malware { background: #fdf4ff; color: #a21caf; border: 1px solid #e879f9; }
.badge-high { background: #fff7ed; color: #c2410c; border: 1px solid #fdba74; }

.risk-text { font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }

.empty-row { text-align: center; padding: 40px !important; color: var(--text-muted); font-size: 13px; }

/* ─── 响应式 ─── */
@media (max-width: 768px) {
  .events-page { padding: 12px; }
  .filter-bar { flex-direction: column; align-items: stretch; }
  .search-box { max-width: none; }
  .event-table { font-size: 11px; }
  .col-event { min-width: 120px; }
  .col-time, .col-attack, .col-risk { display: none; }
}
</style>
