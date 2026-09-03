<template>
  <div class="event-detail-page" style="padding: 24px; height: calc(100vh - 48px); overflow-y: auto;">
    <!-- Loading State -->
    <div v-if="loading" style="display: flex; justify-content: center; align-items: center; height: 60vh;">
      <n-spin size="large" />
    </div>

    <!-- Event Not Found -->
    <div v-else-if="!event" style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 60vh; color: #475569; gap: 12px;">
      <div style="font-size: 48px; opacity: 0.3;">!</div>
      <div style="font-size: 16px; font-weight: 600;">事件未找到</div>
      <div style="font-size: 13px;">事件 ID "{{ $route.params.id }}" 不存在</div>
      <n-button size="small" @click="$router.push('/events')" style="margin-top: 8px;">&#8592; 返回事件列表</n-button>
    </div>

    <!-- Event Detail Content -->
    <template v-else>
      <!-- ====== 顶部导航面包屑 ====== -->
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 20px; font-size: 13px;">
        <n-button text size="tiny" @click="$router.push('/events')" style="color: #64748b;">事件</n-button>
        <span style="color: #475569;">/</span>
        <span style="color: #60a5fa; font-weight: 600;">{{ event.id }}</span>
        <div style="flex:1" />
        <n-button size="tiny" quaternary @click="$router.push('/events')">&#8592; 返回</n-button>
      </div>

      <!-- ====== 卡片1: 事件概要 Header ====== -->
      <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px; border-radius: 8px;">
        <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
          <div style="display: flex; align-items: center; gap: 12px;">
            <div style="width: 4px; height: 32px; border-radius: 2px; background: severityColor(event.severity);"></div>
            <div>
              <div style="color: #e2e8f0; font-size: 20px; font-weight: 700;">
                Event {{ event.id }}
              </div>
              <div style="color: #94a3b8; font-size: 13px; margin-top: 2px;">
                {{ event.title }} &middot; {{ event.created_at }}
              </div>
            </div>
          </div>
          <div style="flex:1; min-width: 20px;" />
          <n-tag :type="severityMapColor(event.severity)" size="medium" style="font-weight: 600;">
            {{ event.severity }}
          </n-tag>
          <n-tag :type="statusMapType(event.status)" size="medium" :bordered="false">
            {{ statusLabel(event.status) }}
          </n-tag>
          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-left:8px;">
            <n-button size="small" :loading="dispatching" @click="dispatchEvent('confirm')">确认事件</n-button>
            <n-button size="small" type="warning" :loading="dispatching" @click="dispatchEvent('escalate')">升级处置</n-button>
            <n-button v-if="event.source_ip" size="small" type="error" :loading="dispatching" @click="confirmFirewallBlock">封禁来源 IP</n-button>
          </div>
        </div>
        <div style="margin-top:12px; color:#94a3b8; font-size:11px; line-height:1.5;">
          事件状态更新由本机控制台直接记录；封禁会弹出二次确认，且仍受防火墙白名单、熔断器和后端开关约束。
        </div>
      </n-card>

      <!-- ====== 卡片2: 关键信息网格 ====== -->
      <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px; border-radius: 8px;">
        <template #header><span style="color: #e2e8f0; font-size: 14px; font-weight: 600;">关键信息</span></template>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <!-- Severity -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">SEVERITY</div>
            <div :style="{ color: textSeverityColor(event.severity), fontSize: '18px', fontWeight: '700' }">
              {{ event.severity }}
            </div>
          </div>
          <!-- Confidence -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">CONFIDENCE</div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <div style="flex: 1; max-width: 140px; height: 8px; border-radius: 4px; background: #2a2d38; overflow: hidden;">
                <div :style="{ width: (event.confidence * 100) + '%', height: '100%', borderRadius: '4px', background: confidenceBarColor(event.confidence) }"></div>
              </div>
              <span :style="{ color: confidenceTextColor(event.confidence), fontSize: '16px', fontWeight: '700' }">
                {{ (event.confidence * 100).toFixed(0) }}%
              </span>
            </div>
          </div>
          <!-- ATT&CK -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">MITRE ATT&CK</div>
            <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 2px;">
              <n-tag v-for="tech in event.techniques" :key="tech.id" size="small" color="#1e3a5f" style="color: #fbbf24; border: 1px solid #334155;">
                {{ tech.id }} {{ tech.name }}
              </n-tag>
              <span v-if="!event.techniques || event.techniques.length === 0" style="color: #64748b; font-size: 13px;">无映射</span>
            </div>
          </div>
          <!-- Alert Type -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">ALERT TYPE</div>
            <div style="color: #cbd5e1; font-size: 14px; font-weight: 500;">{{ event.alert_type }}</div>
          </div>
          <!-- CVE / APT / Malware -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">THREAT ASSOCIATIONS</div>
            <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 2px;">
              <n-tag v-if="event.cve_id" size="small" color="#3b1f1f" style="color: #fca5a5; border: 1px solid #7f1d1d;">
                🛡️ {{ event.cve_id }}
              </n-tag>
              <n-tag v-if="event.actor_name" size="small" color="#1e3a5f" style="color: #93c5fd; border: 1px solid #1e40af;">
                🕵️ {{ event.actor_name }}<span v-if="event.actor_country" style="color: #64748b; margin-left: 4px;">({{ event.actor_country }})</span>
              </n-tag>
              <n-tag v-if="event.malware_name" size="small" color="#3b1f3b" style="color: #f0abfc; border: 1px solid #86198f;">
                💀 {{ event.malware_name }}
              </n-tag>
              <n-tag v-if="event.threat_level === 'high'" size="small" color="#3b1f1f" style="color: #fbbf24; border: 1px solid #92400e;">
                高置信度威胁
              </n-tag>
              <span v-if="!event.cve_id && !event.actor_name && !event.malware_name" style="color: #64748b; font-size: 13px;">无关联</span>
            </div>
          </div>
          <!-- Source IP -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">SOURCE IP</div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <n-tag size="small" color="#1e293b" style="color: #60a5fa; border: 1px solid #334155;">
                <template #icon><span style="color: #3b82f6;">&#9679;</span></template>
                {{ event.source_ip }}
              </n-tag>
              <n-button size="tiny" quaternary circle style="color: #64748b;" @click="copyText(event.source_ip)" title="复制IP">
                                <template #icon><span style="font-size: 11px;">复制</span></template>
              </n-button>
            </div>
          </div>
          <!-- Destination -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">DESTINATION</div>
            <div style="color: #cbd5e1; font-size: 14px; font-weight: 500;">
              {{ event.destination || event.target || '—' }}
              <span v-if="event.destination_port" style="color: #64748b; margin-left: 4px;">:{{ event.destination_port }}</span>
            </div>
          </div>
          <!-- Source -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">DATA SOURCE</div>
            <div style="color: #a5d6ff; font-size: 13px;">{{ event.source || '—' }}</div>
            <div v-if="event.threat_sources && event.threat_sources.length" style="display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px;">
              <n-tag v-for="src in event.threat_sources.slice(0,3)" :key="src" size="tiny" color="#1e293b" style="color: #94a3b8; font-size: 10px;">
                {{ src }}
              </n-tag>
              <n-tag v-if="event.threat_sources.length > 3" size="tiny" color="#1e293b" style="color: #64748b;">+{{ event.threat_sources.length - 3 }}</n-tag>
            </div>
          </div>
          <!-- Timestamp -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">DETECTED AT</div>
            <div style="color: #94a3b8; font-size: 13px;">{{ event.created_at }}</div>
          </div>
        </div>
      </n-card>

      <!-- ====== 卡片3: AI Analysis ====== -->
      <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px; border-radius: 8px;">
        <template #header>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="color: #22c55e; font-size: 16px; font-weight: 600;">AI Analysis</span>
            <n-tag size="tiny" color="#1e293b" style="color: #94a3b8;">Agent-Intel &middot; Analyst</n-tag>
          </div>
        </template>

        <div style="color: #cbd5e1; font-size: 13px; line-height: 1.7;">
          <div v-if="event.ai_analysis" style="white-space: pre-wrap;">{{ event.ai_analysis }}</div>
          <n-empty v-else size="small" description="该事件尚无已持久化的 AI 分析结果" />
        </div>
      </n-card>

      <!-- ====== 卡片4: IOC & 技术详表 ====== -->
      <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px; border-radius: 8px;">
        <template #header>
          <div style="display: flex; align-items: center; gap: 12px;">
            <span style="color: #e2e8f0; font-size: 14px; font-weight: 600;">IOC &amp; 技术映射</span>
            <n-tag size="tiny" color="#1e293b" style="color: #94a3b8;">{{ iocList.length }} 项IOC &middot; {{ event.techniques ? event.techniques.length : 0 }} 项技术</n-tag>
          </div>
        </template>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <!-- IOC 列表 -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 8px;">威胁指标 (IOC)</div>
            <div v-if="iocList.length > 0" style="display: flex; flex-direction: column; gap: 6px;">
              <div v-for="ioc in iocList" :key="ioc.value" style="display: flex; align-items: center; gap: 8px; background: #1a1d29; padding: 8px 12px; border-radius: 6px; border: 1px solid #2a2d38;">
                <span :style="{ color: iocColor(ioc.type), fontSize: '11px', fontWeight: '700', minWidth: '36px', textTransform: 'uppercase' }">{{ iocLabel(ioc.type) }}</span>
                <code style="color: #a5d6ff; font-size: 12px; flex: 1; background: #2a2d38; padding: 2px 8px; border-radius: 3px;">{{ ioc.value }}</code>
                <n-button size="tiny" quaternary circle style="color: #475569;" @click="copyText(ioc.value)">
                                  <template #icon><span style="font-size: 11px;">复制</span></template>
                </n-button>
              </div>
            </div>
            <div v-else style="color: #475569; font-size: 13px;">无关联IOC</div>
          </div>
          <!-- Technique 映射 -->
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 8px;">MITRE ATT&CK 映射</div>
            <div v-if="event.techniques && event.techniques.length > 0" style="display: flex; flex-direction: column; gap: 8px;">
              <div v-for="tech in event.techniques" :key="tech.id" style="background: #1a1d29; padding: 10px 12px; border-radius: 6px; border: 1px solid #2a2d38;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <n-button text size="tiny" style="color: #fbbf24; font-weight: 700;" @click="openMitre(tech.id)">{{ tech.id }}</n-button>
                  <span style="color: #cbd5e1; font-size: 13px;">{{ tech.name }}</span>
                  <div style="flex:1" />
                  <n-tag :bordered="false" size="tiny" :type="tech.confidence >= 0.8 ? 'success' : tech.confidence >= 0.5 ? 'warning' : 'info'">
                    {{ (tech.confidence * 100).toFixed(0) }}%
                  </n-tag>
                </div>
                <!-- 战术阶段标签 -->
                <div v-if="tech.tactic" style="margin-top: 4px;">
                  <n-tag size="tiny" color="#1e293b" style="color: #94a3b8;">{{ tech.tactic }}</n-tag>
                </div>
              </div>
            </div>
            <div v-else style="color: #475569; font-size: 13px;">无ATT&CK映射</div>
          </div>
        </div>
      </n-card>

      <!-- ====== 卡片5: 响应建议 ====== -->
      <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px; border-radius: 8px;">
        <template #header>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="color: #22c55e; font-size: 14px; font-weight: 600;">Recommendations</span>
            <n-tag size="tiny" color="#1e293b" style="color: #94a3b8;">Agent-Responder</n-tag>
          </div>
        </template>

        <div v-if="event.recommendation && event.recommendation.length > 0" style="display: flex; flex-direction: column; gap: 8px;">
          <div v-for="(rec, ri) in event.recommendation" :key="ri"
               style="display: flex; align-items: flex-start; gap: 12px; background: #0f1117; padding: 12px 16px; border-radius: 6px; border: 1px solid #2a2d38;">
            <div style="width: 22px; height: 22px; border-radius: 50%; background: rgba(34,197,94,0.15); display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 1px;">
              <span style="color: #22c55e; font-size: 12px; font-weight: 700;">{{ ri + 1 }}</span>
            </div>
            <div style="flex: 1; color: #cbd5e1; font-size: 13px; line-height: 1.5;">{{ rec }}</div>
            <n-tag size="tiny" :bordered="false">建议，需人工确认</n-tag>
          </div>
        </div>
        <div v-else style="color: #475569; font-size: 13px;">无建议</div>
      </n-card>

      <!-- ====== 卡片6: 原始告警数据 ====== -->
      <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px; border-radius: 8px;">
        <template #header>
          <span style="color: #e2e8f0; font-size: 14px; font-weight: 600;">原始数据</span>
        </template>
        <n-code :code="rawJson" language="json" style="font-size: 12px; background: #0f1117; border-radius: 6px; padding: 12px;" />
      </n-card>
    </template>
  </div>
</template>

<style scoped>
.event-detail-page { padding: 24px; height: calc(100vh - var(--header-height)); overflow-y: auto; }
.detail-loading { display: flex; justify-content: center; align-items: center; height: 60vh; }
.detail-empty { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 60vh; color: var(--text-muted); gap: 12px; }
.detail-empty-icon { width: 48px; height: 48px; border-radius: 50%; background: var(--bg-elevated); display: flex; align-items: center; justify-content: center; font-size: 20px; font-weight: 700; color: var(--text-muted); }
.breadcrumb { display: flex; align-items: center; gap: 8px; margin-bottom: 20px; font-size: 13px; }
.breadcrumb-sep { color: var(--text-muted); opacity: 0.4; }
.breadcrumb-current { color: var(--info); font-weight: 600; }
.detail-card { margin-bottom: 16px; }
.event-header-card { padding: 20px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.header-accent { width: 4px; height: 36px; border-radius: 2px; flex-shrink: 0; }
.event-title-large { font-size: 20px; font-weight: 700; color: var(--text-primary); }
.event-title-sub { font-size: 13px; color: var(--text-tertiary); margin-top: 2px; }
.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.info-label { font-size: 11px; font-weight: 600; color: var(--text-muted); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
.info-value { font-size: 14px; font-weight: 500; color: var(--text-secondary); }
.info-value-lg { font-size: 18px; font-weight: 700; }
.conf-bar-wrap { display: flex; align-items: center; gap: 10px; }
.conf-bar-track { flex: 1; max-width: 140px; height: 8px; border-radius: 4px; background: var(--bg-elevated); overflow: hidden; }
.conf-bar-fill { height: 100%; border-radius: 4px; }
.tech-tag { font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: var(--radius-sm); background: rgba(30,58,95,0.5); color: var(--warning); border: 1px solid var(--border-primary); cursor: pointer; transition: all var(--transition-fast); }
.tech-tag:hover { border-color: var(--warning); }
.ip-value { font-size: 13px; font-family: var(--font-mono); color: var(--info); }
.copy-btn { width: 24px; height: 24px; display: inline-flex; align-items: center; justify-content: center; border-radius: 50%; border: none; background: transparent; color: var(--text-muted); cursor: pointer; transition: all var(--transition-fast); }
.copy-btn:hover { background: var(--bg-card-hover); color: var(--text-tertiary); }

/* ─── Timeline ─── */
.timeline-section { margin-bottom: 16px; }
.timeline { position: relative; padding-left: 28px; }
.timeline::before { content: ''; position: absolute; left: 9px; top: 8px; bottom: 8px; width: 2px; background: var(--border-primary); }
.timeline-item { position: relative; padding: 0 0 20px 20px; }
.timeline-item:last-child { padding-bottom: 0; }
.timeline-dot { position: absolute; left: -24px; top: 4px; width: 16px; height: 16px; border-radius: 50%; border: 2px solid; display: flex; align-items: center; justify-content: center; background: var(--bg-card); }
.timeline-dot-inner { width: 6px; height: 6px; border-radius: 50%; }
.timeline-time { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); }
.timeline-title { font-size: 13px; font-weight: 600; color: var(--text-primary); margin-top: 2px; }
.timeline-desc { font-size: 12px; color: var(--text-tertiary); margin-top: 2px; }

/* ─── IOC list ─── */
.ioc-item { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-primary); background: var(--bg-primary); }
.ioc-type { font-size: 11px; font-weight: 700; min-width: 36px; text-transform: uppercase; }
.ioc-value { font-size: 12px; font-family: var(--font-mono); color: #a5d6ff; flex: 1; background: var(--bg-elevated); padding: 2px 8px; border-radius: 3px; }

/* ─── Recommendation ─── */
.rec-item { display: flex; align-items: flex-start; gap: 12px; padding: 12px 16px; border-radius: var(--radius-sm); border: 1px solid var(--border-primary); background: var(--bg-primary); }
.rec-num { width: 22px; height: 22px; border-radius: 50%; background: var(--success-bg); display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 1px; color: var(--success); font-size: 12px; font-weight: 700; }
.rec-text { flex: 1; color: var(--text-secondary); font-size: 13px; line-height: 1.5; }
.rec-btn { padding: 2px 10px; border: 1px solid var(--border-primary); border-radius: var(--radius-sm); background: transparent; color: var(--info); font-size: 11px; cursor: pointer; transition: all var(--transition-fast); }
.rec-btn:hover { border-color: var(--info); background: var(--info-bg); }

/* ─── Bayesian ─── */
.bayes-row { display: flex; align-items: center; gap: 12px; }
.bayes-label { font-size: 11px; color: var(--text-muted); min-width: 60px; }
.bayes-bar { width: 60px; height: 4px; border-radius: 2px; }
.bayes-val { font-size: 12px; font-weight: 600; color: var(--text-primary); }

/* ─── Skeleton ─── */
.detail-skeleton { padding: 24px; }
.sk-block { height: 60px; border-radius: var(--radius-md); margin-bottom: 16px; background: linear-gradient(90deg, var(--border-primary) 25%, var(--bg-card-hover) 50%, var(--border-primary) 75%); background-size: 200% 100%; animation: skeleton-pulse 1.8s ease-in-out infinite; }
.sk-block-sm { height: 200px; }

/* ═══ 响应式 EventDetailView ═══ */
@media (max-width: 768px) {
  .event-detail-page { padding: 12px !important; }
  .event-header-card { flex-direction: column !important; align-items: flex-start !important; gap: 8px !important; }
  .info-grid { grid-template-columns: 1fr !important; gap: 8px !important; }
  .event-title-large { font-size: 16px !important; }
}
</style>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useDialog, useMessage } from 'naive-ui'
import { apiFetch } from '../utils/http.js'

const route = useRoute()
const message = useMessage()
const dialog = useDialog()

const loading = ref(true)
const event = ref(null)
const dispatching = ref(false)

const iocList = computed(() => {
  if (!event.value) return []
  const values = Array.isArray(event.value.iocs) ? event.value.iocs : []
  return values.map((ioc) => {
    if (typeof ioc === 'string') return { type: 'indicator', value: ioc }
    return { type: ioc.type || 'indicator', value: ioc.value || ioc.indicator || '' }
  }).filter((ioc) => ioc.value)
})

const rawJson = computed(() => JSON.stringify(event.value || {}, null, 2))

function severityColor(level) {
  return { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', '紧急': '#ef4444', '高危': '#f97316', '中危': '#eab308', '低危': '#22c55e' }[level] || '#64748b'
}
function textSeverityColor(level) { return severityColor(level) }
function severityMapColor(level) {
  return { critical: 'error', high: 'error', medium: 'warning', low: 'success', '紧急': 'error', '高危': 'error', '中危': 'warning', '低危': 'success' }[level] || 'default'
}
function statusMapType(status) { return { open: 'error', investigating: 'warning', confirmed: 'info', escalated: 'warning', blocked: 'error', ignored: 'default', resolved: 'success', closed: 'default' }[status] || 'default' }
function statusLabel(status) { return { open: '待处理', investigating: '调查中', confirmed: '已确认', escalated: '已升级', blocked: '已封禁', ignored: '已忽略', resolved: '已解决', closed: '已关闭' }[status] || status || '未知' }
function confidenceBarColor(value) { return Number(value) >= 0.8 ? '#22c55e' : Number(value) >= 0.5 ? '#eab308' : '#ef4444' }
function confidenceTextColor(value) { return confidenceBarColor(value) }
function iocColor(type) { return { ip: '#60a5fa', domain: '#c084fc', hash: '#f59e0b', url: '#34d399' }[type] || '#94a3b8' }
function iocLabel(type) { return { ip: 'IP', domain: '域名', hash: 'HASH', url: 'URL', indicator: 'IOC' }[type] || String(type || 'IOC').toUpperCase() }
function copyText(value) {
  navigator.clipboard.writeText(String(value || '')).then(() => message.success('已复制')).catch(() => message.warning('复制失败'))
}
function openMitre(techniqueId) {
  if (/^T\d{4}(?:\.\d{3})?$/.test(String(techniqueId || ''))) {
    window.open(`https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`, '_blank', 'noopener,noreferrer')
  }
}

async function submitDispatch(payload, successText) {
  dispatching.value = true
  try {
    const result = await apiFetch('/api/dispatch', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    if (!result.success) throw new Error(result.error || '处置未完成')
    message.success(successText || result.message || '处置已记录')
    await fetchEvent(route.params.id)
  } catch (error) {
    message.error(error.message || '处置失败')
  } finally {
    dispatching.value = false
  }
}

function dispatchEvent(action) {
  const labels = { confirm: '确认', escalate: '升级' }
  void submitDispatch({
    action,
    event_id: event.value.id,
    reason: `本机控制台人工${labels[action] || '处置'}事件`,
  }, `事件已${labels[action] || '处理'}`)
}

function confirmFirewallBlock() {
  const ip = event.value?.source_ip
  if (!ip) return
  dialog.warning({
    title: '确认封禁来源 IP',
    content: `将封禁 ${ip} 120 分钟。此操作会改变网络访问规则；请确认它不是白名单或业务地址。`,
    positiveText: '确认封禁',
    negativeText: '取消',
    onPositiveClick: () => submitDispatch({
      action: 'block',
      ip,
      duration_minutes: 120,
      reason: `本机控制台人工确认：事件 ${event.value.id}`,
      confirmed: true,
    }, `已提交 ${ip} 的封禁操作`),
  })
}
// 事件详情只展示后端持久化的真实事件；失败时保留空状态。
async function fetchEvent(id) {
  try {
    const payload = await apiFetch(`/api/events/${id}`)
    payload.confidence = Number(payload.confidence) || 0
    payload.techniques = (Array.isArray(payload.techniques) ? payload.techniques : []).map((tech) => ({
      ...tech,
      confidence: Number(tech.confidence) || 0,
    }))
    payload.recommendation = Array.isArray(payload.recommendation) ? payload.recommendation : []
    event.value = payload
    return true
  } catch (e) {
    console.warn('[EventDetailView] 事件加载失败:', e.message)
  }
  return false
}

onMounted(async () => {
  const id = route.params.id
  await fetchEvent(id)
  loading.value = false
})
</script>
