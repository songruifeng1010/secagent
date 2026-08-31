<template>
  <div style="padding: 24px;">
    <n-h2> 攻击链自动生成</n-h2>
    <n-text depth="3">基于告警自动聚类 -> ATT&CK映射 -> 杀伤链构建</n-text>

    <n-space style="margin-top: 16px;">
      <n-button type="primary" @click="loadChain" :loading="loading">
         从真实告警构建攻击链
      </n-button>
      <n-button @click="loadChainHistory" :loading="loadingHistory">
         查看历史
      </n-button>
    </n-space>

    <!-- 攻击链仪表盘 -->
    <div v-if="chain" style="margin-top: 20px;">
      <n-grid :cols="5" :x-gap="12" :y-gap="12">
        <n-grid-item>
          <n-card size="small" :bordered="true">
            <n-statistic title="杀伤链覆盖率" :value="`${chain.coverage}%`" />
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card size="small" :bordered="true">
            <n-statistic title="检测到阶段" :value="`${chain.detected_steps}/${chain.total_steps}`" />
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card size="small" :bordered="true">
            <n-statistic title="整体置信度" :value="`${(chain.overall_confidence * 100).toFixed(0)}%`" />
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card size="small" :bordered="true">
            <n-statistic title="告警总数" :value="chain.total_alerts" />
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card size="small" :bordered="true">
            <template #header>
              <n-text depth="3">源IP</n-text>
            </template>
            <n-text tag="code">{{ chain.source_ip }}</n-text>
          </n-card>
        </n-grid-item>
      </n-grid>

      <!-- 杀伤链可视化图 -->
      <n-card title=" 杀伤链 (Kill Chain)" :bordered="true" style="margin-top: 16px;">
        <div style="display: flex; flex-wrap: wrap; gap: 4px; align-items: center;">
          <template v-for="(v, i) in chain.kill_chain_visual" :key="v.position">
            <!-- 阶段节点 -->
            <div
              :style="{
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                padding: '8px 10px', borderRadius: '8px', minWidth: '72px',
                background: v.status === 'detected'
                  ? (v.confidence >= 0.8 ? 'rgba(74,222,128,0.15)' : v.confidence >= 0.5 ? 'rgba(250,204,21,0.15)' : 'rgba(248,113,113,0.15)')
                  : 'rgba(75,85,99,0.2)',
                border: v.status === 'detected'
                  ? (v.confidence >= 0.8 ? '2px solid #4ade80' : v.confidence >= 0.5 ? '2px solid #facc15' : '2px solid #f87171')
                  : '2px dashed #4b5563',
                cursor: v.status === 'detected' ? 'pointer' : 'default',
                transition: 'all 0.2s',
              }"
              @click="v.status === 'detected' && selectStep(v)"
              :title="v.status === 'detected' ? `${v.technique_name} (${v.confidence})` : '未检测到'"
            >
              <div :style="{ fontSize: '12px', color: '#94a3b8' }">[{{ v.position }}]</div>
              <div :style="{ fontSize: '11px', fontWeight: 'bold', textAlign: 'center', color: v.status === 'detected' ? '#e2e8f0' : '#6b7280' }">
                {{ v.tactic_name.length > 4 ? v.tactic_name.slice(0,4) : v.tactic_name }}
              </div>
              <div v-if="v.status === 'detected'" :style="{ fontSize: '9px', color: v.confidence >= 0.8 ? '#4ade80' : '#facc15', marginTop: '2px' }">
                {{ (v.confidence * 100).toFixed(0) }}%
              </div>
              <div v-else :style="{ fontSize: '16px', color: '#4b5563' }"></div>
            </div>
            <!-- 箭头 -->
            <div v-if="i < chain.kill_chain_visual.length - 1" :style="{ color: '#4b5563', fontSize: '16px' }">
              ->
            </div>
          </template>
        </div>

        <!-- 图例 -->
        <div style="margin-top: 12px; display: flex; gap: 16px;">
          <n-space><div style="width:16px;height:16px;border-radius:4px;background:rgba(74,222,128,0.3);border:2px solid #4ade80;"></div><n-text depth="3" style="font-size:12px;">高置信度</n-text></n-space>
          <n-space><div style="width:16px;height:16px;border-radius:4px;background:rgba(250,204,21,0.3);border:2px solid #facc15;"></div><n-text depth="3" style="font-size:12px;">中置信度</n-text></n-space>
          <n-space><div style="width:16px;height:16px;border-radius:4px;background:rgba(248,113,113,0.3);border:2px solid #f87171;"></div><n-text depth="3" style="font-size:12px;">低置信度</n-text></n-space>
          <n-space><div style="width:16px;height:16px;border-radius:4px;background:rgba(75,85,99,0.2);border:2px dashed #4b5563;"></div><n-text depth="3" style="font-size:12px;">未检测到</n-text></n-space>
        </div>
      </n-card>

      <n-grid :cols="2" :x-gap="16" style="margin-top: 16px;">
        <!-- 详细步骤 -->
        <n-grid-item>
          <n-card title=" 检测到的攻击步骤" :bordered="true">
            <n-list v-if="chain.steps.length > 0">
              <n-list-item v-for="s in chain.steps" :key="s.position"
                :style="{ background: selectedStepPos === s.position ? 'rgba(99,102,241,0.1)' : '', borderRadius: '4px' }"
                clickable @click="selectStep(s)">
                <n-thing :title="`第${s.position}步: ${s.tactic_name}`">
                  <template #header-extra>
                    <n-tag :type="confTag(s.confidence)" size="tiny">{{ (s.confidence * 100).toFixed(0) }}%</n-tag>
                  </template>
                  <template #description>
                    <div><n-tag size="tiny" :bordered="false">{{ s.technique_id }}</n-tag> {{ s.technique_name }}</div>
                    <n-text depth="3" style="font-size: 0.85em;">{{ s.alerts_count }} 条告警</n-text>
                    <div v-if="s.evidence && s.evidence.length > 0" style="margin-top: 4px;">
                      <div v-for="ev in s.evidence.slice(0,2)" :key="ev" style="font-size: 0.85em; color: #94a3b8;"> {{ ev }}</div>
                    </div>
                  </template>
                </n-thing>
              </n-list-item>
            </n-list>
            <n-empty v-else description="未检测到攻击阶段" />
          </n-card>
        </n-grid-item>

        <!-- 缺失阶段 + 原始告警 -->
        <n-grid-item>
          <n-card title=" 可能遗漏的阶段" :bordered="true" style="margin-bottom: 16px;">
            <n-list v-if="chain.missing_stages && chain.missing_stages.length > 0">
              <n-list-item v-for="m in chain.missing_stages" :key="m.tactic_id">
                <n-thing :title="`[${m.pos}] ${m.tactic_name}`" description="未触发告警，可能是遗漏阶段">
                  <template #avatar></template>
                </n-thing>
              </n-list-item>
            </n-list>
            <n-empty v-else description="所有阶段均已覆盖" />
          </n-card>

          <n-card title=" 原始聚类信息" :bordered="true">
            <div v-if="chain.cluster">
              <n-description-list :column="1" size="small">
                <n-description-list-item label="聚类ID">{{ chain.cluster.cluster_id }}</n-description-list-item>
                <n-description-list-item label="源IP">{{ chain.cluster.source_ip }}</n-description-list-item>
                <n-description-list-item label="告警数">{{ chain.cluster.alert_count }}</n-description-list-item>
                <n-description-list-item label="持续时间">{{ chain.cluster.duration_minutes }} 分钟</n-description-list-item>
                <n-description-list-item label="目标IP数">{{ chain.cluster.target_ips?.length || 0 }}</n-description-list-item>
                <n-description-list-item label="告警类型">
                  <n-space>
                    <n-tag v-for="at in chain.cluster.alert_types || []" :key="at" size="tiny" :bordered="false">{{ at }}</n-tag>
                  </n-space>
                </n-description-list-item>
              </n-description-list>
            </div>
          </n-card>
        </n-grid-item>
      </n-grid>
    </div>

    <!-- 初始占位 -->
    <div v-else-if="!loading" style="text-align: center; margin-top: 80px;">
      <n-h2 style="opacity: 0.5;"></n-h2>
      <n-text depth="3">点击「生成攻击链」从数据库中的真实告警构建杀伤链</n-text>
      <div style="margin-top: 16px;">
        <n-text depth="3" style="font-size: 0.9em;">
          系统将自动执行: <br>
          告警聚类 -> ATT&CK技术映射 -> 杀伤链排序 -> 缺失分析 -> 可视化
        </n-text>
      </div>
    </div>

    <n-spin v-else size="large" style="display: block; margin: 80px auto;" />
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useMessage } from 'naive-ui'
import { apiFetch } from '../utils/http.js'

const msg = useMessage()
// 使用相对路径，Vite 代理自动转发到后端
// 不再需要硬编码 apiBase

const loading = ref(false)
const loadingHistory = ref(false)
const chain = ref(null)
const selectedStepPos = ref(null)

function confTag(conf) {
  if (conf >= 0.8) return 'success'
  if (conf >= 0.5) return 'warning'
  return 'error'
}

async function loadChain() {
  loading.value = true
  try {
    chain.value = await apiFetch('/api/attack-chain/from-events?count=30')
    selectedStepPos.value = null
    msg.success('攻击链构建完成')
  } catch(e) {
    msg.error('构建失败: ' + e.message)
  }
  loading.value = false
}

async function loadChainHistory() {
  loadingHistory.value = true
  msg.info('当前视图按需从事件库重建，不生成演示历史')
  loadingHistory.value = false
}

function selectStep(step) {
  selectedStepPos.value = step.position || step.pos
}
</script>
