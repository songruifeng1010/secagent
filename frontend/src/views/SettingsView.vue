<template>
  <div style="padding: 20px; height: calc(100vh - 80px); overflow-y: auto;">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
      <div>
        <div style="color: #e2e8f0; font-size: 20px; font-weight: 700;">系统设置</div>
        <div style="color: #64748b; font-size: 13px; margin-top: 4px;">自动模块运行状态 · 数据保留策略 · 运行时配置</div>
      </div>
      <n-button size="small" quaternary @click="showConfigModal = true" :loading="loadingConfig">
        编辑配置
      </n-button>
    </div>

    <!-- 自动模块状态 -->
    <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px;">
      <template #header>
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="color:#e2e8f0;font-weight:600;">零人工干预模块</span>
          <n-tag v-if="autoStatus.enabled" size="small" type="success" :bordered="false">已启用</n-tag>
          <n-tag v-else size="small" type="error" :bordered="false">已禁用</n-tag>
          <n-button size="tiny" quaternary @click="fetchAutoStatus" :loading="loading" style="margin-left:auto;">刷新</n-button>
        </div>
      </template>
      <n-descriptions :column="2" label-placement="left" bordered size="small">
        <n-descriptions-item>
          <template #label>告警接入器</template>
          <span v-if="autoStatus.ingestor" style="color:#22c55e;">运行中 · 已处理 {{ autoStatus.ingestor.processed_count || 0 }} 条</span>
          <span v-else style="color:#64748b;">未启动</span>
        </n-descriptions-item>
        <n-descriptions-item>
          <template #label>告警去重</template>
          <span v-if="autoStatus.ingestor?.dedup" style="color:#94a3b8;">
            窗口 {{ autoStatus.ingestor.dedup.window_seconds }}s · 追踪 {{ autoStatus.ingestor.dedup.tracked_entries }} 条
          </span>
          <span v-else style="color:#64748b;">-</span>
        </n-descriptions-item>
        <n-descriptions-item>
          <template #label>安全巡检器</template>
          <span v-if="autoStatus.patrol" style="color:#22c55e;">
            已执行 {{ autoStatus.patrol.patrol_count || 0 }} 次 · 间隔 {{ autoStatus.patrol.interval_seconds }}s
          </span>
          <span v-else style="color:#64748b;">未启动</span>
        </n-descriptions-item>
        <n-descriptions-item>
          <template #label>升级通知引擎</template>
          <span v-if="autoStatus.escalation && autoStatus.escalation.length > 0" style="color:#22c55e;">
            {{ autoStatus.escalation.filter(e => e.enabled).map(e => e.type).join(', ') || '仅控制台' }}
          </span>
          <span v-else style="color:#64748b;">未配置</span>
        </n-descriptions-item>
      </n-descriptions>
    </n-card>

    <!-- 数据保留策略 -->
    <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px;">
      <template #header>
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="color:#e2e8f0;font-weight:600;">数据保留策略</span>
          <n-tag v-if="retention.enabled" size="small" type="success" :bordered="false">已启用</n-tag>
          <n-tag v-else size="small" type="warning" :bordered="false">未启用</n-tag>
        </div>
      </template>
      <n-descriptions :column="2" label-placement="left" bordered size="small">
        <n-descriptions-item><template #label>安全事件</template>{{ retention.event_retention_days || 90 }} 天</n-descriptions-item>
        <n-descriptions-item><template #label>对话记录</template>{{ retention.conversation_retention_days || 30 }} 天</n-descriptions-item>
        <n-descriptions-item><template #label>IOC</template>{{ retention.ioc_retention_days || 365 }} 天</n-descriptions-item>
        <n-descriptions-item><template #label>清理周期</template>每 {{ retention.run_interval_hours || 24 }} 小时</n-descriptions-item>
        <n-descriptions-item><template #label>上次执行</template>{{ retention.last_run || '未执行' }}</n-descriptions-item>
      </n-descriptions>
    </n-card>

    <!-- 熔断器状态 -->
    <n-card :bordered="true" size="small" style="background: #171923; margin-bottom: 16px;">
      <template #header>
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="color:#e2e8f0;font-weight:600;">熔断器</span>
          <n-tag :type="cbStatus.state === 'open' ? 'error' : cbStatus.state === 'half_open' ? 'warning' : 'success'" size="small" :bordered="false">
            {{ cbStatus.state === 'open' ? '已熔断' : cbStatus.state === 'half_open' ? '半开' : '正常' }}
          </n-tag>
        </div>
      </template>
      <n-descriptions :column="2" label-placement="left" bordered size="small">
        <n-descriptions-item><template #label>状态</template>{{ cbStatus.state }}</n-descriptions-item>
        <n-descriptions-item><template #label>连续失败</template>{{ cbStatus.failures || 0 }} / {{ cbStatus.failure_threshold || 3 }}</n-descriptions-item>
        <n-descriptions-item><template #label>今日封禁</template>{{ cbStatus.blocks_today || 0 }} / {{ cbStatus.daily_limit || 20 }}</n-descriptions-item>
        <n-descriptions-item><template #label>自动恢复</template>{{ (cbStatus.auto_reset_seconds || 1800) / 60 }} 分钟后</n-descriptions-item>
      </n-descriptions>
    </n-card>

    <!-- 编辑配置弹窗 -->
    <n-modal v-model:show="showConfigModal" preset="card" title="编辑运行时配置" style="width: 600px;"
      :bordered="true" :mask-closable="false">
      <n-form ref="configFormRef" :model="configForm" label-placement="left" label-width="140px">
        <n-divider>自动处置</n-divider>
        <n-form-item label="自动处置开关">
          <n-switch v-model:value="configForm.auto_operation.enabled" />
        </n-form-item>
        <n-form-item label="自动闭环阈值">
          <n-input-number v-model:value="configForm.auto_operation.thresholds.auto_close" :min="0" :max="1" :step="0.05" />
        </n-form-item>
        <n-form-item label="自动封禁阈值">
          <n-input-number v-model:value="configForm.auto_operation.thresholds.auto_block" :min="0" :max="1" :step="0.05" />
        </n-form-item>
        <n-form-item label="升级人工阈值">
          <n-input-number v-model:value="configForm.auto_operation.thresholds.manual_escalation" :min="0" :max="1" :step="0.05" />
        </n-form-item>
        <n-divider>安全巡检</n-divider>
        <n-form-item label="巡检间隔(秒)">
          <n-input-number v-model:value="configForm.auto_operation.patrol.interval_seconds" :min="60" :step="60" />
        </n-form-item>
        <n-form-item label="封禁续期阈值">
          <n-input-number v-model:value="configForm.auto_operation.patrol.block_renew_threshold" :min="0" :max="1" :step="0.05" />
        </n-form-item>
        <n-form-item label="最多续封次数">
          <n-input-number v-model:value="configForm.auto_operation.patrol.max_renew_count" :min="1" :max="10" />
        </n-form-item>
        <n-divider>数据保留</n-divider>
        <n-form-item label="自动清理开关">
          <n-switch v-model:value="configForm.data_retention.enabled" />
        </n-form-item>
        <n-form-item label="事件保留(天)">
          <n-input-number v-model:value="configForm.data_retention.event_retention_days" :min="7" :max="730" />
        </n-form-item>
        <n-form-item label="对话保留(天)">
          <n-input-number v-model:value="configForm.data_retention.conversation_retention_days" :min="1" :max="365" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-button @click="showConfigModal = false" style="margin-right:8px;">取消</n-button>
        <n-button type="primary" :loading="savingConfig" @click="saveConfig">保存配置</n-button>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import { apiFetch } from '../utils/http.js'

const msg = useMessage()
const loading = ref(false)
const loadingConfig = ref(false)
const savingConfig = ref(false)
const showConfigModal = ref(false)

const autoStatus = reactive({ enabled: false, ingestor: null, patrol: null, escalation: null })
const retention = reactive({ enabled: false, event_retention_days: 90, conversation_retention_days: 30, ioc_retention_days: 365, run_interval_hours: 24, last_run: '未执行' })
const cbStatus = reactive({ state: 'closed', failures: 0, blocks_today: 0, failure_threshold: 3, daily_limit: 20, auto_reset_seconds: 1800 })

const configForm = reactive({
  auto_operation: {
    enabled: true,
    thresholds: { auto_close: 0.85, auto_block: 0.70, manual_escalation: 0.30 },
    patrol: { interval_seconds: 1800, block_renew_threshold: 0.50, max_renew_count: 3 },
  },
  data_retention: {
    enabled: false, event_retention_days: 90, conversation_retention_days: 30,
    ioc_retention_days: 365, run_interval_hours: 24,
  },
})

async function fetchAutoStatus() {
  loading.value = true
  try {
    const data = await apiFetch('/api/auto/status')
    Object.assign(autoStatus, data)
    if (data.data_retention) Object.assign(retention, data.data_retention)
    const hdata = await apiFetch('/api/health')
    if (hdata.circuit_breaker) Object.assign(cbStatus, hdata.circuit_breaker)
  } catch (e) { /* offline */ }
  loading.value = false
}

async function loadConfig() {
  loadingConfig.value = true
  try {
    const data = await apiFetch('/api/auto/config')
    if (data.auto_operation) Object.assign(configForm.auto_operation, data.auto_operation)
    if (data.data_retention) Object.assign(configForm.data_retention, data.data_retention)
    if (data.thresholds) Object.assign(configForm.auto_operation.thresholds, data.thresholds)
    if (data.patrol) Object.assign(configForm.auto_operation.patrol, data.patrol)
  } catch (e) { /* use defaults */ }
  loadingConfig.value = false
}

async function saveConfig() {
  savingConfig.value = true
  try {
    await apiFetch('/api/admin/config', {
      method: 'PUT',
      body: JSON.stringify({
        auto_operation: configForm.auto_operation,
        data_retention: configForm.data_retention,
      }),
    })
    msg.success('配置已保存')
    showConfigModal.value = false
    await fetchAutoStatus()
  } catch (e) {
    msg.error('保存失败: ' + e.message)
  }
  savingConfig.value = false
}

onMounted(() => {
  fetchAutoStatus()
  loadConfig()
})
</script>
