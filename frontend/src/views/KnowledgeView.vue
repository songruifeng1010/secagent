<template>
  <div class="knowledge-page" style="padding: 16px; display: flex; flex-direction: column; height: calc(100vh - var(--header-height));">
    <!-- Tabs -->
    <n-card :bordered="true" size="small" style="background: #171923; flex-shrink: 0;">
      <n-tabs v-model:value="activeTab" type="line" :bar-width="80" @update:value="onTabChange">
        <n-tab-pane name="mitre" tab="ATT&CK 知识库">
          <template #tab>
            <span style="font-weight: 600; font-size: 14px;">ATT&CK 知识库</span>
          </template>
        </n-tab-pane>
        <n-tab-pane name="owasp" tab="OWASP 安全知识">
          <template #tab>
            <span style="font-weight: 600; font-size: 14px;">OWASP 安全知识</span>
          </template>
        </n-tab-pane>
        <n-tab-pane name="cve" tab="CVE 漏洞库">
          <template #tab>
            <span style="font-weight: 600; font-size: 14px;">CVE 漏洞库</span>
          </template>
        </n-tab-pane>
        <n-tab-pane name="rules" tab="检测规则">
          <template #tab>
            <span style="font-weight: 600; font-size: 14px;">检测规则</span>
          </template>
        </n-tab-pane>
      </n-tabs>
    </n-card>

    <!-- MITRE 内容：热力图矩阵 -->
    <div v-if="activeTab === 'mitre'" style="flex: 1; display: flex; gap: 16px; margin-top: 16px; overflow: hidden;">
      <!-- 左侧: 热力图 -->
      <div :style="{ width: selectedTech ? '55%' : '100%', display: 'flex', flexDirection: 'column', transition: 'width 0.3s ease' }">
        <n-card :bordered="true" size="small" style="background: #171923; flex: 1; display: flex; flex-direction: column;">
          <template #header>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="color: #e2e8f0; font-size: 14px; font-weight: 600;">ATT&CK Matrix</span>
              <n-tag size="tiny" color="#1e293b" style="color: #94a3b8;">{{ heatmapTactics.length }} 战术 · {{ allTechniques.length }} 技术</n-tag>
              <div style="flex:1" />
              <div style="display: flex; align-items: center; gap: 6px;">
                <span style="color: #64748b; font-size: 10px;">子技术数</span>
                <span style="width: 12px; height: 12px; border-radius: 2px; background: #334155; display: inline-block;"></span><span style="color: #64748b; font-size: 10px;">0</span>
                <span style="width: 12px; height: 12px; border-radius: 2px; background: #eab308; display: inline-block;"></span><span style="color: #64748b; font-size: 10px;">1-5</span>
                <span style="width: 12px; height: 12px; border-radius: 2px; background: #f97316; display: inline-block;"></span><span style="color: #64748b; font-size: 10px;">6-10</span>
                <span style="width: 12px; height: 12px; border-radius: 2px; background: #ef4444; display: inline-block;"></span><span style="color: #64748b; font-size: 10px;">10+</span>
              </div>
            </div>
          </template>
          <div ref="mitreHeatmapRef" style="width: 100%; flex: 1; min-height: 400px;"></div>
        </n-card>
      </div>

      <!-- 右侧: 技术详情（选中时显示） -->
      <div v-if="selectedTech" style="width: 45%; display: flex; flex-direction: column; transition: width 0.3s ease;">
        <n-card :bordered="true" size="small" style="background: #171923; flex: 1; overflow-y: auto;">
          <template #header>
            <div style="display: flex; align-items: center; gap: 8px;">
              <n-button size="tiny" quaternary @click="selectedTech = null" style="color: #64748b;">X</n-button>
              <span style="color: #fbbf24; font-size: 15px; font-weight: 700;">{{ selectedTech.id }}</span>
              <span style="color: #e2e8f0; font-size: 14px; font-weight: 600;">{{ selectedTech.name }}</span>
              <div style="flex:1;"></div>
              <n-tag v-if="selectedTech.scores?.risk_level" :type="riskTagType(selectedTech.scores?.risk_level)" size="small" :bordered="false">
                {{ selectedTech.scores?.risk_level }}
              </n-tag>
              <n-tag size="small" :bordered="false">{{ selectedTech.tactic_name }}</n-tag>
            </div>
          </template>

          <div style="margin-bottom: 16px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 6px;">DESCRIPTION</div>
            <div style="color: #cbd5e1; font-size: 13px; line-height: 1.6;">{{ selectedTech.description || '无描述' }}</div>
          </div>

          <div v-if="selectedTech.related_cves && selectedTech.related_cves.length > 0" style="margin-bottom: 16px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 6px;">RELATED CVEs</div>
            <div v-for="cve in selectedTech.related_cves" :key="cve" style="display: flex; align-items: center; gap: 6px; padding: 4px 0;">
              <code style="color: #f87171; font-size: 12px; background: #2a2d38; padding: 2px 6px; border-radius: 3px;">{{ cve }}</code>
              <span style="color: #64748b; font-size: 11px;">-</span>
              <span style="color: #94a3b8; font-size: 11px;">{{ cveCaseMap[cve] || '相关漏洞案例' }}</span>
            </div>
          </div>

          <div style="margin-bottom: 16px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 6px;">DETECTION</div>
            <div v-if="selectedTech.detection" style="background: #0f1117; border-radius: 6px; padding: 10px 14px;">
              <div v-for="d in parseList(selectedTech.detection)" :key="d" style="padding: 3px 0; font-size: 12px; color: #94a3b8; display: flex; gap: 6px;">
                <span style="color: #3b82f6;">-</span><span>{{ d }}</span>
              </div>
            </div>
            <div v-else style="color: #64748b; font-size: 12px;">无检测信息</div>
          </div>

          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 6px;">MITIGATION</div>
            <div v-if="selectedTech.mitigation" style="background: #0f1117; border-radius: 6px; padding: 10px 14px;">
              <div v-for="m in parseList(selectedTech.mitigation)" :key="m" style="padding: 3px 0; font-size: 12px; color: #94a3b8; display: flex; gap: 6px;">
                <span style="color: #22c55e;">-</span><span>{{ m }}</span>
              </div>
            </div>
            <div v-else style="color: #64748b; font-size: 12px;">无缓解措施</div>
          </div>

          <div v-if="selectedTech.sub_techniques && Object.keys(selectedTech.sub_techniques).length > 0" style="margin-top: 16px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 6px;">SUB-TECHNIQUES ({{ Object.keys(selectedTech.sub_techniques).length }})</div>
            <div style="display: flex; flex-wrap: wrap; gap: 6px;">
              <div v-for="(v, k) in selectedTech.sub_techniques" :key="k" style="background: #2a2d38; padding: 4px 10px; border-radius: 4px;">
                <span style="color: #fbbf24; font-size: 11px;">{{ k }}</span>
                <span style="color: #94a3b8; font-size: 11px; margin-left: 4px;">{{ typeof v === 'object' ? v.name : v }}</span>
              </div>
            </div>
          </div>
        </n-card>
      </div>
    </div>

    <!-- OWASP / 合规知识 内容（从真实合规法规数据加载） -->
    <div v-if="activeTab === 'owasp'" style="flex: 1; margin-top: 16px; overflow-y: auto;">
      <n-card :bordered="true" size="small" style="background: #171923;">
        <template #header>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="color: #e2e8f0; font-weight: 600;">合规法规知识库</span>
            <n-tag size="tiny" color="#1e293b" style="color: #94a3b8;">{{ owaspData.length }} 项法规</n-tag>
            <div v-if="complianceLoading" style="color: #64748b; font-size: 11px;">加载中...</div>
          </div>
        </template>
        <div v-if="owaspData.length === 0 && !complianceLoading" style="color: #475569; text-align: center; padding: 40px;">
          无合规法规数据
        </div>
        <div v-for="(item, i) in owaspData" :key="item.id"
          :style="{
            padding: '10px 14px', borderBottom: i < owaspData.length - 1 ? '1px solid #2a2d38' : 'none',
            cursor: 'pointer',
            background: selectedOwasp?.id === item.id ? '#1f2230' : 'transparent',
          }"
          @click="selectedOwasp = selectedOwasp?.id === item.id ? null : item"
        >
          <div style="display: flex; align-items: center; gap: 12px;">
            <div :style="{
              width: '24px', height: '24px', borderRadius: '6px',
              background: (owaspColors[item.id] || '#f97316') + '20',
              color: owaspColors[item.id] || '#f97316',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '12px', fontWeight: 'bold', flexShrink: 0,
            }">{{ i + 1 }}</div>
            <div style="flex: 1;">
              <div style="color: #e2e8f0; font-size: 13px; font-weight: 600;">{{ item.name }}</div>
              <div style="color: #64748b; font-size: 11px; margin-top: 2px;">{{ item.id }}</div>
            </div>
            <div style="color: #64748b; font-size: 11px;">{{ item.risk }}</div>
          </div>
          <!-- 展开详情 -->
          <div v-if="selectedOwasp?.id === item.id" style="margin-top: 10px; padding: 12px; background: #171923; border-radius: 6px; border: 1px solid #2a2d38;">
            <div style="color: #cbd5e1; font-size: 12px; line-height: 1.6; margin-bottom: 10px;">{{ item.description }}</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
              <div>
                <div style="color: #64748b; font-size: 10px; font-weight: 600; margin-bottom: 4px;">合规要求</div>
                <div v-for="p in item.prevention" :key="p" style="color: #94a3b8; font-size: 11px; padding: 2px 0;">- {{ p }}</div>
              </div>
              <div>
                <div style="color: #64748b; font-size: 10px; font-weight: 600; margin-bottom: 4px;">违规处罚</div>
                <div v-for="d in item.detection" :key="d" style="color: #94a3b8; font-size: 11px; padding: 2px 0;">- {{ d }}</div>
              </div>
            </div>
          </div>
        </div>
      </n-card>
    </div>

    <!-- CVE 内容 -->
    <div v-if="activeTab === 'cve'" style="flex: 1; margin-top: 16px; display: flex; gap: 16px; overflow: hidden;">
      <div style="width: 50%; display: flex; flex-direction: column;">
        <n-card :bordered="true" size="small" style="background: #171923; flex: 1;">
          <template #header>
            <div style="display: flex; align-items: center; gap: 8px;">
              <n-input v-model:value="cveQuery" placeholder="搜索 CVE ID, 如 CVE-2025-1234" size="small" clearable style="flex:1;" @keydown.enter="searchCve" />
              <n-button size="small" type="primary" @click="searchCve">搜索</n-button>
            </div>
          </template>
          <div style="overflow-y: auto;">
            <div v-if="cveLoading" style="color: #64748b; text-align: center; padding-top: 40px; font-size: 12px;">加载 {{ allCves.length }} 条 CVE 数据中...</div>
            <div v-else v-for="cve in cveResults" :key="cve.id"
              :style="{
                padding: '8px 12px', cursor: 'pointer', borderRadius: '6px', marginBottom: '4px',
                background: selectedCve?.id === cve.id ? '#1f2230' : 'transparent',
              }"
              @click="selectedCve = cve"
            >
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="color: #f87171; font-size: 13px; font-weight: 600;">{{ cve.id }}</span>
                <n-tag size="tiny" :type="cve.severity === 'CRITICAL' ? 'error' : cve.severity === 'HIGH' ? 'warning' : 'info'" :bordered="false">{{ cve.severity }}</n-tag>
              </div>
              <div style="color: #cbd5e1; font-size: 12px; margin-top: 2px;">{{ cve.title }}</div>
              <div style="color: #64748b; font-size: 11px; margin-top: 2px;">CVSS {{ cve.cvss }} | {{ cve.published }}</div>
            </div>
            <div v-if="cveResults.length === 0 && !cveLoading" style="color: #475569; text-align: center; padding-top: 40px; font-size: 13px;">
              <div>共 {{ allCves.length }} 条 CVE 记录</div>
              <div style="margin-top: 4px; font-size: 11px;">输入 CVE ID 或关键词搜索</div>
            </div>
          </div>
        </n-card>
      </div>
      <div style="width: 50%; display: flex; flex-direction: column;">
        <n-card v-if="selectedCve" :bordered="true" size="small" style="background: #171923; flex: 1; overflow-y: auto;">
          <template #header>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="color: #f87171; font-size: 16px; font-weight: 700;">{{ selectedCve.id }}</span>
              <n-tag :type="selectedCve.severity === 'CRITICAL' ? 'error' : 'warning'" size="small">{{ selectedCve.severity }}</n-tag>
            </div>
          </template>
          <div style="margin-bottom: 12px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">TITLE</div>
            <div style="color: #e2e8f0; font-size: 13px;">{{ selectedCve.title }}</div>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">DESCRIPTION</div>
            <div style="color: #94a3b8; font-size: 12px; line-height: 1.5;">{{ selectedCve.description }}</div>
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
            <div>
              <span style="color: #64748b; font-size: 11px;">CVSS</span>
              <div style="color: #f87171; font-size: 18px; font-weight: 700;">{{ selectedCve.cvss }}</div>
            </div>
            <div>
              <span style="color: #64748b; font-size: 11px;">PUBLISHED</span>
              <div style="color: #94a3b8; font-size: 13px;">{{ selectedCve.published }}</div>
            </div>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">AFFECTED</div>
            <div style="color: #94a3b8; font-size: 12px;">{{ selectedCve.affected }}</div>
          </div>
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">REMEDIATION</div>
            <div style="color: #22c55e; font-size: 12px;">{{ selectedCve.remediation }}</div>
          </div>
        </n-card>
        <n-empty v-else description="选择一个CVE查看详情" style="padding-top: 80px;" />
      </div>
    </div>

    <!-- Detection Rules 内容 -->
    <div v-if="activeTab === 'rules'" style="flex: 1; margin-top: 16px; display: flex; gap: 16px; overflow: hidden;">
      <div style="width: 50%; display: flex; flex-direction: column;">
        <n-card :bordered="true" size="small" style="background: #171923; flex: 1;">
          <template #header>
            <div style="display: flex; align-items: center; gap: 8px;">
              <n-input v-model:value="ruleQuery" placeholder="搜索规则名称或ID" size="small" clearable style="flex:1;" @keydown.enter="searchRules" />
              <n-select v-model:value="ruleFilterType" placeholder="类型" :options="ruleTypeOptions" clearable size="small" style="width: 100px;" />
              <n-button size="small" type="primary" @click="searchRules">搜索</n-button>
            </div>
          </template>
          <div style="overflow-y: auto;">
            <div v-if="rulesLoading" style="color: #64748b; text-align: center; padding-top: 40px; font-size: 12px;">加载 {{ rulesData.length }} 个应急响应剧本...</div>
            <div v-else v-for="rule in filteredRules" :key="rule.id"
              :style="{
                padding: '8px 12px', cursor: 'pointer', borderRadius: '6px', marginBottom: '4px',
                background: selectedRule?.id === rule.id ? '#1f2230' : 'transparent',
              }"
              @click="selectedRule = rule"
            >
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="color: #60a5fa; font-size: 12px; font-weight: 600;">{{ rule.id }}</span>
                <span style="color: #e2e8f0; font-size: 12px;">{{ rule.name }}</span>
                <n-tag :bordered="false" size="tiny" type="info" style="margin-left: auto;">应急响应</n-tag>
              </div>
              <div style="color: #64748b; font-size: 11px; margin-top: 2px;">{{ (rule.indicators || '').substring(0, 80) }}{{ (rule.indicators || '').length > 80 ? '...' : '' }}</div>
            </div>
            <div v-if="filteredRules.length === 0 && !rulesLoading" style="color: #475569; text-align: center; padding-top: 40px; font-size: 13px;">
              <div>共 {{ rulesData.length }} 个应急响应剧本</div>
              <div style="margin-top: 4px; font-size: 11px;">输入关键词搜索场景</div>
            </div>
          </div>
        </n-card>
      </div>
      <div style="width: 50%; display: flex; flex-direction: column;">
        <n-card v-if="selectedRule" :bordered="true" size="small" style="background: #171923; flex: 1; overflow-y: auto;">
          <template #header>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="color: #60a5fa; font-size: 15px; font-weight: 700;">{{ selectedRule.id }}</span>
              <span style="color: #e2e8f0; font-size: 14px; font-weight: 600;">{{ selectedRule.name }}</span>
              <n-tag :bordered="false" size="small" type="info">应急响应剧本</n-tag>
            </div>
          </template>
          <div style="margin-bottom: 12px;">
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">识别指标</div>
            <div style="color: #e2e8f0; font-size: 12px; line-height: 1.5;">{{ selectedRule.indicators }}</div>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="color: #f97316; font-size: 11px; font-weight: 600; margin-bottom: 4px;">立即处置</div>
            <div v-for="action in selectedRule.immediate_actions" :key="action" style="color: #94a3b8; font-size: 12px; padding: 3px 0; display: flex; gap: 6px;">
              <span style="color: #ef4444;">•</span><span>{{ action }}</span>
            </div>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="color: #eab308; font-size: 11px; font-weight: 600; margin-bottom: 4px;">短期措施</div>
            <div v-for="action in selectedRule.medium_term" :key="action" style="color: #94a3b8; font-size: 12px; padding: 3px 0; display: flex; gap: 6px;">
              <span style="color: #eab308;">•</span><span>{{ action }}</span>
            </div>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="color: #22c55e; font-size: 11px; font-weight: 600; margin-bottom: 4px;">长期加固</div>
            <div v-for="action in selectedRule.long_term" :key="action" style="color: #94a3b8; font-size: 12px; padding: 3px 0; display: flex; gap: 6px;">
              <span style="color: #22c55e;">•</span><span>{{ action }}</span>
            </div>
          </div>
          <div>
            <div style="color: #64748b; font-size: 11px; font-weight: 600; margin-bottom: 4px;">完整剧本</div>
            <pre style="background: #0f1117; border: 1px solid #2a2d38; border-radius: 6px; padding: 12px; overflow-x: auto; color: #a5d6ff; font-size: 11px; line-height: 1.5;">{{ selectedRule.content }}</pre>
          </div>
        </n-card>
        <n-empty v-else description="选择一个规则查看详情" style="padding-top: 80px;" />
      </div>
    </div>
  </div>
</template>

<style scoped>
.knowledge-page { padding: 16px; display: flex; flex-direction: column; height: calc(100vh - var(--header-height)); }
.knowledge-tabs { flex-shrink: 0; }
.tab-content { flex: 1; display: flex; gap: 16px; margin-top: 16px; overflow: hidden; }
.mitre-panel { flex: 1; display: flex; flex-direction: column; transition: width 0.3s ease; }
.section-label { font-size: 11px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
.section-body { background: var(--bg-primary); border-radius: var(--radius-sm); padding: 10px 14px; }
.section-text { font-size: 13px; color: var(--text-secondary); line-height: 1.6; }
.list-item { padding: 3px 0; font-size: 12px; color: var(--text-tertiary); display: flex; gap: 6px; }
.cve-tag { font-size: 12px; color: var(--error); background: var(--bg-elevated); padding: 2px 6px; border-radius: 3px; font-family: var(--font-mono); }
.owasp-list, .cve-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; overflow-y: auto; padding: 4px; }
.owasp-card, .cve-card { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); padding: 14px 16px; cursor: pointer; transition: all var(--transition-fast); }
.owasp-card:hover, .cve-card:hover { border-color: var(--border-hover); transform: translateY(-1px); box-shadow: var(--shadow-sm); }
.rules-list { display: flex; flex-direction: column; gap: 10px; overflow-y: auto; padding: 4px; }
.rule-card { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); padding: 14px 16px; cursor: pointer; transition: all var(--transition-fast); }
.rule-card:hover { border-color: var(--border-hover); }
.empty-panel { padding-top: 80px; }

/* ═══ 响应式 KnowledgeView ═══ */
@media (max-width: 768px) {
  .knowledge-page { padding: 8px !important; }
  .tab-content { flex-direction: column !important; gap: 8px !important; }
  .mitre-panel { width: 100% !important; }
  .owasp-list, .cve-grid { grid-template-columns: 1fr !important; }
  .cve-card, .owasp-card { padding: 10px 12px !important; }
}
</style>

<script setup>
import { ref, computed, watch, onMounted, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useMessage } from 'naive-ui'
import * as echarts from 'echarts'

const msg = useMessage()
const route = useRoute()
const router = useRouter()

// 统一 HTTP 客户端（超时 + 错误处理）
import { apiFetch, apiFetchWithLoading } from '../utils/http.js'

// 从路由路径推导 activeTab
const tabFromRoute = computed(() => {
  const p = route.path
  if (p.includes('/knowledge/mitre')) return 'mitre'
  if (p.includes('/knowledge/owasp')) return 'owasp'
  if (p.includes('/knowledge/cve')) return 'cve'
  if (p.includes('/knowledge/rules')) return 'rules'
  return 'mitre'
})
const activeTab = ref(tabFromRoute.value)

// 监听路由变化同步 tab
watch(() => route.path, () => {
  activeTab.value = tabFromRoute.value
  selectedTech.value = null
  selectedOwasp.value = null
  selectedCve.value = null
  selectedRule.value = null
})

// ===== MITRE ATT&CK 热力图矩阵 =====
const selectedTech = ref(null)
const mitreHeatmapRef = ref(null)
let mitreHeatmapInstance = null
const allTechniques = ref([])
const heatmapTactics = ref([])

// KILL CHAIN 顺序 + 中文映射
const mitreTacticsOrder = [
  { id: 'TA0043', eng: 'Reconnaissance', cn: '侦察' },
  { id: 'TA0042', eng: 'Resource Dev.', cn: '资源开发' },
  { id: 'TA0001', eng: 'Initial Access', cn: '初始访问' },
  { id: 'TA0002', eng: 'Execution', cn: '执行' },
  { id: 'TA0003', eng: 'Persistence', cn: '持久化' },
  { id: 'TA0004', eng: 'Privilege Esc.', cn: '权限提升' },
  { id: 'TA0005', eng: 'Defense Evasion', cn: '防御绕过' },
  { id: 'TA0006', eng: 'Credential Access', cn: '凭据访问' },
  { id: 'TA0007', eng: 'Discovery', cn: '发现' },
  { id: 'TA0008', eng: 'Lateral Movement', cn: '横向移动' },
  { id: 'TA0009', eng: 'Collection', cn: '收集' },
  { id: 'TA0011', eng: 'C&C', cn: '命令与控制' },
  { id: 'TA0010', eng: 'Exfiltration', cn: '数据外传' },
  { id: 'TA0040', eng: 'Impact', cn: '影响' },
]

const cveCaseMap = {
  'CVE-2021-44228': 'Log4j RCE - 广泛利用的命令执行漏洞',
  'CVE-2023-34362': 'MOVEit SQL注入 - Clop勒索软件利用',
  'CVE-2024-1708': 'ScreenConnect 认证绕过 - 初始访问',
  'CVE-2022-26134': 'Confluence OGNL注入 - 初始访问',
}

function parseList(text) {
  if (!text) return []
  return text.split(/[；;]\s*/).filter(Boolean)
}

function riskTagType(level) {
  return { '紧急': 'error', '高危': 'warning', '中危': 'info', '低危': 'success' }[level] || 'default'
}

// 获取子技术数量
function countSubTechniques(tech) {
  if (!tech.sub_techniques) return 0
  if (typeof tech.sub_techniques === 'object') return Object.keys(tech.sub_techniques).length
  return 0
}

// 根据子技术数返回颜色等级
function subTechColor(count) {
  if (count === 0) return '#334155'  // 灰色
  if (count <= 5) return '#eab308'   // 黄色
  if (count <= 10) return '#f97316'  // 橙色
  return '#ef4444'                   // 红色
}

// 加载 MITRE 数据并渲染热力图
async function loadMitreHeatmap() {
  try {
    const data = await apiFetch('/api/mitre/search?q=*', { timeout: 10000 })
    if (data.length > 0) {
      allTechniques.value = data
    }
  } catch(e) {
    console.warn('[KnowledgeView] MITRE API 加载失败:', e.message)
  }
  
  // API 无数据时保持空状态，禁止用生成数据伪装为 ATT&CK 知识。
  heatmapTactics.value = mitreTacticsOrder.filter(t =>
    allTechniques.value.some(tech => (tech.tactic_id || tech.tactic) === t.id)
  )
  renderHeatmap()
}

async function selectTechnique(id) {
  try {
    const data = await apiFetch(`/api/mitre/technique/${id}`, { timeout: 8000 })
    selectedTech.value = data
    return
  } catch(e) {
    console.warn(`[KnowledgeView] MITRE 技术 ${id} 查询失败:`, e.message)
  }
  // fallback: use local data
  selectedTech.value = allTechniques.value.find(t => t.id === id) || null
}

function renderHeatmap() {
  if (!mitreHeatmapRef.value) return
  if (!mitreHeatmapInstance) {
    mitreHeatmapInstance = echarts.init(mitreHeatmapRef.value, 'dark')
  }

  const tactics = mitreTacticsOrder
  const techniques = allTechniques.value

  // 按战术分组
  const techByTactic = {}
  for (const t of tactics) {
    // API 返回 tactic_id 字段（兼容旧数据 tech.tactic）
    techByTactic[t.id] = techniques.filter(tech => (tech.tactic_id || tech.tactic) === t.id)
  }

  // Y轴 = 所有技术ID（按战术分组排序）
  const yLabels = []
  const yTacticMarkers = []  // 用于绘制战术分隔线
  for (const t of tactics) {
    const techs = techByTactic[t.id] || []
    if (techs.length === 0) continue
    yTacticMarkers.push({ index: yLabels.length, tactic: t })
    for (const tech of techs) {
      yLabels.push(tech.id + ' ' + tech.name)
    }
  }

  // X轴 = 战术
  const xLabels = tactics.filter(t => (techByTactic[t.id] || []).length > 0).map(t => t.eng)

  // 构建热力图数据
  const heatmapData = []
  let yIdx = 0
  for (const t of tactics) {
    const techs = techByTactic[t.id] || []
    if (techs.length === 0) continue
    const xIdx = xLabels.indexOf(t.eng)
    for (const tech of techs) {
      const subCount = countSubTechniques(tech)
      heatmapData.push([xIdx, yIdx, subCount])
      yIdx++
    }
  }

  // 最大值
  const maxVal = Math.max(1, ...heatmapData.map(d => d[2]))

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      position: 'top',
      formatter: (params) => {
        if (!params.data || !params.data[2]) return ''
        const yIdx = params.data[1]
        const techLabel = yLabels[yIdx] || ''
        const parts = techLabel.split(' ')
        const techId = parts[0] || ''
        const techName = parts.slice(1).join(' ') || ''
        const count = params.data[2]
        return `<div style="font-size: 12px;">
          <div style="color: #fbbf24; font-weight: 700;">${techId}</div>
          <div style="color: #e2e8f0;">${techName}</div>
          <div style="color: #94a3b8; margin-top: 4px;">子技术: <span style="color: #60a5fa; font-weight: 600;">${count}</span></div>
          <div style="margin-top: 4px;"><span style="color: #64748b;">点击查看详情</span></div>
        </div>`
      },
      backgroundColor: '#1a1d29',
      borderColor: '#2a2d38',
      textStyle: { color: '#cbd5e1' },
      extraCssText: 'border-radius: 8px; padding: 8px 12px;',
    },
    grid: {
      left: '120px',
      right: '40px',
      top: '40px',
      bottom: '60px',
    },
    xAxis: {
      type: 'category',
      data: xLabels,
      splitArea: { show: true },
      axisLine: { lineStyle: { color: '#2a2d38' } },
      axisLabel: {
        color: '#94a3b8',
        fontSize: 10,
        fontWeight: 600,
        rotate: xLabels.length > 10 ? 30 : 0,
        interval: 0,
      },
      axisTick: { show: false },
    },
    yAxis: {
      type: 'category',
      data: yLabels,
      splitArea: { show: true },
      axisLine: { lineStyle: { color: '#2a2d38' } },
      axisLabel: {
        color: '#cbd5e1',
        fontSize: 10,
        fontWeight: 500,
        formatter: (v) => v.split(' ')[0],
      },
      axisTick: { show: false },
    },
    visualMap: {
      min: 0,
      max: Math.max(10, maxVal),
      calculable: true,
      orient: 'horizontal',
      left: 'center',
      bottom: 5,
      textStyle: { color: '#94a3b8', fontSize: 10 },
      inRange: {
        color: ['#334155', '#eab308', '#f97316', '#ef4444'],
      },
    },
    series: [{
      type: 'heatmap',
      data: heatmapData,
      label: {
        show: true,
        color: '#e2e8f0',
        fontSize: 11,
        fontWeight: 600,
        formatter: (p) => p.data[2] > 0 ? p.data[2] : '',
      },
      emphasis: {
        itemStyle: {
          shadowBlur: 10,
          shadowColor: 'rgba(0, 0, 0, 0.5)',
        },
      },
    }],
  }

  mitreHeatmapInstance.setOption(option, true)

  // 点击事件
  mitreHeatmapInstance.off('click')
  mitreHeatmapInstance.on('click', (params) => {
    if (!params.data) return
    const yIdx = params.data[1]
    const techLabel = yLabels[yIdx] || ''
    const techId = techLabel.split(' ')[0]
    if (techId) selectTechnique(techId)
  })
}

function handleHeatmapResize() {
  if (mitreHeatmapInstance) mitreHeatmapInstance.resize()
}

// 窗口 resize
if (typeof window !== 'undefined') {
  window.addEventListener('resize', () => {
    if (activeTab.value === 'mitre') handleHeatmapResize()
  })
}

// 监听 tab 切换
watch(activeTab, (tab) => {
  if (tab === 'mitre') {
    setTimeout(loadMitreHeatmap, 100)
  }
})

// 监听 heatmapRef
watch(mitreHeatmapRef, (ref) => {
  if (ref) loadMitreHeatmap()
}, { immediate: true })

// 组件挂载时按当前 tab 主动加载数据。
// 关键修复：/knowledge、/knowledge/mitre、/knowledge/cve 等是多个独立路由
// 指向同一组件，vue-router 切换时组件会重新挂载（state 全部重置），
// 若只在 tab 点击时加载数据，则重新挂载后数据加载丢失 → 页面空白。
// onMounted 保证无论从哪个路由进入，都会加载对应 tab 的数据。
onMounted(() => {
  const tab = tabFromRoute.value
  if (tab === 'mitre') {
    // MITRE 数据由 heatmapRef watch 触发，无需重复加载
  } else if (tab === 'owasp') {
    loadComplianceData()
  } else if (tab === 'cve') {
    loadAllCves()
  } else if (tab === 'rules') {
    loadRulesData()
  }
})

// ===== OWASP / 合规知识 =====
const selectedOwasp = ref(null)
const owaspData = ref([])
const complianceLoading = ref(false)

// OWASP 颜色映射
const owaspColors = {
  'A01': '#ef4444', 'A02': '#f97316', 'A03': '#ef4444',
  'A04': '#f97316', 'A05': '#eab308', 'A06': '#f97316',
  'A07': '#f97316', 'A08': '#eab308', 'A09': '#eab308',
  'A10': '#ef4444',
}

// OWASP Top 10 标准 ID 列表（用于匹配合规法规）
const owaspKeywords = {
  'A01': { name: '访问控制失效', risk: '高危', id: 'A01' },
  'A02': { name: '加密机制失效', risk: '高危', id: 'A02' },
  'A03': { name: '注入攻击', risk: '紧急', id: 'A03' },
  'A04': { name: '不安全设计', risk: '高危', id: 'A04' },
  'A05': { name: '安全配置错误', risk: '中危', id: 'A05' },
  'A06': { name: '易受攻击和过时组件', risk: '高危', id: 'A06' },
  'A07': { name: '身份识别和认证失败', risk: '高危', id: 'A07' },
  'A08': { name: '软件和数据完整性失效', risk: '中危', id: 'A08' },
  'A09': { name: '安全日志和监控不足', risk: '中危', id: 'A09' },
  'A10': { name: '服务端请求伪造', risk: '高危', id: 'A10' },
}

// 从合规 API 加载真实法规数据，映射到 OWASP 标签页展示
async function loadComplianceData() {
  complianceLoading.value = true
  try {
    const regulations = await apiFetch('/api/compliance/search?q=*', { timeout: 8000 })
    // 将法规数据映射到 OWASP 格式展示
    owaspData.value = regulations.map((reg, i) => {
        const idx = i + 1
        const aid = `A${String(idx).padStart(2, '0')}`
        return {
          id: aid,
          name: reg.name,
          risk: '高危',
          color: owaspColors[aid] || '#f97316',
          description: reg.description || '合规法规',
          prevention: reg.key_requirements ? reg.key_requirements.slice(0, 4) : [],
          detection: reg.penalties ? [reg.penalties.substring(0, 60) + '...'] : [],
          raw: reg,
        }
      })
  } catch (e) {
    console.warn('[KnowledgeView] 合规API加载失败，使用内置回退:', e.message)
    // Fallback to built-in OWASP data
    owaspData.value = [
      { id: 'A01', name: '访问控制失效', risk: '高危', color: '#ef4444', description: '未正确实施访问控制导致用户可越权访问未授权的功能或数据', prevention: ['实施最小权限原则', '使用统一访问控制中间件', '拒绝默认访问'], detection: ['权限审计测试', '自动化访问控制扫描'] },
      { id: 'A02', name: '加密机制失效', risk: '高危', color: '#f97316', description: '敏感数据在传输或存储时未正确加密，导致数据泄露', prevention: ['传输层使用TLS 1.3', '存储加密使用AES-256', '密钥轮换管理'], detection: ['数据流审查', '加密强度扫描'] },
      { id: 'A03', name: '注入攻击', risk: '紧急', color: '#ef4444', description: 'SQL、OS命令、LDAP等注入攻击', prevention: ['参数化查询', '输入验证白名单', '最小数据库权限'], detection: ['WAF规则', 'DAST扫描', '代码审计'] },
      { id: 'A04', name: '不安全设计', risk: '高危', color: '#f97316', description: '设计阶段未考虑安全控制，导致架构级安全缺陷', prevention: ['威胁建模', '安全设计模式', '默认安全原则'], detection: ['架构评审', 'STRIDE分析'] },
      { id: 'A05', name: '安全配置错误', risk: '中危', color: '#eab308', description: '默认配置、未修补的漏洞、云存储开放等配置问题', prevention: ['最小化配置', '自动化配置管理', '定期扫描'], detection: ['CIS基准检查', '配置审核'] },
      { id: 'A06', name: '易受攻击和过时组件', risk: '高危', color: '#f97316', description: '使用含有已知漏洞的第三方库和框架', prevention: ['SBOM管理', '自动依赖更新', '漏洞扫描'], detection: ['SCA工具', 'CVE监控'] },
      { id: 'A07', name: '身份识别和认证失败', risk: '高危', color: '#f97316', description: '认证机制薄弱导致账户被盗用', prevention: ['MFA强制', '防范暴力破解', '安全密码策略'], detection: ['登录审计', '异常检测'] },
      { id: 'A08', name: '软件和数据完整性失效', risk: '中危', color: '#eab308', description: 'CI/CD Pipeline不安全、软件供应链攻击', prevention: ['签名验证', '安全CI/CD', '制品完整性检查'], detection: ['完整性监控', '供应链审计'] },
      { id: 'A09', name: '安全日志和监控不足', risk: '中危', color: '#eab308', description: '日志记录不完整或监控缺失导致无法及时发现和响应攻击', prevention: ['全面日志策略', '集中日志管理', 'SIEM集成'], detection: ['日志覆盖率审查', '告警规则测试'] },
      { id: 'A10', name: '服务端请求伪造', risk: '高危', color: '#ef4444', description: '应用从用户获取URL并请求，未对目标进行验证导致SSRF攻击', prevention: ['URL白名单', '内网隔离', '协议限制'], detection: ['动态扫描', '代码审查'] },
    ]
  } finally {
    complianceLoading.value = false
  }
}

// ===== CVE 漏洞库 (76 条真实 CVE 数据) =====
const cveQuery = ref('')
const cveResults = ref([])
const selectedCve = ref(null)
const cveLoading = ref(false)
const allCves = ref([])

async function loadAllCves() {
  cveLoading.value = true
  try {
    const data = await apiFetch('/api/cve/search?q=*', { timeout: 10000 })
    // 将后端格式映射到前端展示格式
    allCves.value = data.map(c => ({
        id: c.id || c.cve_id,
        severity: c.severity || 'UNKNOWN',
        cvss: c.cvss_score || 'N/A',
        title: (c.description || '').substring(0, 80),
        description: c.description || '',
        published: c.published || 'N/A',
        affected: c.affected || 'N/A',
        remediation: c.remediation || '暂无修复方案',
        detection: c.detection || '',
        impact: c.impact || '',
        cwe_ids: c.cwe_ids || [],
        mitre_techniques: c.mitre_techniques || [],
      }))
    cveResults.value = allCves.value.slice(0, 20)
  } catch (e) {
    console.warn('[KnowledgeView] CVE API加载失败:', e.message)
    cveResults.value = []
  } finally {
    cveLoading.value = false
  }
}

async function searchCve() {
  const q = cveQuery.value.trim().toLowerCase()
  if (!q) {
    cveResults.value = allCves.value.slice(0, 20)
    selectedCve.value = null
    return
  }
  try {
    const data = await apiFetch(`/api/cve/search?q=${encodeURIComponent(q)}`, { timeout: 8000 })
    cveResults.value = (data || []).map(c => ({
        id: c.id || c.cve_id,
        severity: c.severity || 'UNKNOWN',
        cvss: c.cvss_score || 'N/A',
        title: (c.description || '').substring(0, 80),
        description: c.description || '',
        published: c.published || 'N/A',
        affected: c.affected || 'N/A',
        remediation: c.remediation || '暂无修复方案',
        detection: c.detection || '',
        impact: c.impact || '',
        cwe_ids: c.cwe_ids || [],
        mitre_techniques: c.mitre_techniques || [],
      }))
  } catch (e) {
    console.warn('[KnowledgeView] CVE搜索失败，使用本地回退:', e.message)
    // local filter fallback
    cveResults.value = allCves.value.filter(c =>
      c.id.toLowerCase().includes(q) ||
      c.title.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q)
    )
  }
  selectedCve.value = cveResults.value[0] || null
}

// ===== Detection Rules / 应急响应剧本 (23 个真实场景) =====
const ruleQuery = ref('')
const ruleFilterType = ref(null)
const selectedRule = ref(null)
const rulesData = ref([])
const rulesLoading = ref(false)

const ruleTypeOptions = [
  { label: '应急响应', value: '应急响应' },
  { label: '供应链安全', value: '供应链' },
  { label: '云安全', value: '云安全' },
]

async function loadRulesData() {
  rulesLoading.value = true
  try {
    const data = await apiFetch('/api/remediation/search?q=*', { timeout: 8000 })
    rulesData.value = (data || []).map((r, i) => ({
        id: `PB-${String(i + 1).padStart(3, '0')}`,
        name: r.scenario || '未知场景',
        type: '应急响应',
        technique: r.scenario || '',
        description: `响应场景: ${r.scenario}\n识别指标: ${(r.indicators || '').substring(0, 80)}`,
        content: formatPlaybookContent(r),
        reference: r.scenario || '',
        indicators: r.indicators || '',
        immediate_actions: r.immediate_actions || [],
        medium_term: r.medium_term || [],
        long_term: r.long_term || [],
      }))
  } catch (e) {
    console.warn('[KnowledgeView] 应急剧本API加载失败:', e.message)
    rulesData.value = []
  } finally {
    rulesLoading.value = false
  }
}

function formatPlaybookContent(playbook) {
  let content = `# 应急响应剧本: ${playbook.scenario || '未知'}\n\n`
  content += `## 识别指标\n${playbook.indicators || '无'}\n\n`
  content += `## 立即处置\n`
  for (const action of (playbook.immediate_actions || [])) {
    content += `  - ${action}\n`
  }
  content += `\n## 短期措施\n`
  for (const action of (playbook.medium_term || [])) {
    content += `  - ${action}\n`
  }
  content += `\n## 长期措施\n`
  for (const action of (playbook.long_term || [])) {
    content += `  - ${action}\n`
  }
  return content
}

const filteredRules = computed(() => {
  let result = rulesData.value
  if (ruleQuery.value.trim()) {
    const q = ruleQuery.value.trim().toLowerCase()
    result = result.filter(r =>
      r.name.toLowerCase().includes(q) ||
      r.id.toLowerCase().includes(q)
    )
  }
  return result
})

function searchRules() {
  // computed 自动处理
}

function onTabChange(tab) {
  selectedTech.value = null
  selectedOwasp.value = null
  selectedCve.value = null
  selectedRule.value = null
  const pathMap = { mitre: '/knowledge/mitre', owasp: '/knowledge/owasp', cve: '/knowledge/cve', rules: '/knowledge/rules' }
  const target = pathMap[tab]
  if (target && route.path !== target) {
    router.push(target)
  }
  // 按需加载数据
  if (tab === 'cve' && allCves.value.length === 0) {
    loadAllCves()
  }
  if (tab === 'rules' && rulesData.value.length === 0) {
    loadRulesData()
  }
  if (tab === 'owasp' && owaspData.value.length === 0) {
    loadComplianceData()
  }
}
</script>
