<template>
  <div class="chat-view">
    <!-- 会话侧边栏 -->
    <div class="conv-sidebar">
      <button class="new-conv-btn" @click="handleNewConversation">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        新建对话
      </button>
      <div class="conv-list">
        <div v-if="chatStore.convLoading" class="conv-loading">加载中...</div>
        <template v-else>
          <div
            v-for="c in chatStore.conversations"
            :key="c.conversation_id"
            class="conv-item"
            :class="{ active: c.conversation_id === chatStore.currentConversationId }"
            @click="handleResumeConversation(c.conversation_id)"
            :title="c.title"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
            <span class="conv-title">{{ c.title || c.conversation_id }}</span>
          </div>
          <div v-if="chatStore.conversations.length === 0" class="conv-empty">暂无历史对话</div>
        </template>
      </div>
    </div>

    <!-- 右侧主区域（消息 + 输入） -->
    <div class="chat-main">
    <!-- 消息容器 -->
    <div ref="msgContainer" class="msg-list">
      <!-- 空状态 -->
      <div v-if="chatStore.messages.length === 0" class="empty-state">
        <div class="empty-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            <line x1="9" y1="10" x2="15" y2="10"/><line x1="12" y1="7" x2="12" y2="13"/>
          </svg>
        </div>
        <div class="empty-title">SecAgentX</div>
        <div class="empty-subtitle">多智能体协同 · Agentic-RAG · 多厂商模型兼容</div>
        <div class="quick-replies">
          <button class="quick-btn" @click="sendQuick('查询 T1566.001 的防御措施')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            T1566.001 防御
          </button>
          <button class="quick-btn" @click="sendQuick('调查 IP 45.33.32.156')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><line x1="21.93" y1="12" x2="2.07" y2="12"/>
            </svg>
            调查 IP
          </button>
          <button class="quick-btn" @click="sendQuick('分析 SSH 暴力破解告警')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            分析告警
          </button>
          <button class="quick-btn" @click="sendQuick('非工作时间内部用户大量外传数据，分析是否内部威胁')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
            </svg>
            内部威胁分析
          </button>
        </div>
      </div>

      <!-- 消息列表 -->
      <div v-for="msg in chatStore.messages" :key="msg.id" class="msg-item" :class="'role-' + msg.role">
        <!-- 用户消息 -->
        <div v-if="msg.role === 'user'" class="msg-user">
          <div class="msg-bubble user-bubble">
            <div class="bubble-avatar user-avatar">{{ userInitial }}</div>
            <div class="bubble-content" v-html="renderMarkdown(msg.content)" />
          </div>
        </div>

        <!-- Agent消息 -->
        <div v-else-if="msg.role === 'agent'" class="msg-agent">
          <div class="msg-bubble agent-bubble">
            <div class="bubble-avatar agent-avatar">AI</div>
            <div class="bubble-content agent-text" v-html="renderMarkdown(msg.content)" />
          </div>
        </div>

        <!-- Agent状态卡片 -->
        <div v-else-if="msg.role === 'agent_status_card'" class="msg-agent">
          <div class="status-card" :class="'status-' + (msg.content.status || '').toLowerCase()">
            <div class="status-dot" :class="statusClass(msg.content.status)" />
            <div class="status-info">
              <span class="status-name">{{ msg.content.agentName || msg.content.agentId }}</span>
              <span class="status-label" :class="'label-' + (msg.content.status || '').toLowerCase()">{{ msg.content.status }}</span>
            </div>
            <div class="status-metrics">
              <span v-if="msg.content.durationMs > 0" class="metric-item">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                {{ msg.content.durationMs.toFixed(0) }}ms
              </span>
              <span v-if="msg.content.tokens > 0" class="metric-item">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/></svg>
                {{ msg.content.tokens }} tok
              </span>
            </div>
            <div class="status-result">
              <span v-if="msg.content.status === 'Completed'" class="result-pass">Success</span>
              <span v-else-if="msg.content.status === 'Failed'" class="result-fail">Failed</span>
              <span v-else class="result-pending">Pending</span>
            </div>
          </div>
        </div>

        <!-- Agent启动中 -->
        <div v-else-if="msg.role === 'agent_start'" class="msg-agent">
          <div class="status-card status-pending">
            <div class="status-spinner" />
            <span class="status-name">{{ msg.agentName }} 正在处理...</span>
          </div>
        </div>

        <!-- CoT思维链 - 开始 -->
        <div v-else-if="msg.role === 'cot_start'" class="msg-agent">
          <div class="cot-card cot-start">
            <div class="cot-header">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
              <span>Threat Assessment</span>
            </div>
            <div class="cot-body" v-html="renderMarkdown(msg.content)" />
          </div>
        </div>

        <!-- 推理链 -->
        <div v-else-if="msg.role === 'reasoning_chain'" class="msg-agent">
          <div class="chain-list">
            <div v-for="(step, si) in msg.content.steps" :key="step.type" class="chain-step" :class="'step-' + step.status">
              <div class="step-node">
                <div class="step-indicator" :class="'indicator-' + step.status">
                  <svg v-if="step.status === 'completed'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  <svg v-else-if="step.status === 'running'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  <span v-else class="step-num">{{ si + 1 }}</span>
                </div>
                <div class="step-body">
                  <div class="step-title">{{ step.label }}</div>
                  <div v-if="step.output" class="step-output">{{ step.output }}</div>
                </div>
                <span class="step-badge" :class="'badge-' + step.status">
                  {{ step.status === 'running' ? 'RUNNING' : step.status === 'completed' ? 'DONE' : 'PENDING' }}
                </span>
              </div>
            </div>
          </div>
        </div>

        <!-- Reasoner 综合推理 -->
        <div v-else-if="msg.role === 'reasoner_complete'" class="msg-agent">
          <div class="reasoner-card">
            <div class="reasoner-header">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
              <span>Source</span>
              <span v-if="msg.content.winner" class="winner-tag" :class="'winner-' + (msg.content.confidence >= 0.7 ? 'high' : msg.content.confidence >= 0.4 ? 'mid' : 'low')">
                {{ msg.content.winner.title }} · {{ (msg.content.confidence * 100).toFixed(0) }}%
              </span>
            </div>
            <div class="reasoner-body" v-html="renderMarkdown(msg.content.content || '')" />
            <!-- 可视化区 -->
            <div v-if="hasVisualizationData(msg.content)" class="viz-grid">
              <div v-if="msg.content.evidenceMatrix && msg.content.evidenceMatrix.length > 0" class="viz-card">
                <div class="viz-title">EVIDENCE MATRIX</div>
                <table class="viz-table">
                  <thead><tr><th>Evidence</th><th v-for="h in hypothesisHeaders(msg.content)" :key="h">{{ h }}</th></tr></thead>
                  <tbody>
                    <tr v-for="(ev, ei) in msg.content.evidenceMatrix.slice(0, 5)" :key="ei">
                      <td class="ev-cell">{{ ev.content }}</td>
                      <td v-for="h in hypothesisHeaders(msg.content)" :key="h" class="val-cell">
                        <span v-if="ev[h] !== undefined" :style="{ color: matrixColor(ev[h]) }">{{ typeof ev[h] === 'number' ? ev[h].toFixed(1) : ev[h] }}</span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div class="viz-side">
                <div v-if="msg.content.bayesianHistory && msg.content.bayesianHistory.length > 0" class="viz-card">
                  <div class="viz-title">BAYESIAN UPDATE</div>
                  <div v-for="h in msg.content.bayesianHistory" :key="h.id" class="bayes-item">
                    <div class="bayes-label"><span class="bayes-id">{{ h.id }}</span>{{ h.title }}</div>
                    <div class="bar-row"><span class="bar-label">Prior</span><div class="bar-track"><div class="bar-fill" :style="{ width: Math.max(1, h.prior * 100) + '%' }"></div></div><span class="bar-val">{{ (h.prior * 100).toFixed(0) }}%</span></div>
                    <div class="bar-row"><span class="bar-label">Post</span><div class="bar-track"><div class="bar-fill" :class="h.posterior > h.prior ? 'bar-up' : 'bar-down'" :style="{ width: Math.max(1, h.posterior * 100) + '%' }"></div></div><span class="bar-val" :class="h.posterior > h.prior ? 'text-up' : 'text-down'">{{ (h.posterior * 100).toFixed(0) }}%</span></div>
                  </div>
                </div>
                <div v-if="msg.content.agentDurations && msg.content.agentDurations.length > 0" class="viz-card">
                  <div class="viz-title">AGENT DURATION</div>
                  <div v-for="ad in msg.content.agentDurations" :key="ad.name" class="dur-row">
                    <span class="dur-name">{{ ad.name }}</span>
                    <div class="dur-track"><div class="dur-fill" :style="{ width: agentBarWidth(ad, msg.content.agentDurations), background: agentBarColor(ad.name) }"></div></div>
                    <span class="dur-val">{{ ad.duration_ms.toFixed(0) }}ms</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- CoT单步推理 -->
        <div v-else-if="msg.role === 'cot_step'" class="msg-agent">
          <div class="cot-card cot-step">
            <div class="cot-header"><span>Step {{ msg.content.stepNumber }}/{{ msg.content.totalSteps }}: {{ msg.content.title }}</span><span class="conf-badge">{{ (msg.content.confidence * 100).toFixed(0) }}%</span></div>
            <div class="cot-body">
              <div v-if="msg.content.analysis" class="cot-section">
                <div class="cot-section-title">Knowledge</div>
                <div class="cot-section-body" v-html="renderMarkdown(msg.content.analysis)" />
              </div>
              <div v-if="msg.content.conclusion" class="cot-section">
                <div class="cot-section-title">Conclusion</div>
                <div class="cot-section-body conclusion-body" v-html="renderMarkdown(msg.content.conclusion)" />
              </div>
              <div v-if="msg.content.evidence && msg.content.evidence.length > 0" class="cot-section">
                <div class="cot-section-title">Evidence</div>
                <div v-for="(ev, i) in msg.content.evidence" :key="i" class="ev-item" v-html="renderMarkdown(ev)" />
              </div>
              <div v-if="msg.content.nextQuestion" class="cot-next">Next Step: {{ msg.content.nextQuestion }}</div>
            </div>
          </div>
        </div>

        <!-- CoT完成 -->
        <div v-else-if="msg.role === 'cot_complete'" class="msg-agent">
          <div class="cot-card cot-complete">
            <div class="cot-header">Conclusion</div>
            <div class="cot-body" v-html="renderMarkdown(msg.content)" />
          </div>
        </div>

        <!-- 分析结果 -->
        <div v-else-if="msg.role === 'analysis_result'" class="msg-agent">
          <div class="analysis-card">
            <div class="analysis-header">Intent Analysis</div>
            <div class="analysis-grid">
              <div class="analysis-cell"><span class="cell-label">INTENT</span><span class="cell-value">{{ msg.content.intent }}</span></div>
              <div class="analysis-cell"><span class="cell-label">RISK</span><span class="cell-value" :style="{ color: severityColor(msg.content.severity) }">{{ msg.content.severity }}</span></div>
              <div class="analysis-cell"><span class="cell-label">CONFIDENCE</span><span class="cell-value">{{ (msg.content.confidence * 100).toFixed(0) }}%</span></div>
              <div class="analysis-cell"><span class="cell-label">SOURCE</span><span class="cell-value">{{ msg.content.source }}</span></div>
              <div class="analysis-cell"><span class="cell-label">EVIDENCE</span><span class="cell-value">{{ msg.content.evidenceCount }}</span></div>
            </div>
          </div>
        </div>

        <!-- 结构化最终结果卡片 (v2.5: 安全事件分析 / 核心发现 / 推荐动作 / 详细分析折叠 / 报告模式 / 事件模板) -->
        <div v-else-if="msg.role === 'structured_result'" class="msg-agent">
          <div class="sr-card" :class="'tpl-' + srTemplateType(msg.content)">
            <!-- 头部：安全事件分析 + 报告模式切换 -->
            <div class="sr-header">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
              <span class="sr-title">安全事件分析</span>
              <span class="sr-tpl-tag">{{ srTemplateTitle(srTemplateType(msg.content)) }}</span>
              <span class="sr-status">{{ srStatusLabel(msg.content.status) }}</span>
              <span class="sr-mode-switch">
                <button class="mode-btn" :class="{ 'mode-active': reportMode(msg.id) === 'quick' }" @click="setReportMode(msg.id, 'quick')">快速分析</button>
                <button class="mode-btn" :class="{ 'mode-active': reportMode(msg.id) === 'expert' }" @click="setReportMode(msg.id, 'expert')">专家报告</button>
              </span>
            </div>

            <!-- 总体判定（v2.6: 风险概率 与 置信度 分离显示） -->
            <div class="sr-main">
              <span class="sr-score" :class="riskScoreClass(msg.content.score)">{{ msg.content.score }}</span>
              <span class="sr-label">风险评分</span>
              <span class="sr-decision" :class="confVerdictClass(srVerdict(msg.content))">{{ srVerdict(msg.content) }}</span>
              <span v-if="msg.content.needs_human" class="sr-human">需人工介入</span>
              <span v-if="srVerdict(msg.content) === 'unknown'" class="sr-unknown-hint">证据不足/冲突，置信度不作高估</span>
            </div>
            <div class="sr-meta">
              <span class="sr-meta-item">风险概率 <strong :class="riskProbClass(srRiskProbability(msg.content))">{{ srRiskProbability(msg.content) }}</strong></span>
              <span class="sr-meta-item">置信度 <strong>{{ srConfidence(msg.content) }}</strong></span>
              <span class="sr-meta-item">风险等级 <strong :style="{ color: severityColor(srRiskLevel(msg.content)) }">{{ srRiskLevel(msg.content) }}</strong></span>
              <span class="sr-meta-item">轮次 <strong>{{ msg.content.rounds || 0 }}</strong></span>
            </div>

            <!-- 风险摘要（Summary Agent, v2.5） -->
            <div v-if="srRiskSummary(msg.content)" class="sr-summary" v-html="renderMarkdown(srRiskSummary(msg.content))" />

            <!-- 核心发现 -->
            <div v-if="srCoreFindings(msg.content).length" class="sr-section">
              <div class="sr-section-title">核心发现</div>
              <div v-for="(f, fi) in srCoreFindings(msg.content)" :key="'cf' + fi" class="sr-finding">
                <span class="sr-finding-dot" />
                <span class="sr-finding-text">{{ f }}</span>
              </div>
            </div>

            <!-- 推荐动作 -->
            <div v-if="srRecommendedActions(msg.content).length" class="sr-section">
              <div class="sr-section-title">推荐动作</div>
              <div v-for="(a, ai) in srRecommendedActions(msg.content)" :key="'ra' + ai" class="sr-action">
                <span class="sr-action-num">{{ ai + 1 }}</span>
                <span class="sr-action-text">{{ a }}</span>
              </div>
            </div>

            <!-- 证据链（v2.6: 为什么 / 依据 / 调用了什么工具） -->
            <div v-if="srEvidenceChain(msg.content).length" class="sr-section">
              <div class="sr-section-title">证据链</div>
              <div v-for="(ec, ei) in srEvidenceChain(msg.content)" :key="'ec' + ei" class="ec-item" :class="'agent-verdict-' + (ec.verdict || 'unknown')">
                <div class="ec-head">
                  <span class="ec-agent">{{ ec.agent_name || ec.agent_id }}</span>
                  <span class="ec-verdict">{{ ec.verdict }}</span>
                  <span v-if="ec.confidence != null" class="ec-conf">{{ (ec.confidence * 100).toFixed(0) }}%</span>
                </div>
                <div v-if="ec.evidence" class="ec-row">
                  <span class="ec-label">结论</span><span class="ec-val">{{ ec.evidence }}</span>
                </div>
                <div v-if="ec.basis" class="ec-row">
                  <span class="ec-label">依据</span><span class="ec-val">{{ ec.basis }}</span>
                </div>
                <div v-if="ec.tools && ec.tools.length" class="ec-row">
                  <span class="ec-label">工具</span>
                  <span class="ec-tools">
                    <code v-for="(tk, ti) in ec.tools" :key="ti" class="ec-tool">{{ tk }}</code>
                  </span>
                </div>
              </div>
            </div>

            <!-- 模板化表格（第六步：按事件模板分类展示） -->
            <div v-if="srTemplateTable(msg.content).length" class="sr-section">
              <div class="sr-section-title">{{ srTemplateTableTitle(srTemplateType(msg.content)) }}</div>
              <table class="sr-table">
                <thead>
                  <tr><th v-for="h in srTableHeaders(msg.content)" :key="h">{{ h }}</th></tr>
                </thead>
                <tbody>
                  <tr v-for="(row, ri) in srTemplateTable(msg.content)" :key="ri">
                    <td v-for="h in srTableHeaders(msg.content)" :key="h">{{ row[h] }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- 详细分析（折叠，点击后显示） -->
            <details class="sr-detail" :open="reportMode(msg.id) === 'expert'">
              <summary class="sr-detail-summary">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                详细分析
              </summary>
              <div class="sr-detail-body" v-html="renderMarkdown(srDetail(msg.content))" />
            </details>

            <!-- 专家报告模式：额外明细 -->
            <template v-if="reportMode(msg.id) === 'expert'">
              <!-- 各 Agent 明细 -->
              <div v-if="(msg.content.agent_results || []).length" class="sr-agents">
                <div class="sr-section-title">参与分析 Agent</div>
                <div v-for="a in msg.content.agent_results" :key="(a.agent_id || Math.random())" class="sr-agent" :class="'agent-verdict-' + (a.verdict || 'unknown')">
                  <span class="sr-agent-name">{{ a.agent_name || a.agent_id }}</span>
                  <span class="sr-agent-verdict">{{ a.verdict }}</span>
                  <span class="sr-agent-conf">{{ a.confidence !== null && a.confidence !== undefined ? (a.confidence * 100).toFixed(0) + '%' : '—' }}</span>
                  <span v-if="a.risk_summary" class="sr-agent-summary">{{ a.risk_summary }}</span>
                  <span v-if="a.degraded" class="conf-tag tag-degraded">已降级</span>
                  <span v-else-if="a.status === 'failed'" class="conf-tag tag-failed">失败</span>
                </div>
              </div>
              <!-- 决策依据链（Decision Fusion, v2.4） -->
              <div v-if="(msg.content.decision_path || []).length" class="sr-path">
                <div class="sr-path-title">决策依据链</div>
                <div v-for="p in msg.content.decision_path" :key="'dp-' + p.step" class="sr-path-step" :class="'path-tag-' + (p.tag || '')">
                  <span class="sr-path-num">{{ p.step }}</span>
                  <span class="sr-path-desc">{{ p.desc }}</span>
                </div>
                <!-- 证据冲突 -->
                <div v-if="(msg.content.fusion_result?.conflicts || []).length" class="sr-path-conflicts">
                  <div v-for="(c, ci) in msg.content.fusion_result.conflicts" :key="'cf-' + ci" class="sr-conflict">
                    {{ c.between }} 冲突系数 {{ (c.coefficient * 100).toFixed(0) }}% — {{ c.resolution }}
                  </div>
                </div>
              </div>
              <!-- 原始完整报告 -->
              <div v-if="msg.content.summary_text" class="sr-full">
                <div class="sr-section-title">完整分析</div>
                <div class="sr-full-body" v-html="renderMarkdown(msg.content.summary_text)" />
              </div>
            </template>
          </div>
        </div>

        <!-- TrueReAct 过程时间线（工具调用/Agent 路由/失败修正） -->
        <div v-else-if="msg.role === 'trace_panel'" class="msg-agent">
          <details class="trace-card" :open="false">
            <summary class="trace-header">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>
              <span class="trace-title">多智能体执行过程</span>
              <span class="trace-badge">{{ traceCount(msg.content) }} 项操作</span>
            </summary>
            <div class="trace-body">
              <div v-for="r in msg.content.rounds" :key="'r' + r.round" class="trace-round">
                <div class="trace-round-title">第 {{ r.round }} 轮</div>
                <div v-for="(it, ii) in r.items" :key="ii" class="trace-item" :class="'t-' + it.type">
                  <span class="t-badge">{{ traceBadge(it) }}</span>
                  <div class="t-content">
                    <template v-if="it.type === 'think'">
                      <div class="t-think" v-html="renderMarkdown(it.text)" />
                    </template>
                    <template v-else-if="it.type === 'act' || it.type === 'observe' || it.type === 'agent_route' || it.type === 'round_complete'">
                      <span class="t-line">{{ it.text }}</span>
                    </template>
                    <template v-else-if="it.type === 'tool_call'">
                      <span class="t-name">调用工具 <code>{{ it.tool }}</code></span>
                      <pre v-if="hasKeys(it.args)" class="t-args">{{ formatArgs(it.args) }}</pre>
                    </template>
                    <template v-else-if="it.type === 'tool_result'">
                      <span class="t-name" :class="it.success ? 't-ok' : 't-err'">{{ it.success ? '[OK]' : '[FAIL]' }} <code>{{ it.tool }}</code></span>
                      <pre v-if="it.preview" class="t-args">{{ it.preview }}</pre>
                    </template>
                    <template v-else-if="it.type === 'agent_dispatch'">
                      <span class="t-name">路由 <code>{{ it.agentId }}</code> 分析</span>
                      <div v-if="it.task" class="t-task">&gt; {{ it.task }}</div>
                    </template>
                    <template v-else-if="it.type === 'agent_result'">
                      <span class="t-name"><code>{{ it.agentId }}</code> 完成</span>
                      <span v-if="it.verdict" class="t-meta t-verdict" :class="'v-' + it.verdict">裁决 {{ it.verdict }}</span>
                      <span v-if="it.confidence != null" class="t-meta">置信度 {{ (it.confidence * 100).toFixed(0) }}%</span>
                    </template>
                    <template v-else-if="it.type === 'agent_error'">
                      <span class="t-name t-err">✗ <code>{{ it.agentId }}</code> 分析失败</span>
                    </template>
                    <template v-else-if="it.type === 'route_correction'">
                      <span class="t-name t-warn">路由修正 <code>{{ it.from }}</code> → <code>{{ it.to }}</code></span>
                      <div v-if="it.reason" class="t-task">原因: {{ it.reason }}</div>
                    </template>
                  </div>
                </div>
              </div>
            </div>
          </details>
        </div>

        <!-- 确定性置信度裁决卡片 (v2.2.2) -->
        <div v-else-if="msg.role === 'confidence_card'" class="msg-agent">
          <div class="confidence-card">
            <div class="conf-header">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 L15.09 8.26 L22 9.27 L17 14.14 L18.18 21.02 L12 17.77 L5.82 21.02 L7 14.14 L2 9.27 L8.91 8.26 Z"/></svg>
              <span class="conf-title">确定性置信度裁决（可复现）</span>
            </div>
            <div class="conf-main">
              <span class="conf-value" :class="confLevelClass(msg.content.confidence)">{{ (msg.content.confidence * 100).toFixed(0) }}%</span>
              <span class="conf-verdict" :class="confVerdictClass(msg.content.verdict)">{{ msg.content.verdict }}</span>
              <span v-if="msg.content.needs_human" class="conf-human">需人工介入</span>
            </div>
            <div class="conf-details">
              <div v-for="d in (msg.content.details || [])" :key="d.agent_id" class="conf-row">
                <span class="conf-agent">{{ d.agent_id }}</span>
                <span class="conf-weight">{{ (d.weight * 100).toFixed(0) }}%</span>
                <span class="conf-bar"><i :style="{ width: (d.weight * 100) + '%' }" /></span>
                <span class="conf-agent-conf">{{ d.confidence !== null ? (d.confidence * 100).toFixed(0) + '%' : '—' }}</span>
                <span v-if="d.degraded" class="conf-tag tag-degraded">已降级</span>
                <span v-else-if="d.failed" class="conf-tag tag-failed">失败</span>
              </div>
            </div>
            <div v-if="msg.content.coverage !== null && msg.content.coverage !== undefined" class="conf-coverage">
              情报覆盖度 <strong>{{ (msg.content.coverage * 100).toFixed(0) }}%</strong>
              <span v-if="msg.content.coverage < 1">（缺失源按"未知"处理，不视为无恶意）</span>
            </div>
          </div>
        </div>

        <!-- 可解释风险评分卡 (v2.3) -->
        <div v-else-if="msg.role === 'risk_card'" class="msg-agent">
          <div class="risk-card">
            <div class="risk-header">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9V3 M12 21v-6 M5.6 6.2l4.2 4.2 M14.2 13.6l4.2 4.2 M3 12h6 M15 12h6"/><circle cx="12" cy="12" r="2"/></svg>
              <span class="risk-title">可解释风险评分</span>
              <span class="risk-level" :class="riskLevelClass(msg.content.risk_level)">{{ msg.content.risk_level }}</span>
            </div>
            <div class="risk-main">
              <span class="risk-score" :class="riskScoreClass(msg.content.risk_score)">{{ msg.content.risk_score }}</span>
              <span class="risk-label">最终风险评分</span>
              <span v-if="msg.content.needs_human" class="risk-human">需人工复核</span>
            </div>
            <div class="risk-dims">
              <div v-for="d in (msg.content.dimensions || [])" :key="d.name" class="risk-dim" :class="'risk-tag-' + (d.tag || 'neutral')">
                <span class="risk-dim-name">{{ d.name }}</span>
                <span class="risk-dim-delta" :class="d.delta > 0 ? 'delta-pos' : d.delta < 0 ? 'delta-neg' : 'delta-zero'">
                  {{ d.delta > 0 ? '+' : '' }}{{ d.delta }}
                </span>
                <span class="risk-dim-reason">{{ d.reason }}</span>
              </div>
            </div>
            <div class="risk-footer">
              <span>{{ msg.content.summarized }}</span>
              <span class="risk-rules" v-if="(msg.content.rules_hit || []).length">规则: {{ msg.content.rules_hit.join(' / ') }}</span>
            </div>
          </div>
        </div>

        <!-- 系统消息 -->
        <div v-else class="msg-system">
          <span class="sys-text">{{ typeof msg.content === 'string' ? msg.content : (msg.content?.content || '') }}</span>
        </div>

        <button
          v-if="isCopyable(msg)"
          class="copy-message-btn"
          :class="{ copied: copiedMessageId === msg.id }"
          type="button"
          :aria-label="copiedMessageId === msg.id ? '已复制' : '复制结果'"
          @click="copyMessage(msg)"
        >
          {{ copiedMessageId === msg.id ? '已复制' : '复制' }}
        </button>
      </div>

      <!-- 处理中指示 -->
      <div v-if="chatStore.isProcessing" class="processing-bar">
        <div class="processing-dots"><span /><span /><span /></div>
        <span>多智能体协同分析中...</span>
      </div>
    </div>

    <!-- 连接状态栏 -->
    <div class="ws-status-bar" :class="'ws-' + wsStatus">
      <span class="ws-dot" />
      <span class="ws-label">{{ wsStatusText }}</span>
      <span class="ws-boundary">本机控制台 · 无登录 · 仅本机访问</span>
    </div>

    <!-- 输入区域 -->
    <div class="input-bar">
      <div class="input-wrapper">
        <textarea
          ref="inputRef"
          v-model="inputText"
          class="chat-input"
          placeholder="输入安全问题；Enter 发送，Shift + Enter 换行"
          :disabled="chatStore.isProcessing"
          rows="1"
          @keydown.enter.exact.prevent="sendMessage"
        />
        <button
          class="send-btn"
          :class="{ active: inputText.trim() }"
          :disabled="!inputText.trim() || chatStore.isProcessing"
          @click="sendMessage"
        >
          <svg v-if="!chatStore.isProcessing" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
          </svg>
          <div v-else class="send-spinner" />
        </button>
      </div>
      <div class="input-hint">分析结果仅供辅助研判；涉及封禁、隔离等动作前请先人工确认。</div>
    </div>
    </div><!-- /chat-main -->
  </div>
</template>

<script setup>
import { ref, reactive, computed, nextTick, watch, onMounted } from 'vue'
import { useChatStore } from '../stores/chat.js'
import { marked } from 'marked'

// 配置 marked 安全选项
marked.setOptions({
  breaks: true,
  gfm: true,
})

const chatStore = useChatStore()
const inputText = ref('')
const msgContainer = ref(null)
const inputRef = ref(null)
const copiedMessageId = ref('')

// ─── 会话管理（新建 / 恢复历史） ───
function handleNewConversation() {
  chatStore.newConversation()
}
function handleResumeConversation(convId) {
  chatStore.resumeConversation(convId)
}

// 挂载时加载历史会话列表
onMounted(() => {
  chatStore.fetchConversations()
})

// 本机控制台不维护账户资料；使用固定标识，避免遗留旧登录态。
const userInitial = '本'

// ─── 连接状态（来自 store 的统一 WebSocket） ───
const wsStatus = computed(() =>
  chatStore.wsConnected ? 'connected' : 'disconnected'
)
const wsStatusText = computed(() =>
  chatStore.wsConnected ? '已连接' : '未连接'
)

// ─── 发送消息（委托给 store 的统一 WebSocket） ───
function sendMessage() {
  const text = inputText.value.trim()
  if (!text || chatStore.isProcessing) return
  chatStore.sendWsMessage(text)
  inputText.value = ''
  resetInputHeight()
}
function sendQuick(text) { inputText.value = text; sendMessage() }
function resetInputHeight() { if (inputRef.value) inputRef.value.style.height = 'auto' }

function isCopyable(msg) {
  return msg.role === 'agent' || msg.role === 'structured_result' || msg.role === 'cot_complete'
}

function messageText(msg) {
  if (typeof msg.content === 'string') return msg.content
  const content = msg.content || {}
  return content.summary_text || content.content || content.summarized || JSON.stringify(content, null, 2)
}

async function copyMessage(msg) {
  const text = messageText(msg)
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const fallback = document.createElement('textarea')
    fallback.value = text
    fallback.setAttribute('readonly', '')
    fallback.style.position = 'fixed'
    fallback.style.opacity = '0'
    document.body.appendChild(fallback)
    fallback.select()
    document.execCommand('copy')
    fallback.remove()
  }
  copiedMessageId.value = msg.id
  window.setTimeout(() => {
    if (copiedMessageId.value === msg.id) copiedMessageId.value = ''
  }, 1600)
}

// ─── 自动滚动 ───
watch(() => chatStore.messages.length, async () => { await nextTick(); if (msgContainer.value) msgContainer.value.scrollTop = msgContainer.value.scrollHeight })
watch(inputText, () => { nextTick(() => { if (inputRef.value) { inputRef.value.style.height = 'auto'; inputRef.value.style.height = Math.min(inputRef.value.scrollHeight, 120) + 'px' } }) })

// === 工具函数 ===
function statusClass(s) { return { Completed: 'completed', Failed: 'error', Running: 'running', Pending: 'pending' }[s] || 'pending' }
function hypothesisHeaders(c) { if (!c.evidenceMatrix?.length) return []; return Object.keys(c.evidenceMatrix[0]).filter(k => /^H\d$/.test(k)).sort() }
function matrixColor(v) { const n = parseFloat(v); if (isNaN(n)) return 'var(--text-muted)'; if (n >= 0.6) return 'var(--success)'; if (n >= 0.3) return 'var(--warning)'; if (n > 0) return 'var(--error)'; if (n < 0) return 'var(--info)'; return 'var(--text-muted)' }
function hasVisualizationData(c) { return !!((c.evidenceMatrix?.length) || (c.bayesianHistory?.length) || (c.agentDurations?.length)) }
function agentBarWidth(ad, all) { return Math.max(3, (ad.duration_ms / Math.max(...all.map(a => a.duration_ms), 1)) * 100) + '%' }
function agentBarColor(name) { return { '安全分析师': 'var(--color-analyst)', '威胁情报员': 'var(--color-intel)', '应急响应员': 'var(--color-responder)', '知识智能体': 'var(--color-knowledge)' }[name] || 'var(--color-intel)' }
function severityColor(s) { return { '紧急': 'var(--error)', '高危': '#f97316', '中危': 'var(--warning)', '低危': 'var(--success)' }[s] || 'var(--text-muted)' }

// 确定性置信度裁决卡片辅助函数 (v2.2.2)
function confLevelClass(c) {
  if (c >= 0.7) return 'conf-level-high'
  if (c >= 0.4) return 'conf-level-mid'
  return 'conf-level-low'
}
function confVerdictClass(v) {
  return { malicious: 'conf-verdict-mal', suspicious: 'conf-verdict-susp', unknown: 'conf-verdict-unk' }[v] || 'conf-verdict-unk'
}

// 可解释风险评分卡辅助函数 (v2.3)
function riskLevelClass(level) {
  return { '高危': 'risk-level-high', '中危': 'risk-level-mid', '低危': 'risk-level-low' }[level] || 'risk-level-low'
}
function riskScoreClass(score) {
  if (score >= 60) return 'risk-score-high'
  if (score >= 20) return 'risk-score-mid'
  return 'risk-score-low'
}

// 结构化最终结果卡片辅助函数 (v2.4)
function srVerdict(c) {
  return (c.verdict && c.verdict.verdict) || 'unknown'
}
function srConfidence(c) {
  const conf = c.verdict && c.verdict.confidence
  if (conf === null || conf === undefined) return '—'
  return (conf * 100).toFixed(0) + '%'
}
function srRiskLevel(c) {
  return (c.verdict && c.verdict.risk_level) || '低危'
}
function srRiskProbability(c) {
  // v2.6: 风险概率（事件为恶意的可能性）与置信度分离
  // 裁决为 unknown（证据不足）时，概率显示"未知"而非 0%，
  // 避免用户误读为"确定不是恶意"
  const verdict = c && c.verdict && c.verdict.verdict
  const p = c && c.verdict && c.verdict.risk_probability
  if (p === null || p === undefined) return '—'
  if (verdict === 'unknown' && p === 0) return '未知'
  return (p * 100).toFixed(0) + '%'
}
function riskProbClass(p) {
  if (p === '—' || p === '未知') return ''
  const v = parseFloat(p)
  if (v >= 60) return 'risk-score-high'
  if (v >= 30) return 'risk-score-mid'
  return 'risk-score-low'
}
function srStatusLabel(s) {
  return { completed: '分析完成', max_rounds: '达到最大轮次', timeout: '超时熔断', error: '异常终止' }[s] || '完成'
}

// ═══════════ 报告模式 & 事件模板辅助 (v2.5) ═══════════
// 每个卡片的查看模式（quick=快速分析 / expert=专家报告），以消息 id 为 key
const reportModes = reactive({})
function reportMode(id) { return reportModes[id] || 'quick' }
function setReportMode(id, mode) { reportModes[id] = mode }

// Summary Agent 输出（summary_report）优先，回退到 content 顶层字段
function srSummaryReport(c) {
  return (c && c.summary_report && typeof c.summary_report === 'object' && Object.keys(c.summary_report).length)
    ? c.summary_report : null
}
function srRiskSummary(c) {
  const r = srSummaryReport(c)
  return (r && r.risk_summary) || (c && c.risk_summary) || (c && c.summary_text) || ''
}
function srCoreFindings(c) {
  const r = srSummaryReport(c)
  if (r && r.core_findings && r.core_findings.length) return r.core_findings.slice(0, 3)
  const ev = (c && c.agent_results) ? c.agent_results.flatMap(a => (a.key_evidence || [])) : []
  return ev.slice(0, 3)
}
function srRecommendedActions(c) {
  const r = srSummaryReport(c)
  if (r && r.recommended_actions && r.recommended_actions.length) return r.recommended_actions.slice(0, 3)
  const action = c && c.verdict && c.verdict.recommended_action
  const labels = { block: ['封禁来源地址'], monitoring: ['持续监控'], escalate: ['升级人工处置'], none: ['无需处置'] }
  return action ? (labels[action] || [action]) : []
}
function srDetail(c) {
  const r = srSummaryReport(c)
  return (r && r.detail) || (c && c.summary_text) || ''
}
function srTemplateType(c) {
  const r = srSummaryReport(c)
  return (r && r.template_type) || (c && c.template_type) || '安全配置'
}
function srTemplateTitle(t) {
  return { '漏洞分析': '漏洞分析', '攻击检测': '攻击检测', '安全配置': '安全配置', '威胁情报': '威胁情报', '应急响应': '应急响应' }[t] || '安全分析'
}
function srTemplateTable(c) {
  const r = srSummaryReport(c)
  const t = (r && r.table) || (c && c.table) || []
  return Array.isArray(t) ? t.filter(x => x && typeof x === 'object') : []
}
function srTemplateTableTitle(t) {
  return { '漏洞分析': '漏洞明细', '攻击检测': '攻击证据', '安全配置': '配置项明细', '威胁情报': '情报命中', '应急响应': '处置步骤' }[t] || '明细'
}
function srTableHeaders(c) {
  const rows = srTemplateTable(c)
  const headers = []
  for (const r of rows) for (const k in r) if (!headers.includes(k)) headers.push(k)
  return headers.slice(0, 6)
}
function srEvidenceChain(c) {
  // v2.6 证据链：为什么 / 依据 / 调用了什么工具
  const chain = (c && c.evidence_chain) || []
  return Array.isArray(chain) ? chain : []
}

// ─── TrueReAct 过程时间线辅助 ───
function traceCount(content) {
  const rounds = content?.rounds || []
  return rounds.reduce((n, r) => n + (r.items?.length || 0), 0)
}
function traceBadge(it) {
  return {
    think: '推理', act: '决策', observe: '观察', agent_route: '路由', round_complete: '轮次',
    tool_call: '工具', tool_result: '结果', agent_dispatch: '分发',
    agent_result: '完成', agent_error: '失败', route_correction: '修正',
  }[it.type] || it.type
}
function hasKeys(o) {
  return !!o && typeof o === 'object' && Object.keys(o).length > 0
}
function formatArgs(args) {
  try { return JSON.stringify(args, null, 2) } catch { return String(args) }
}

function renderMarkdown(text) {
  if (!text) return ''
  if (typeof text !== 'string') { try { text = JSON.stringify(text, null, 2) } catch { text = String(text) } }
  try {
    // 使用 marked 库安全渲染，strip 掉可能危险的 HTML
    const html = marked.parse(text)
    // 只允许安全标签
    return html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/on\w+="[^"]*"/gi, '')
  } catch {
    // fallback: 基本转义
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\n/g, '<br>')
  }
}
</script>

<style scoped>
.chat-view { height: 100%; display: flex; background: var(--bg-primary); }
.chat-main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
/* 会话侧边栏 */
.conv-sidebar { width: 220px; flex-shrink: 0; border-right: 1px solid var(--border-primary); background: var(--bg-card); display: flex; flex-direction: column; padding: 12px; gap: 10px; overflow-y: auto; }
.new-conv-btn { display: flex; align-items: center; justify-content: center; gap: 6px; padding: 8px 12px; background: var(--accent); color: white; border: none; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all var(--transition-fast); flex-shrink: 0; }
.new-conv-btn:hover { background: var(--accent-hover); }
.conv-list { flex: 1; display: flex; flex-direction: column; gap: 4px; overflow-y: auto; }
.conv-item { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: 8px; cursor: pointer; color: var(--text-secondary); font-size: 12px; transition: background var(--transition-fast); }
.conv-item:hover { background: var(--bg-elevated); }
.conv-item.active { background: var(--accent-subtle); color: var(--accent-hover); }
.conv-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
.conv-loading { color: var(--text-muted); font-size: 12px; padding: 8px; text-align: center; }
.conv-empty { color: var(--text-muted); font-size: 12px; padding: 16px 8px; text-align: center; }
.msg-list { flex: 1; overflow-y: auto; padding: 20px 24px; scroll-behavior: smooth; }
.empty-state { text-align: center; margin-top: 80px; animation: count-up 0.5s ease; }
.empty-icon { margin-bottom: 16px; opacity: 0.4; }
.empty-title { font-size: 22px; font-weight: 700; color: var(--text-primary); letter-spacing: 2px; margin-bottom: 6px; }
.empty-subtitle { font-size: 13px; color: var(--text-muted); margin-bottom: 32px; }
.quick-replies { display: flex; justify-content: center; gap: 10px; flex-wrap: wrap; }
.quick-btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-full); color: var(--text-tertiary); font-size: 12px; font-weight: 500; cursor: pointer; transition: all var(--transition-fast); }
.quick-btn:hover { border-color: var(--accent); color: var(--accent-hover); background: var(--accent-subtle); }
.msg-item { position: relative; margin-bottom: 16px; animation: count-up 0.3s ease; }
.copy-message-btn { position: absolute; right: 2px; bottom: -2px; padding: 3px 7px; border: 1px solid var(--border-primary); border-radius: 5px; background: var(--bg-card); color: var(--text-muted); font-size: 10px; cursor: pointer; opacity: 0; transition: opacity var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast); }
.msg-item:hover .copy-message-btn, .copy-message-btn:focus-visible { opacity: 1; }
.copy-message-btn:hover, .copy-message-btn.copied { color: var(--success); border-color: var(--success); }
.msg-user { display: flex; justify-content: flex-end; }
.msg-bubble { display: flex; gap: 10px; max-width: 75%; }
.bubble-avatar { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; flex-shrink: 0; margin-top: 4px; }
.user-avatar { background: var(--accent); color: white; order: 1; }
.agent-avatar { background: linear-gradient(135deg, var(--color-intel), var(--color-analyst)); color: white; }
.bubble-content { line-height: 1.7; font-size: 14px; position: relative; }
.user-bubble .bubble-content { background: var(--accent-subtle); border: 1px solid rgba(220,38,38,0.2); border-radius: 16px 4px 16px 16px; padding: 10px 16px; color: var(--text-secondary); }
.agent-bubble { justify-content: flex-start; }
.agent-bubble .bubble-content { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: 4px 16px 16px 16px; padding: 10px 16px; color: var(--text-secondary); }
:deep(.md-h3) { margin: 16px 0 6px; color: var(--text-primary); font-size: 15px; font-weight: 600; }
:deep(.md-h4) { margin: 12px 0 4px; color: var(--text-primary); font-size: 14px; font-weight: 600; }
:deep(.md-bold) { color: var(--warning); font-weight: 600; }
:deep(.md-code) { background: var(--bg-elevated); padding: 2px 6px; border-radius: 4px; color: #a5d6ff; font-family: var(--font-mono); font-size: 13px; }
:deep(.md-li) { margin: 3px 0; color: var(--text-secondary); list-style: none; }
:deep(.md-li)::before { content: ''; display: inline-block; width: 5px; height: 5px; border-radius: 50%; background: var(--accent); margin-right: 8px; vertical-align: middle; }
:deep(.md-para) { margin: 8px 0; }
:deep(.md-arrow) { color: var(--warning); }
.status-card { display: flex; align-items: center; gap: 10px; width: 100%; padding: 10px 16px; border-radius: var(--radius-sm); border: 1px solid var(--border-primary); background: var(--bg-card); transition: all var(--transition-fast); }
.status-card.status-running { border-color: rgba(34,197,94,0.3); }
.status-card.status-completed { border-color: rgba(59,130,246,0.3); }
.status-card.status-error { border-color: rgba(239,68,68,0.3); }
.status-card.status-pending { border-color: rgba(234,179,8,0.2); }
.status-info { flex: 1; display: flex; align-items: center; gap: 8px; }
.status-name { font-size: 13px; font-weight: 500; color: var(--text-secondary); }
.status-label { font-size: 10px; font-weight: 600; padding: 1px 6px; border-radius: 3px; }
.label-completed { color: var(--info); background: var(--info-bg); }
.label-running { color: var(--success); background: var(--success-bg); }
.label-failed { color: var(--error); background: var(--error-bg); }
.label-pending { color: var(--warning); background: var(--warning-bg); }
.status-metrics { display: flex; gap: 12px; font-size: 11px; color: var(--text-muted); }
.metric-item { display: flex; align-items: center; gap: 4px; }
.status-result { font-size: 11px; font-weight: 600; }
.result-pass { color: var(--success); } .result-fail { color: var(--error); } .result-pending { color: var(--warning); }
.status-spinner { width: 14px; height: 14px; border: 2px solid var(--border-primary); border-top-color: var(--warning); border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.cot-card { width: 100%; border-radius: var(--radius-sm); overflow: hidden; }
.cot-start { border-left: 4px solid var(--warning); background: var(--bg-card); }
.cot-step { border-left: 4px solid var(--color-intel); background: var(--bg-card); }
.cot-complete { border-left: 4px solid var(--success); background: var(--bg-card); }
.cot-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; font-size: 13px; font-weight: 600; color: var(--warning); border-bottom: 1px solid var(--border-primary); }
.cot-step .cot-header { color: var(--color-intel); } .cot-complete .cot-header { color: var(--success); }
.cot-body { padding: 12px 14px; font-size: 13px; line-height: 1.6; color: var(--text-secondary); }
.cot-section { margin-bottom: 10px; }
.cot-section-title { font-size: 11px; font-weight: 600; color: var(--text-muted); margin-bottom: 4px; }
.cot-section-body { background: var(--bg-primary); padding: 8px 12px; border-radius: var(--radius-sm); font-size: 13px; }
.conclusion-body { border-left: 3px solid var(--success); }
.ev-item { padding: 2px 0; font-size: 13px; color: var(--text-tertiary); }
.cot-next { display: inline-block; margin-top: 8px; padding: 4px 10px; background: var(--bg-elevated); border-radius: var(--radius-sm); color: var(--info); font-size: 12px; }
.conf-badge { margin-left: auto; font-size: 11px; font-weight: 600; padding: 1px 8px; border-radius: 3px; background: var(--bg-elevated); color: var(--text-tertiary); }
.chain-list { width: 100%; }
.chain-step { margin-bottom: 4px; }
.step-node { display: flex; align-items: center; gap: 12px; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-primary); background: var(--bg-card); transition: all var(--transition-fast); }
.step-completed .step-node { border-color: rgba(59,130,246,0.2); }
.step-running .step-node { border-color: rgba(34,197,94,0.3); }
.step-pending .step-node { opacity: 0.5; }
.step-indicator { width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; font-size: 12px; font-weight: 700; }
.indicator-completed { background: var(--info-bg); color: var(--info); }
.indicator-running { background: var(--success-bg); color: var(--success); animation: pulse-dot 1.5s infinite; }
.indicator-pending { background: var(--bg-elevated); color: var(--text-muted); }
.step-body { flex: 1; }
.step-title { font-size: 13px; font-weight: 600; color: var(--text-secondary); }
.step-output { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
.step-badge { font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: var(--radius-full); }
.badge-completed { background: var(--info-bg); color: var(--info); }
.badge-running { background: var(--success-bg); color: var(--success); }
.badge-pending { background: var(--bg-elevated); color: var(--text-muted); }
.step-num { color: var(--text-muted); }
.reasoner-card { width: 100%; background: var(--bg-primary); border: 1px solid var(--border-primary); border-left: 4px solid var(--color-intel); border-radius: var(--radius-sm); }
.reasoner-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; color: var(--color-intel); font-size: 13px; font-weight: 600; border-bottom: 1px solid var(--border-primary); }
.winner-tag { margin-left: auto; font-size: 11px; padding: 2px 8px; border-radius: var(--radius-full); font-weight: 600; }
.winner-high { background: var(--success-bg); color: var(--success); } .winner-mid { background: var(--warning-bg); color: var(--warning); } .winner-low { background: var(--error-bg); color: var(--error); }
.reasoner-body { padding: 12px 14px; font-size: 13px; line-height: 1.6; color: var(--text-secondary); }
.viz-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 0 14px 14px; }
.viz-card { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); padding: 10px; }
.viz-title { font-size: 10px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; letter-spacing: 1px; }
.viz-table { width: 100%; border-collapse: collapse; font-size: 11px; }
.viz-table th { text-align: left; color: var(--text-muted); padding: 4px 6px; border-bottom: 1px solid var(--border-primary); }
.viz-table td { padding: 4px 6px; border-bottom: 1px solid var(--bg-elevated); }
.ev-cell { color: var(--text-tertiary); max-width: 100px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.val-cell { text-align: center; font-weight: 600; }
.viz-side { display: flex; flex-direction: column; gap: 12px; }
.bayes-item { margin-bottom: 8px; }
.bayes-label { display: flex; gap: 8px; font-size: 11px; color: var(--text-secondary); margin-bottom: 2px; }
.bayes-id { color: var(--warning); }
.bar-row { display: flex; align-items: center; gap: 6px; font-size: 10px; color: var(--text-muted); margin-bottom: 2px; }
.bar-label { min-width: 28px; } .bar-track { flex: 1; height: 6px; background: var(--bg-elevated); border-radius: 3px; overflow: hidden; }
.bar-fill { height: 100%; background: var(--text-muted); border-radius: 3px; }
.bar-up { background: var(--success); } .bar-down { background: var(--error); }
.bar-val { min-width: 32px; text-align: right; } .text-up { color: var(--success); } .text-down { color: var(--error); }
.dur-row { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.dur-name { font-size: 11px; color: var(--text-secondary); min-width: 65px; }
.dur-track { flex: 1; height: 8px; background: var(--bg-elevated); border-radius: 4px; overflow: hidden; }
.dur-fill { height: 100%; border-radius: 4px; } .dur-val { font-size: 10px; color: var(--text-muted); min-width: 50px; text-align: right; }
/* ═══ TrueReAct 过程时间线 ═══ */
.trace-card { width: 100%; border: 1px solid var(--border-primary); border-radius: var(--radius-sm); background: var(--bg-card); overflow: hidden; }
.trace-card > summary { list-style: none; cursor: pointer; }
.trace-card > summary::-webkit-details-marker { display: none; }
.trace-header { display: flex; align-items: center; gap: 8px; padding: 8px 14px; font-size: 12px; font-weight: 600; color: var(--color-intel); background: var(--bg-elevated); border-bottom: 1px solid var(--border-primary); user-select: none; }
.trace-header svg { color: var(--color-intel); flex-shrink: 0; }
.trace-badge { margin-left: auto; font-size: 10px; font-weight: 500; color: var(--text-muted); background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-full); padding: 1px 8px; }
.trace-body { padding: 6px 14px 10px; max-height: 340px; overflow-y: auto; }
.trace-round { margin-top: 8px; }
.trace-round-title { font-size: 11px; font-weight: 700; color: var(--text-tertiary); margin-bottom: 4px; letter-spacing: 0.5px; }
.trace-item { display: flex; align-items: flex-start; gap: 8px; padding: 3px 0; font-size: 12px; line-height: 1.5; }
.t-badge { flex-shrink: 0; min-width: 30px; text-align: center; font-size: 10px; font-weight: 600; padding: 1px 6px; border-radius: 3px; background: var(--bg-elevated); color: var(--text-muted); margin-top: 1px; }
.t-content { flex: 1; min-width: 0; color: var(--text-secondary); }
.t-line { color: var(--text-secondary); }
.t-name { color: var(--text-secondary); }
.t-name code, .t-content code { background: var(--bg-elevated); padding: 0 4px; border-radius: 3px; color: #a5d6ff; font-family: var(--font-mono); font-size: 11px; }
.t-ok { color: var(--success); } .t-err { color: var(--error); } .t-warn { color: var(--warning); }
.t-task { font-size: 11px; color: var(--text-muted); margin-top: 1px; overflow: hidden; text-overflow: ellipsis; }
.t-meta { margin-left: 6px; font-size: 11px; color: var(--text-muted); }
.t-verdict { font-weight: 600; }
.t-verdict.v-malicious { color: var(--error); }
.t-verdict.v-suspicious { color: var(--warning); }
.t-verdict.v-benign { color: var(--success); }
.t-verdict.v-unknown { color: var(--text-muted); }
.t-args { margin: 3px 0 0; padding: 6px 8px; background: var(--bg-primary); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 10px; color: var(--text-tertiary); overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.t-think { font-size: 12px; line-height: 1.7; color: var(--text-tertiary); padding: 2px 0; }
.t-think p { margin: 4px 0; }
.t-think strong { color: var(--text-secondary); }
.t-item.t-think { border-left: 2px solid var(--color-intel); padding-left: 8px; margin-left: 2px; }
.t-item.t-think .t-badge { background: rgba(6,182,212,0.12); color: var(--color-intel); }
.t-item.t-agent_error .t-badge { background: rgba(239,68,68,0.12); color: var(--error); }
.t-item.t-route_correction .t-badge { background: rgba(245,158,11,0.12); color: var(--warning); }
.t-item.t-tool_call .t-badge { background: rgba(59,130,246,0.12); color: var(--color-intel); }
.t-item.t-agent_result .t-badge { background: rgba(34,197,94,0.12); color: var(--success); }

.analysis-card { width: 100%; border: 1px solid var(--border-primary); border-radius: var(--radius-sm); overflow: hidden; }
.analysis-header { padding: 8px 14px; font-size: 12px; font-weight: 600; color: var(--text-secondary); background: var(--bg-elevated); border-bottom: 1px solid var(--border-primary); }
.analysis-grid { display: grid; grid-template-columns: repeat(5, 1fr); }
.analysis-cell { padding: 8px 10px; border-right: 1px solid var(--border-primary); }
.analysis-cell:last-child { border-right: none; }
.cell-label { display: block; font-size: 10px; color: var(--text-muted); margin-bottom: 2px; }
.cell-value { font-size: 13px; font-weight: 500; color: var(--text-secondary); }
.msg-system { text-align: center; } .sys-text { font-size: 11px; color: var(--text-muted); opacity: 0.7; }
/* ═══ 结构化最终结果卡片 (JSON-first, v2.4) ═══ */
.sr-card { width: 100%; border: 1px solid var(--border-primary); border-radius: var(--radius-sm); overflow: hidden; background: var(--bg-card); }
.sr-header { display: flex; align-items: center; gap: 6px; padding: 8px 14px; font-size: 12px; font-weight: 600; color: var(--text-secondary); background: var(--bg-elevated); border-bottom: 1px solid var(--border-primary); }
.sr-header svg { color: var(--color-analyst, var(--accent)); }
.sr-status { margin-left: auto; font-size: 10px; font-weight: 500; color: var(--text-muted); }
.sr-main { display: flex; align-items: baseline; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--border-primary); }
.sr-score { font-size: 34px; font-weight: 800; line-height: 1; }
.risk-score-high { color: var(--error); }
.risk-score-mid { color: var(--warning); }
.risk-score-low { color: var(--success); }
.sr-label { font-size: 11px; color: var(--text-muted); }
.sr-decision { font-size: 14px; font-weight: 700; text-transform: capitalize; margin-left: auto; }
.sr-human { font-size: 11px; color: var(--warning); }
.sr-unknown-hint { font-size: 10px; color: var(--text-muted); border: 1px dashed var(--border-primary); border-radius: 3px; padding: 1px 6px; white-space: nowrap; }
.sr-meta { display: flex; gap: 18px; padding: 8px 14px; font-size: 11px; color: var(--text-muted); border-bottom: 1px solid var(--border-primary); }
.sr-meta-item strong { color: var(--text-secondary); }
.sr-summary { padding: 10px 14px; font-size: 13px; color: var(--text-secondary); border-bottom: 1px dashed var(--border-primary); line-height: 1.7; }
.sr-agents { padding: 6px 14px 10px; }
.sr-agent { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 12px; }
.sr-agent-name { width: 130px; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sr-agent-verdict { font-weight: 600; text-transform: capitalize; }
.sr-agent-verdict.agent-verdict-malicious { color: var(--error); }
.sr-agent-verdict.agent-verdict-suspicious { color: var(--warning); }
.sr-agent-verdict.agent-verdict-benign { color: var(--success); }
.sr-agent-verdict.agent-verdict-unknown { color: var(--text-muted); }
.sr-agent-conf { margin-left: auto; color: var(--text-secondary); font-size: 11px; }
.sr-path { padding: 8px 14px 12px; border-top: 1px dashed var(--border-primary); }
.sr-path-title { font-size: 11px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px; }
.sr-path-step { display: flex; align-items: flex-start; gap: 8px; padding: 3px 0; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
.sr-path-num { flex-shrink: 0; width: 18px; height: 18px; border-radius: 50%; background: var(--bg-elevated); color: var(--text-muted); font-size: 10px; font-weight: 700; display: flex; align-items: center; justify-content: center; margin-top: 1px; }
.path-tag-evidence .sr-path-num { background: rgba(96,165,250,0.15); color: var(--color-intel, #3b82f6); }
.path-tag-conflict .sr-path-num { background: rgba(245,158,11,0.15); color: var(--warning); }
.path-tag-fusion .sr-path-num { background: rgba(168,85,247,0.15); color: #a855f7; }
.path-tag-decision .sr-path-num { background: rgba(220,38,38,0.15); color: var(--error); }
.sr-path-conflicts { margin-top: 6px; border-top: 1px dashed var(--border-primary); padding-top: 6px; }
.sr-conflict { font-size: 11px; color: var(--warning); padding: 2px 0; }
/* ═══ v2.5: 报告模式 & 事件模板 & 折叠详细分析 ═══ */
.sr-tpl-tag { font-size: 10px; font-weight: 600; padding: 1px 8px; border-radius: 10px; color: var(--color-intel); background: rgba(59,130,246,0.12); }
.sr-mode-switch { display: flex; gap: 4px; }
.mode-btn { font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 3px; border: 1px solid var(--border-primary); background: var(--bg-card); color: var(--text-muted); cursor: pointer; transition: all var(--transition-fast); }
.mode-btn:hover { border-color: var(--accent); color: var(--accent-hover); }
.mode-btn.mode-active { background: var(--accent); border-color: var(--accent); color: #fff; }
.sr-section { padding: 8px 14px; border-bottom: 1px dashed var(--border-primary); }
.sr-section-title { font-size: 11px; font-weight: 700; color: var(--text-tertiary); margin-bottom: 6px; letter-spacing: 0.5px; }
.sr-finding { display: flex; align-items: flex-start; gap: 8px; padding: 2px 0; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
.sr-finding-dot { flex-shrink: 0; width: 6px; height: 6px; border-radius: 50%; background: var(--accent); margin-top: 6px; }
.sr-finding-text { flex: 1; }
.sr-action { display: flex; align-items: flex-start; gap: 8px; padding: 3px 0; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
.sr-action-num { flex-shrink: 0; width: 18px; height: 18px; border-radius: 50%; background: var(--success-bg); color: var(--success); font-size: 10px; font-weight: 700; display: flex; align-items: center; justify-content: center; margin-top: 1px; }
.sr-action-text { flex: 1; }
/* ═══ 证据链 (v2.6) ═══ */
.ec-item { border: 1px solid var(--border-primary); border-left: 3px solid var(--color-intel); border-radius: var(--radius-sm); padding: 8px 10px; margin-bottom: 6px; background: var(--bg-primary); }
.ec-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.ec-agent { font-size: 12px; font-weight: 700; color: var(--text-secondary); }
.ec-verdict { font-size: 10px; font-weight: 600; text-transform: capitalize; }
.ec-verdict.agent-verdict-malicious { color: var(--error); }
.ec-verdict.agent-verdict-suspicious { color: var(--warning); }
.ec-verdict.agent-verdict-benign { color: var(--success); }
.ec-verdict.agent-verdict-unknown { color: var(--text-muted); }
.ec-conf { margin-left: auto; font-size: 11px; font-weight: 600; color: var(--text-secondary); }
.ec-row { display: flex; align-items: flex-start; gap: 8px; padding: 2px 0; font-size: 11px; line-height: 1.5; }
.ec-label { flex-shrink: 0; min-width: 28px; font-weight: 600; color: var(--text-muted); }
.ec-val { flex: 1; color: var(--text-secondary); }
.ec-tools { flex: 1; display: flex; flex-wrap: wrap; gap: 4px; }
.ec-tool { background: var(--bg-elevated); padding: 0 6px; border-radius: 3px; color: #a5d6ff; font-family: var(--font-mono); font-size: 10px; }
.sr-table { width: 100%; border-collapse: collapse; font-size: 11px; margin-top: 4px; }
.sr-table th { text-align: left; color: var(--text-muted); padding: 4px 8px; border-bottom: 1px solid var(--border-primary); white-space: nowrap; }
.sr-table td { padding: 4px 8px; border-bottom: 1px solid var(--bg-elevated); color: var(--text-secondary); }
.sr-detail { border-bottom: 1px dashed var(--border-primary); }
.sr-detail-summary { display: flex; align-items: center; gap: 6px; padding: 8px 14px; font-size: 12px; font-weight: 600; color: var(--text-secondary); cursor: pointer; user-select: none; list-style: none; }
.sr-detail-summary::-webkit-details-marker { display: none; }
.sr-detail-summary svg { transition: transform 0.2s; color: var(--text-muted); }
.sr-detail[open] .sr-detail-summary svg { transform: rotate(90deg); }
.sr-detail-body { padding: 0 14px 12px; font-size: 13px; line-height: 1.7; color: var(--text-secondary); }
.sr-agent-summary { flex: 1; font-size: 11px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sr-full { padding: 8px 14px 12px; border-top: 1px dashed var(--border-primary); }
.sr-full-body { font-size: 12px; line-height: 1.6; color: var(--text-secondary); }
/* 模板分类底色 */
.sr-card.tpl-漏洞分析 { border-top: 2px solid var(--color-knowledge, #8b5cf6); }
.sr-card.tpl-攻击检测 { border-top: 2px solid var(--error); }
.sr-card.tpl-安全配置 { border-top: 2px solid var(--color-analyst, #3b82f6); }
.sr-card.tpl-威胁情报 { border-top: 2px solid var(--color-intel, #06b6d4); }
.sr-card.tpl-应急响应 { border-top: 2px solid var(--warning); }
/* ═══ 确定性置信度裁决卡片 (v2.2.2) ═══ */
.confidence-card { width: 100%; border: 1px solid var(--border-primary); border-radius: var(--radius-sm); overflow: hidden; background: var(--bg-card); }
.conf-header { display: flex; align-items: center; gap: 6px; padding: 8px 14px; font-size: 12px; font-weight: 600; color: var(--text-secondary); background: var(--bg-elevated); border-bottom: 1px solid var(--border-primary); }
.conf-header svg { color: var(--color-intel); }
.conf-main { display: flex; align-items: baseline; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--border-primary); }
.conf-value { font-size: 26px; font-weight: 700; }
.conf-level-high { color: var(--error); }
.conf-level-mid { color: var(--warning); }
.conf-level-low { color: var(--success); }
.conf-verdict { font-size: 13px; font-weight: 600; text-transform: capitalize; }
.conf-verdict-mal { color: var(--error); }
.conf-verdict-susp { color: var(--warning); }
.conf-verdict-unk { color: var(--text-muted); }
.conf-human { font-size: 11px; color: var(--warning); margin-left: auto; }
.conf-details { padding: 6px 14px; }
.conf-row { display: flex; align-items: center; gap: 8px; padding: 3px 0; font-size: 11px; }
.conf-agent { width: 120px; color: var(--text-secondary); font-family: var(--font-mono, monospace); font-size: 10px; }
.conf-weight { width: 32px; color: var(--text-muted); text-align: right; }
.conf-bar { flex: 1; height: 5px; background: var(--bg-elevated); border-radius: 3px; overflow: hidden; }
.conf-bar i { display: block; height: 100%; background: var(--color-intel); opacity: 0.7; }
.conf-agent-conf { width: 44px; text-align: right; font-weight: 600; color: var(--text-secondary); }
.conf-tag { font-size: 9px; padding: 1px 5px; border-radius: 3px; }
.tag-degraded { color: var(--warning); background: rgba(245,158,11,0.12); }
.tag-failed { color: var(--error); background: rgba(239,68,68,0.12); }
.conf-coverage { padding: 6px 14px 10px; font-size: 11px; color: var(--text-muted); border-top: 1px dashed var(--border-primary); }
.conf-coverage strong { color: var(--text-secondary); }
/* ═══ 可解释风险评分卡 (v2.3) ═══ */
.risk-card { width: 100%; border: 1px solid var(--border-primary); border-radius: var(--radius-sm); overflow: hidden; background: var(--bg-card); }
.risk-header { display: flex; align-items: center; gap: 6px; padding: 8px 14px; font-size: 12px; font-weight: 600; color: var(--text-secondary); background: var(--bg-elevated); border-bottom: 1px solid var(--border-primary); }
.risk-header svg { color: var(--warning); }
.risk-level { margin-left: auto; font-size: 11px; font-weight: 700; padding: 1px 8px; border-radius: 10px; }
.risk-level-high { color: var(--error); background: rgba(239,68,68,0.12); }
.risk-level-mid { color: var(--warning); background: rgba(245,158,11,0.12); }
.risk-level-low { color: var(--success); background: rgba(34,197,94,0.12); }
.risk-main { display: flex; align-items: baseline; gap: 8px; padding: 10px 14px; border-bottom: 1px solid var(--border-primary); }
.risk-score { font-size: 30px; font-weight: 800; line-height: 1; }
.risk-score-high { color: var(--error); }
.risk-score-mid { color: var(--warning); }
.risk-score-low { color: var(--success); }
.risk-label { font-size: 11px; color: var(--text-muted); }
.risk-human { font-size: 11px; color: var(--warning); margin-left: auto; }
.risk-dims { padding: 6px 14px; }
.risk-dim { display: flex; align-items: baseline; gap: 8px; padding: 3px 0; font-size: 11px; }
.risk-dim-name { width: 64px; flex-shrink: 0; color: var(--text-secondary); font-weight: 600; }
.risk-dim-delta { width: 40px; flex-shrink: 0; text-align: right; font-weight: 700; font-family: var(--font-mono, monospace); }
.delta-pos { color: var(--error); }
.delta-neg { color: var(--success); }
.delta-zero { color: var(--text-muted); }
.risk-dim-reason { flex: 1; color: var(--text-muted); }
.risk-footer { padding: 6px 14px 10px; font-size: 11px; color: var(--text-secondary); border-top: 1px dashed var(--border-primary); display: flex; justify-content: space-between; gap: 8px; }
.risk-rules { color: var(--text-muted); font-family: var(--font-mono, monospace); font-size: 10px; text-align: right; }
/* ═══ WebSocket 连接状态栏 ═══ */
.ws-status-bar { display: flex; align-items: center; gap: 8px; padding: 4px 20px; border-top: 1px solid var(--border-primary); font-size: 11px; transition: all var(--transition-fast); }
.ws-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; transition: background 0.3s; }
.ws-label { color: var(--text-muted); }
.ws-boundary { color: var(--text-muted); font-size: 10px; margin-left: auto; }
.ws-connected .ws-dot { background: var(--success); box-shadow: 0 0 4px rgba(34,197,94,0.4); }
.ws-connected .ws-label { color: var(--success); }
.ws-connecting .ws-dot { background: var(--warning); animation: pulse-dot 1s infinite; }
.ws-connecting .ws-label { color: var(--warning); }
.ws-reconnecting .ws-dot { background: var(--warning); animation: pulse-dot 1s infinite; }
.ws-reconnecting .ws-label { color: var(--warning); }
.ws-disconnected .ws-dot { background: var(--error); }
.ws-disconnected .ws-label { color: var(--error); }
@keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

.processing-bar { display: flex; align-items: center; gap: 10px; padding: 8px 0; color: var(--text-muted); font-size: 12px; }
.processing-dots { display: flex; gap: 4px; }
.processing-dots span { width: 6px; height: 6px; border-radius: 50%; background: var(--text-muted); animation: bounce 1.4s infinite ease-in-out both; }
.processing-dots span:nth-child(1) { animation-delay: -0.32s; }
.processing-dots span:nth-child(2) { animation-delay: -0.16s; }
@keyframes bounce { 0%,80%,100% { transform: scale(0); } 40% { transform: scale(1); } }
.input-bar { border-top: 1px solid var(--border-primary); padding: 16px 20px; background: var(--bg-card); }
.input-wrapper { display: flex; align-items: flex-end; gap: 10px; background: var(--bg-primary); border: 1px solid var(--border-primary); border-radius: var(--radius-md); padding: 8px 12px; transition: border-color var(--transition-fast); }
.input-wrapper:focus-within { border-color: var(--accent); box-shadow: 0 0 0 1px rgba(220,38,38,0.15); }
.chat-input { flex: 1; background: transparent; border: none; outline: none; color: var(--text-primary); font-family: var(--font-sans); font-size: 14px; line-height: 1.5; resize: none; max-height: 120px; }
.chat-input::placeholder { color: var(--text-muted); } .chat-input:disabled { opacity: 0.5; }
.send-btn { width: 36px; height: 36px; border-radius: 50%; border: none; display: flex; align-items: center; justify-content: center; background: var(--bg-elevated); color: var(--text-muted); cursor: pointer; transition: all var(--transition-fast); flex-shrink: 0; }
.send-btn.active { background: var(--accent); color: white; }
.send-btn.active:hover { background: var(--accent-hover); box-shadow: var(--shadow-glow-red); }
.send-btn:disabled { cursor: not-allowed; opacity: 0.4; }
.send-spinner { width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 0.8s linear infinite; }
.input-hint { margin-top: 7px; color: var(--text-muted); font-size: 10px; line-height: 1.4; }

/* ═══ 响应式 ChatView ═══ */
@media (max-width: 768px) {
  .msg-list { padding: 12px !important; }
  .msg-bubble { max-width: 90% !important; }
  .bubble-content { font-size: 13px !important; }
  .input-bar { padding: 8px 10px !important; }
  .input-wrapper { padding: 6px 10px !important; }
  .input-hint { font-size: 9px; }
  .chat-input { font-size: 13px !important; }
  .empty-state { margin-top: 40px !important; }
  .empty-title { font-size: 18px !important; }
  .empty-subtitle { font-size: 12px !important; }
  .analysis-grid { grid-template-columns: repeat(2, 1fr) !important; }
  .analysis-cell { padding: 6px 8px !important; }
  .analysis-cell:nth-child(5) { grid-column: span 2; }
  .viz-grid { grid-template-columns: 1fr !important; }
  .step-node { flex-wrap: wrap; gap: 6px !important; }
  .step-output { width: 100%; }
  .status-metrics { gap: 6px; font-size: 10px; }
}
</style>
