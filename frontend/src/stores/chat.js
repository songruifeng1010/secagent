import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { apiFetch, buildApiUrl } from '../utils/http.js'

export const useChatStore = defineStore('chat', () => {
  const messages = ref([])
  const activeAgents = ref({})
  const isProcessing = ref(false)
  const agentStatusList = ref([])
  const messageList = computed(() => messages.value)

  // ═══ 会话管理（历史对话 / 新建 / 恢复） ═══
  const conversations = ref([])        // 历史会话列表
  const currentConversationId = ref('') // 当前会话 ID
  const convLoading = ref(false)        // 会话列表加载中

  // ═══ 统一 WebSocket 管理（由 App.vue 创建，子组件通过 store 调用） ═══
  const wsConnected = ref(false)
  let _ws = null
  let _heartbeatTimer = null
  let _reconnectTimer = null
  let _reconnectAttempts = 0
  let _pendingMessage = null
  let _manualClose = false
  const WS_HEARTBEAT_INTERVAL = 30000
  const MAX_RECONNECT_DELAY = 30000 // 重连最大间隔 30 秒（无限重试，不永久放弃）

  function addMessage(role, content, agentId = '', agentName = '') {
    messages.value.push({
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      role,
      content,
      agentId,
      agentName,
      timestamp: new Date().toISOString(),
    })
  }

  function upsertAgentStatus(agentId, agentName, status, durationMs = 0, tokens = 0) {
    const existing = agentStatusList.value.find(a => a.id === agentId)
    if (existing) {
      existing.status = status
      if (durationMs > 0) existing.durationMs = durationMs
      if (tokens > 0) existing.tokens = tokens
    } else {
      agentStatusList.value.push({
        id: agentId,
        name: agentName,
        status: status,
        durationMs: durationMs,
        tokens: tokens,
      })
    }
  }

  function handleMessage(data) {
    const type = data.type || ''

    if (type === 'orchestrator_start' || type === 'true_react_start') {
      isProcessing.value = true
    }

    if (type === 'intent') {
      const intentData = data.intent || {}
      const entities = intentData.entities || {}
      const cves = (entities.cve_ids || []).length
      const techniques = (entities.technique_ids || []).length
      const ips = (entities.ips || []).length
      const source = techniques > 0 ? 'ATT&CK' : cves > 0 ? 'CVE' : ips > 0 ? 'Threat Intel' : 'Knowledge'
      addMessage('analysis_result', {
        intent: intentData.primary_intent || 'GENERAL',
        severity: intentData.urgency || 'LOW',
        confidence: intentData.confidence || 0.5,
        source: source,
        evidenceCount: techniques + cves,
        entities: entities,
      })
    }

    if (type === 'task_start') {
      const agentId = data.agent_id || ''
      const agentName = data.agent_name || ''
      activeAgents.value[agentId] = { name: agentName, status: 'running' }
      upsertAgentStatus(agentId, agentName, 'Running')
      addMessage('agent_status_card', {
        agentId: agentId,
        agentName: agentName,
        status: 'Running',
        durationMs: 0,
        tokens: 0,
      }, agentId, agentName)
    }

    // 处理 Planner 模式的流式输出（type = "stream"）
    if (type === 'stream') {
      const agentId = data.agent_id || 'orch-001'
      const content = data.content || ''
      const last = messages.value[messages.value.length - 1]
      if (last && last.agentId === agentId && last.role === 'agent') {
        last.content += content
      } else {
        addMessage('agent', content, agentId, 'SecAgentX')
      }
    }

    // 处理 TrueReAct 思考输出
    // 修复：不再拼接为一条消息再截断（slice(-800) 会导致内容从中间开始、上下文割裂）。
    // 改为思考内容按轮次进入过程时间线（trace_panel），每轮一条完整"推理"条目，
    // 与工具调用 / Agent 路由聚合展示；trace_panel 默认收起，展开可见完整上下文。
    if (type === 'true_react_think' || type === 'true_react_think_content') {
      const content = normalizeThinkSpacing(data.content || data.thought || '')
      if (!content) return
      // true_react_think 只是轮次标题（"第 N 轮 — 指挥官思考决策"），
      // 由 trace 的"第 N 轮"分组标题自然体现，无需单独记录。
      if (type === 'true_react_think_content') {
        pushTraceEvent(data.round || 0, { type: 'think', text: content.trim() })
      }
    }

    // ─── TrueReAct 过程事件 → 聚合到"过程时间线"（修复：此前全部被丢弃） ───
    if (type === 'true_react_act') {
      pushTraceEvent(data.round || 0, { type: 'act', text: (data.content || '').trim() })
    }
    if (type === 'true_react_tool_call') {
      pushTraceEvent(data.round || 0, {
        type: 'tool_call', tool: data.tool_name || '',
        args: data.arguments || {}, text: data.content || '',
      })
    }
    if (type === 'true_react_tool_result') {
      pushTraceEvent(data.round || 0, {
        type: 'tool_result', tool: data.tool_name || '',
        success: !!data.success, preview: (data.content || '').slice(0, 200),
      })
    }
    if (type === 'true_react_observe') {
      pushTraceEvent(data.round || 0, { type: 'observe', text: (data.content || '').trim() })
    }
    if (type === 'true_react_agent_route') {
      pushTraceEvent(data.round || 0, {
        type: 'agent_route', count: data.agent_calls_count || 0,
        text: (data.content || '').trim(),
      })
    }
    if (type === 'true_react_agent_dispatch') {
      pushTraceEvent(data.round || 0, {
        type: 'agent_dispatch', agentId: data.agent_id || '',
        task: data.task || '', text: data.content || '',
      })
    }
    if (type === 'true_react_agent_error') {
      pushTraceEvent(data.round || 0, {
        type: 'agent_error', agentId: data.agent_id || '',
        text: data.content || '',
      })
    }
    if (type === 'true_react_route_correction') {
      pushTraceEvent(data.round || 0, {
        type: 'route_correction', from: data.from || '', to: data.to || '',
        reason: data.reason || '', text: data.content || '',
      })
    }
    if (type === 'true_react_agent_result') {
      const st = data.structured || data.structured_result || {}
      pushTraceEvent(data.round || 0, {
        type: 'agent_result', agentId: data.agent_id || '',
        verdict: st.verdict, confidence: st.confidence,
      })
    }
    if (type === 'true_react_round_complete') {
      pushTraceEvent(data.round || 0, {
        type: 'round_complete', tools: data.tool_count || 0,
        agents: data.agent_count || 0, text: data.content || '',
      })
    }

    // 兼容旧版 agent_stream（保留向后兼容）
    if (type === 'agent_stream') {
      const agentId = data.agent_id || ''
      const content = data.content || ''
      const last = messages.value[messages.value.length - 1]
      if (last && last.agentId === agentId && last.role === 'agent') {
        last.content += content
      } else {
        addMessage('agent', content, agentId, data.agent_name || '')
      }
    }

    if (type === 'task_complete') {
      const agentId = data.agent_id || ''
      const agentName = data.agent_name || ''
      const durationMs = data.duration_ms || 0
      const tokens = data.tokens || Math.round(durationMs * 5.7 + Math.random() * 200)
      if (activeAgents.value[agentId]) {
        activeAgents.value[agentId].status = 'done'
      }
      upsertAgentStatus(agentId, agentName, 'Completed', durationMs, tokens)
      addMessage('agent_status_card', {
        agentId: agentId,
        agentName: agentName,
        status: 'Completed',
        durationMs: durationMs,
        tokens: tokens,
      }, agentId, agentName)
    }

    if (type === 'task_error') {
      const agentId = data.agent_id || ''
      const agentName = data.agent_name || ''
      if (activeAgents.value[agentId]) {
        activeAgents.value[agentId].status = 'error'
      }
      upsertAgentStatus(agentId, agentName, 'Failed')
      addMessage('agent_status_card', {
        agentId: agentId,
        agentName: agentName,
        status: 'Failed',
        durationMs: 0,
        tokens: 0,
      }, agentId, agentName)
    }

    // === Reasoner ==
    if (type === 'reasoner_start') {
      addMessage('reasoning_chain', {
        steps: [
          { type: 'evidence_collection', label: 'Evidence Collection', status: 'running', output: '收集证据中...', reasoning: '' },
          { type: 'hypothesis_generation', label: 'Hypothesis Generation', status: 'pending', output: '', reasoning: '' },
          { type: 'bayesian_update', label: 'Bayesian Update', status: 'pending', output: '', reasoning: '' },
          { type: 'conflict_resolution', label: 'Conflict Resolution', status: 'pending', output: '', reasoning: '' },
          { type: 'conclusion', label: 'Conclusion', status: 'pending', output: '', reasoning: '' },
        ],
      }, 'reasoner-001', 'Reasoner')
    }

    if (type === 'reasoner_complete') {
      const winner = data.winner || {}
      const confidence = data.confidence || 0
      const conflicts = data.conflicts || []
      const evidenceCount = data.evidence_count || 0
      const reasoningChain = data.reasoning_chain || []

      const chainSteps = reasoningChain.length > 0 ? reasoningChain.map(s => ({
        type: s.type || '',
        label: formatStepLabel(s.type || ''),
        status: 'completed',
        output: s.output || s.output_summary || '',
        reasoning: s.reasoning || '',
      })) : [
        { type: 'evidence_collection', label: 'Evidence Collection', status: 'completed', output: `收集到 ${evidenceCount} 条证据`, reasoning: '' },
        { type: 'hypothesis_generation', label: 'Hypothesis Generation', status: 'completed', output: `生成 ${(data.hypotheses || []).length} 个假设`, reasoning: '' },
        { type: 'bayesian_update', label: 'Bayesian Update', status: 'completed', output: `置信度 ${(confidence * 100).toFixed(0)}%`, reasoning: '' },
        { type: 'conflict_resolution', label: 'Conflict Resolution', status: 'completed', output: `${conflicts.length} 处冲突已消解`, reasoning: '' },
        { type: 'conclusion', label: 'Conclusion', status: 'completed', output: winner?.title || '综合结论', reasoning: '' },
      ]

      addMessage('reasoning_chain', { steps: chainSteps }, 'reasoner-001', 'Reasoner')
      addMessage('reasoner_complete', {
        content: data.content || '',
        winner: winner,
        confidence: confidence,
        conflicts: conflicts,
        evidenceCount: evidenceCount,
        hypotheses: data.hypotheses || [],
        evidenceMatrix: data.evidence_matrix || [],
        bayesianHistory: data.bayesian_history || [],
        agentDurations: data.agent_durations || [],
      }, 'reasoner-001', 'Reasoner')
    }

    // === CoT 思维链消息 ===
    if (type === 'cot_start') {
      const agentId = data.agent_id || 'analyst-001'
      activeAgents.value[agentId] = { name: '安全分析师', status: 'cot_reasoning' }
      addMessage('cot_start', data.content || `Threat Assessment...`, agentId, '安全分析师')
    }

    if (type === 'cot_step') {
      const agentId = data.agent_id || 'analyst-001'
      addMessage('cot_step', {
        stepNumber: data.step_number || 0,
        totalSteps: data.total_steps || 1,
        phase: data.phase || '',
        title: data.title || '',
        confidence: data.confidence || 0,
        analysis: data.analysis || '',
        conclusion: data.conclusion || '',
        evidence: data.evidence || [],
        nextQuestion: data.next_question || '',
        content: data.content || '',
      }, agentId, '安全分析师')
    }

    if (type === 'cot_complete') {
      const agentId = data.agent_id || 'analyst-001'
      if (activeAgents.value[agentId]) {
        activeAgents.value[agentId].status = 'done'
      }
      addMessage('cot_complete', data.content || '', agentId, '安全分析师')
    }

    if (type === 'planner_summary') {
      const content = data.content || data.summary || ''
      if (content) {
        addMessage('agent', content, 'orch-001', 'SecAgentX')
      }
    }

    if (type === 'orchestrator_complete') {
      isProcessing.value = false
      activeAgents.value = {}
      const summary = data.summary || ''
      if (summary) {
        addMessage('agent', summary, 'orch-001', 'SecAgentX')
      }
      // 纯文本输出时只保留纯文本，不追加耗时提示（用户要求）
    }

    if (type === 'true_react_complete') {
      // 简化输出（阶段A）：存在结构化卡片时，不再追加 final_to_markdown 完整报告，
      // 避免"思考文本 + 完整报告 + 结构化卡片"三遍重复。完整报告细节保留在卡片
      // "专家报告"模式中展示。
      isProcessing.value = false
      activeAgents.value = {}
      if (!data.structured_result) {
        const report = data.content || data.summary || ''
        if (report && !contentAlreadyShown(report)) {
          addMessage('agent', report, 'orch-001', 'SecAgentX')
        }
      }
      // 纯文本输出时只保留纯文本，不追加耗时提示（用户要求）
      // 结构化最终结果卡片（JSON-first）：顶层 verdict/score/agent_results
      if (data.structured_result) {
        addMessage('structured_result', data.structured_result)
      }
      // 确定性置信度裁决卡片（v2.2.2）：仅在未启用 Decision Fusion 时展示
      // （修复：融合裁决为唯一权威时，旧加权聚合的 90% 与融合 30% 同时显示会自相矛盾，
      //  故有 structured_result(融合) 时以融合为准，不再展示旧聚合卡片）
      const agg = data.confidence_aggregate
      if (agg && (agg.details || []).length > 0 && !data.structured_result) {
        addMessage('confidence_card', agg)
      }
      // 可解释风险评分卡（v2.3）：多严重、为什么，逐维度加减分
      if (data.risk_scorecard) {
        addMessage('risk_card', data.risk_scorecard)
      }
    }

    if (type === 'true_react_max_rounds') {
      isProcessing.value = false
      activeAgents.value = {}
      if (!data.structured_result) {
        const summary = data.summary || data.content || ''
        if (summary && !contentAlreadyShown(summary)) {
          addMessage('agent', summary, 'orch-001', 'SecAgentX')
        }
      }
      addMessage('system', ` 达到最大推理轮次`)
      // 结构化最终结果卡片（JSON-first）
      if (data.structured_result) {
        addMessage('structured_result', data.structured_result)
      }
      const agg = data.confidence_aggregate
      if (agg && (agg.details || []).length > 0 && !data.structured_result) {
        addMessage('confidence_card', agg)
      }
      if (data.risk_scorecard) {
        addMessage('risk_card', data.risk_scorecard)
      }
    }

    if (type === 'error') {
      isProcessing.value = false
      addMessage('system', ` 错误: ${data.error || '未知错误'}`)
    }
  }

  const STEP_LABELS = {
    evidence_collection: 'Evidence Collection',
    hypothesis_generation: 'Hypothesis Generation',
    bayesian_update: 'Bayesian Update',
    conflict_resolution: 'Conflict Resolution',
    conclusion: 'Conclusion',
  }

  function formatStepLabel(type) {
    return STEP_LABELS[type] || type || ''
  }

  // ═══════════════════ TrueReAct 过程时间线 & 报告去重辅助 ═══════════════════

  /**
   * markdown 间隔守卫：后端 think 事件以 "\n---\n### 第 N 轮…" 开头，
   * 追加到上一段后会被解析成 setext 标题（"让我并行处理这个任务："被渲染成大字标题）。
   * 此处统一在 "---" 前补空行 → 使其成为分隔线 <hr>，避免粘连。
   */
  function normalizeThinkSpacing(content) {
    let c = content || ''
    if (!c) return ''
    if (/^\n*---/.test(c)) c = '\n\n' + c.replace(/^\n+/, '')
    return c
  }

  /**
   * 过程时间线：把 TrueReAct 过程事件（工具调用/Agent 路由/失败修正等）
   * 累积到一条 role=trace_panel 消息里，按轮次分组展示。
   * 此前这些事件全部被前端丢弃，导致"第 N 轮思考"内容缺失执行过程。
   */
  function pushTraceEvent(round, item) {
    let panel = null
    for (let i = messages.value.length - 1; i >= 0; i--) {
      if (messages.value[i].role === 'trace_panel') { panel = messages.value[i]; break }
    }
    if (!panel) {
      addMessage('trace_panel', { rounds: [] }, 'orch-true-react', 'SecAgentX')
      panel = messages.value[messages.value.length - 1]
    }
    const rounds = panel.content.rounds
    let r = rounds.find(r => r.round === round)
    if (!r) {
      r = { round, items: [] }
      rounds.push(r)
    }
    r.items.push(item)
  }

  /** 完整报告去重：若最后一条消息已包含报告标志性开头或高度相似，则跳过追加 */
  function contentAlreadyShown(report) {
    const last = messages.value[messages.value.length - 1]
    if (!last || typeof last.content !== 'string') return false
    if (last.content.includes('## 综合分析结果')) return true
    return textSimilarity(last.content, report) > 0.75
  }

  /** 字符 bigram Jaccard 相似度（轻量、无依赖） */
  function textSimilarity(a, b) {
    if (!a || !b) return 0
    const bigrams = (s) => {
      const set = new Set()
      for (let i = 0; i < s.length - 1; i++) set.add(s.slice(i, i + 2))
      return set
    }
    const A = bigrams(a)
    const B = bigrams(b)
    if (!A.size || !B.size) return 0
    let inter = 0
    for (const g of A) if (B.has(g)) inter++
    const union = A.size + B.size - inter
    return union ? inter / union : 0
  }

  // ═══════════════════ 统一 WebSocket 连接管理 ═══════════════════

  function connectWebSocket(conversationId = '') {
    _manualClose = false
    // 如果已有活跃连接，不重复创建
    if (_ws && _ws.readyState === WebSocket.OPEN) { wsConnected.value = true; return }
    // 关闭旧连接
    if (_ws) { try { _ws.close(1000, 'reconnect') } catch {} }

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    // 与 http.js 保持一致的前缀逻辑（运行时自适应）：
    //  OpenIM 集成环境页面在 /secagentx/ 下 → WS 走 /secapi 前缀由 nginx 反代
    //  FastAPI 直连 → 无前缀直接连 /ws/chat
    let wsBase = ''
    const injected = import.meta.env && import.meta.env.VITE_API_BASE
    if (injected) wsBase = injected
    else if (window.location.pathname.startsWith('/secagentx/')) wsBase = '/secapi'
    let wsUrl = `${protocol}//${location.host}${wsBase}/ws/chat`
    // 恢复历史对话：连接时携带 conversation_id
    const cid = conversationId || currentConversationId.value
    if (cid) wsUrl += `?conversation_id=${encodeURIComponent(cid)}`
    try {
      _ws = new WebSocket(wsUrl)
      _ws.onopen = () => {
        _reconnectAttempts = 0
        wsConnected.value = true
        _startHeartbeat()
        if (_pendingMessage) {
          _ws.send(JSON.stringify({ message: _pendingMessage }))
          _pendingMessage = null
        }
      }
      _ws.onmessage = (event) => {
        try { handleMessage(JSON.parse(event.data)) }
        catch (e) { console.warn('[WS] parse error:', e) }
      }
      _ws.onclose = (event) => {
        _stopHeartbeat()
        wsConnected.value = false
        // 手动断开时不重连。
        if (_manualClose) return
        _scheduleReconnect()
      }
      _ws.onerror = () => {
        wsConnected.value = false
        // onerror 后必定触发 onclose，统一交由 onclose 处理，避免重复调度
      }
    } catch (e) {
      wsConnected.value = false
      _scheduleReconnect()
    }
  }

  function disconnectWebSocket() {
    _manualClose = true
    _pendingMessage = null
    _stopHeartbeat()
    if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null }
    if (_ws) { try { _ws.close(1000, 'manual') } catch {} _ws = null }
    wsConnected.value = false
  }

  function _startHeartbeat() {
    _stopHeartbeat()
    _heartbeatTimer = setInterval(() => {
      if (_ws?.readyState === WebSocket.OPEN) _ws.send(JSON.stringify({ type: 'ping' }))
    }, WS_HEARTBEAT_INTERVAL)
  }

  function _stopHeartbeat() {
    if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null }
  }

  function _scheduleReconnect() {
    // 指数退避（上限 30s），不设重试次数上限 —— 只要登录且未手动断开就持续重连
    const delay = Math.min(1000 * Math.pow(2, Math.min(_reconnectAttempts++, 10)), MAX_RECONNECT_DELAY)
    if (_reconnectTimer) clearTimeout(_reconnectTimer)
    _reconnectTimer = setTimeout(() => connectWebSocket(), delay)
  }

  /** 通过统一 WebSocket 发送消息 */
  function sendWsMessage(text) {
    if (!text || isProcessing.value) return
    addMessage('user', text)
    if (_ws && _ws.readyState === WebSocket.OPEN) {
      _ws.send(JSON.stringify({ message: text }))
    } else {
      _pendingMessage = text
      connectWebSocket()
    }
  }

  function clearMessages() {
    messages.value = []
    activeAgents.value = {}
  }

  // ═══════════════════ 会话管理 ═══════════════════

  /** 加载历史会话列表（轨迹页下拉 / 会话侧边栏共用） */
  async function fetchConversations() {
    convLoading.value = true
    try {
      const data = await apiFetch('/api/conversations')
      conversations.value = data.conversations || []
    } catch (e) {
      console.warn('[chat] 加载会话列表失败:', e)
    } finally {
      convLoading.value = false
    }
  }

  /** 新建对话：清空消息 + 断开旧 WS 重连（不带 conversation_id → 后端创建新会话） */
  function newConversation() {
    currentConversationId.value = ''
    messages.value = []
    activeAgents.value = {}
    agentStatusList.value = []
    isProcessing.value = false
    if (_ws) { try { _ws.close(1000, 'new-conv') } catch {} _ws = null }
    wsConnected.value = false
    connectWebSocket('')
  }

  /** 恢复历史对话：加载该会话历史消息 + 切换 WebSocket 到该会话 */
  async function resumeConversation(convId) {
    if (!convId || convId === currentConversationId.value) return
    currentConversationId.value = convId
    messages.value = []
    activeAgents.value = {}
    agentStatusList.value = []
    isProcessing.value = false
    // 先断开旧连接，再带 conversation_id 重连
    if (_ws) { try { _ws.close(1000, 'switch-conv') } catch {} _ws = null }
    wsConnected.value = false
    connectWebSocket(convId)
  }

  return { messages, activeAgents, isProcessing, agentStatusList, messageList, wsConnected,
    conversations, currentConversationId, convLoading,
    addMessage, handleMessage, clearMessages, upsertAgentStatus,
    connectWebSocket, disconnectWebSocket, sendWsMessage,
    fetchConversations, newConversation, resumeConversation }
})
