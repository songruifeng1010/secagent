/**
 * ChatStore 单元测试
 *
 * 覆盖范围:
 *   - WebSocket 消息处理 (25+ 消息类型)
 *   - 消息增删
 *   - Agent 状态跟踪
 *   - 处理状态管理
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useChatStore } from '../stores/chat.js'

describe('ChatStore', () => {
  let store

  beforeEach(() => {
    setActivePinia(createPinia())
    store = useChatStore()
  })

  // ─── 基本消息 ───
  it('should add user messages', () => {
    store.addMessage('user', '测试消息')
    expect(store.messages).toHaveLength(1)
    expect(store.messages[0].role).toBe('user')
    expect(store.messages[0].content).toBe('测试消息')
    expect(store.messages[0].id).toBeTruthy()
    expect(store.messages[0].timestamp).toBeTruthy()
  })

  it('should add agent messages', () => {
    store.addMessage('agent', '分析结果', 'intel-001', '威胁情报员')
    expect(store.messages).toHaveLength(1)
    expect(store.messages[0].role).toBe('agent')
    expect(store.messages[0].agentId).toBe('intel-001')
    expect(store.messages[0].agentName).toBe('威胁情报员')
  })

  it('should clear all messages', () => {
    store.addMessage('user', 'msg1')
    store.addMessage('agent', 'msg2')
    store.clearMessages()
    expect(store.messages).toHaveLength(0)
    expect(store.activeAgents).toEqual({})
  })

  // ─── 处理状态 ───
  it('should set processing state on orchestrator_start', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    expect(store.isProcessing).toBe(true)
  })

  it('should clear processing state on orchestrator_complete', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    expect(store.isProcessing).toBe(true)
    store.handleMessage({ type: 'orchestrator_complete', total_duration_ms: 1500 })
    expect(store.isProcessing).toBe(false)
    expect(store.activeAgents).toEqual({})
    // 完成事件不再追加重复的耗时系统消息。
    expect(store.messages).toHaveLength(0)
  })

  it('should handle true_react_complete', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    store.handleMessage({ type: 'true_react_complete', total_duration_ms: 2000 })
    expect(store.isProcessing).toBe(false)
    expect(store.activeAgents).toEqual({})
    // 无正文/结构化结果时仅结束处理状态，不制造空消息。
    expect(store.messages).toHaveLength(0)
  })

  // ─── 结构化最终结果卡片 (JSON-first, v2.4) ───
  it('should render structured_result when present on complete', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    const sr = {
      status: 'completed',
      conversation_id: 'abc123',
      rounds: 3,
      needs_human: false,
      summary_text: '检测到暴力破解',
      score: 85,
      verdict: { verdict: 'malicious', confidence: 0.85, risk_level: '高危', recommended_action: 'block' },
      agent_results: [
        { agent_id: 'analyst-001', agent_name: '安全分析师', verdict: 'malicious', confidence: 0.85, status: 'success', degraded: false },
      ],
    }
    store.handleMessage({ type: 'true_react_complete', total_duration_ms: 2000, structured_result: sr })
    expect(store.isProcessing).toBe(false)
    const card = store.messages.find(m => m.role === 'structured_result')
    expect(card).toBeTruthy()
    expect(card.content.score).toBe(85)
    expect(card.content.verdict.verdict).toBe('malicious')
    expect(card.content.summary_text).toContain('暴力破解')
    expect(card.content.agent_results.length).toBe(1)
  })

  it('should preserve decision_path in structured_result (v2.4 fusion)', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    const sr = {
      status: 'completed',
      conversation_id: 'fusion123',
      score: 85,
      verdict: { verdict: 'malicious', confidence: 0.95, risk_level: '高危', recommended_action: 'block' },
      decision_path: [
        { step: 1, desc: '收集 安全分析师 证据：SSH暴力破解', tag: 'evidence' },
        { step: 2, desc: 'Dempster 融合：恶意信念 95%', tag: 'fusion' },
        { step: 3, desc: '最终裁决：malicious', tag: 'decision' },
      ],
      fusion_result: {
        engine: 'dempster_shafer',
        conflicts: [
          { between: 'analyst-001 vs intel-001', coefficient: 0.0, resolution: '取信念较高者' },
        ],
      },
      agent_results: [],
    }
    store.handleMessage({ type: 'true_react_complete', total_duration_ms: 2000, structured_result: sr })
    const card = store.messages.find(m => m.role === 'structured_result')
    expect(card).toBeTruthy()
    expect(card.content.decision_path.length).toBe(3)
    expect(card.content.decision_path[1].desc).toContain('Dempster 融合')
    expect(card.content.fusion_result.engine).toBe('dempster_shafer')
    expect(card.content.fusion_result.conflicts.length).toBe(1)
  })

  it('should render structured_result on max_rounds when present', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    const sr = {
      status: 'max_rounds',
      conversation_id: 'def456',
      rounds: 8,
      needs_human: true,
      score: 40,
      verdict: { verdict: 'suspicious', confidence: 0.45, risk_level: '中危', recommended_action: 'escalate' },
      agent_results: [],
    }
    store.handleMessage({ type: 'true_react_max_rounds', summary: '', structured_result: sr })
    const card = store.messages.find(m => m.role === 'structured_result')
    expect(card).toBeTruthy()
    expect(card.content.status).toBe('max_rounds')
    expect(card.content.needs_human).toBe(true)
  })

  // ─── 确定性置信度裁决卡片 (v2.2.2) ───
  it('should render confidence_card when aggregate present', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    const agg = {
      confidence: 0.425,
      verdict: 'suspicious',
      needs_human: false,
      coverage: 0.25,
      details: [
        { agent_id: 'analyst-001', weight: 0.35, confidence: 0.65, verdict: 'malicious', degraded: false, failed: false },
        { agent_id: 'intel-001', weight: 0.25, confidence: 0.35, verdict: 'suspicious', degraded: true, failed: false },
      ],
    }
    store.handleMessage({ type: 'true_react_complete', total_duration_ms: 2000, confidence_aggregate: agg })
    expect(store.isProcessing).toBe(false)

    const card = store.messages.find(m => m.role === 'confidence_card')
    expect(card).toBeTruthy()
    expect(card.content.confidence).toBe(0.425)
    expect(card.content.verdict).toBe('suspicious')
    expect(card.content.coverage).toBe(0.25)
    expect(card.content.details.length).toBe(2)
    // 降级 Agent 应被标注（P1-3：失败/降级不掩盖）
    expect(card.content.details[1].degraded).toBe(true)
  })

  it('should not render confidence_card when aggregate absent', () => {
    store.handleMessage({ type: 'true_react_complete', total_duration_ms: 2000 })
    expect(store.messages.find(m => m.role === 'confidence_card')).toBeFalsy()
  })

  it('should suppress legacy confidence_card when fusion structured_result present', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    const agg = {
      confidence: 0.9, verdict: 'malicious', needs_human: false, coverage: 1.0,
      details: [{ agent_id: 'knowledge-001', weight: 0.10, confidence: 0.9, verdict: 'malicious', degraded: false, failed: false }],
    }
    const sr = {
      status: 'completed', conversation_id: 'f1', score: 50,
      verdict: { verdict: 'unknown', confidence: 0.3, risk_level: '中危', recommended_action: 'monitoring' },
      agent_results: [],
    }
    store.handleMessage({ type: 'true_react_complete', total_duration_ms: 2000, confidence_aggregate: agg, structured_result: sr })
    expect(store.messages.find(m => m.role === 'confidence_card')).toBeFalsy()
    expect(store.messages.find(m => m.role === 'structured_result')).toBeTruthy()
  })

  // ─── 可解释风险评分卡 (v2.3) ───
  it('should render risk_card when scorecard present on complete', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    const sc = {
      risk_score: -10,
      risk_level: '低危',
      needs_human: false,
      dimensions: [
        { name: '行为证据', delta: 35, reason: '分析师确认恶意行为（置信度 85%）', rule_id: 'RULE-BEH-01', tag: 'pos' },
        { name: '威胁情报', delta: 10, reason: '威胁情报显示可疑', rule_id: 'RULE-INTEL-03', tag: 'pos' },
        { name: 'IP真实性', delta: -50, reason: '源IP 10.0.0.5 为私有/保留地址', rule_id: 'RULE-IP-02', tag: 'neg' },
        { name: '历史信誉', delta: -5, reason: '无历史记录', rule_id: 'RULE-REP-04', tag: 'neg' },
      ],
      rules_hit: ['RULE-BEH-01', 'RULE-INTEL-03', 'RULE-IP-02', 'RULE-REP-04'],
      summarized: '行为证据 +35，威胁情报 +10，IP真实性 -50，历史信誉 -5，最终 -10（低危）',
    }
    store.handleMessage({ type: 'true_react_complete', total_duration_ms: 2000, risk_scorecard: sc })
    expect(store.isProcessing).toBe(false)

    const card = store.messages.find(m => m.role === 'risk_card')
    expect(card).toBeTruthy()
    expect(card.content.risk_score).toBe(-10)
    expect(card.content.risk_level).toBe('低危')
    expect(card.content.dimensions).toHaveLength(4)
    expect(card.content.rules_hit).toContain('RULE-BEH-01')
  })

  it('should render risk_card on max_rounds when scorecard present', () => {
    store.handleMessage({ type: 'true_react_start' })
    const sc = { risk_score: 70, risk_level: '高危', needs_human: false, dimensions: [], rules_hit: [], summarized: '' }
    store.handleMessage({ type: 'true_react_max_rounds', summary: '达到最大轮次', risk_scorecard: sc })
    expect(store.messages.find(m => m.role === 'risk_card')).toBeTruthy()
  })

  it('should not render risk_card when scorecard absent', () => {
    store.handleMessage({ type: 'true_react_complete', total_duration_ms: 2000 })
    expect(store.messages.find(m => m.role === 'risk_card')).toBeFalsy()
  })

  it('should handle errors', () => {
    store.handleMessage({ type: 'error', error: 'API 超时' })
    expect(store.isProcessing).toBe(false)
    const lastMsg = store.messages[store.messages.length - 1]
    expect(lastMsg.role).toBe('system')
    expect(lastMsg.content).toContain('API 超时')
  })

  // ─── Agent 状态管理 ───
  it('should track agent status on task_start', () => {
    store.handleMessage({
      type: 'task_start',
      agent_id: 'analyst-001',
      agent_name: '安全分析师',
    })
    expect(store.activeAgents['analyst-001']).toBeTruthy()
    expect(store.activeAgents['analyst-001'].status).toBe('running')
    expect(store.activeAgents['analyst-001'].name).toBe('安全分析师')
  })

  it('should mark agent done on task_complete', () => {
    store.handleMessage({ type: 'task_start', agent_id: 'intel-001', agent_name: '威胁情报员' })
    expect(store.activeAgents['intel-001'].status).toBe('running')
    store.handleMessage({ type: 'task_complete', agent_id: 'intel-001', agent_name: '威胁情报员', duration_ms: 320 })
    expect(store.activeAgents['intel-001'].status).toBe('done')
  })

  it('should mark agent error on task_error', () => {
    store.handleMessage({ type: 'task_start', agent_id: 'intel-001', agent_name: '威胁情报员' })
    store.handleMessage({ type: 'task_error', agent_id: 'intel-001', agent_name: '威胁情报员' })
    expect(store.activeAgents['intel-001'].status).toBe('error')
  })

  // ─── 流式消息 ───
  it('should append streaming content to last agent message', () => {
    store.addMessage('agent', '初始', 'orch-001', 'SecAgentX')
    store.handleMessage({ type: 'stream', agent_id: 'orch-001', content: '追加内容' })
    expect(store.messages[0].content).toBe('初始追加内容')
  })

  it('should create new message if no matching agent message for stream', () => {
    store.handleMessage({ type: 'stream', agent_id: 'orch-001', content: '新流内容' })
    const msgs = store.messages.filter(m => m.role === 'agent' && m.agentId === 'orch-001')
    expect(msgs.length).toBeGreaterThanOrEqual(1)
  })

  // ─── TrueReAct 思考（按轮进入过程时间线，不截断） ───
  it('should put think_content into trace_panel by round without truncation', () => {
    store.handleMessage({ type: 'true_react_think', round: 1, content: '\n---\n###  第 1 轮 — 指挥官思考决策\n' })
    store.handleMessage({ type: 'true_react_think_content', round: 1, content: '本轮思考：先查 CVE 再路由知识智能体。' })
    // 轮次标题事件（true_react_think）不产生消息
    expect(store.messages.filter(m => m.role === 'agent')).toHaveLength(0)
    // 思考内容进入 trace_panel，按轮分组
    const panel = store.messages.find(m => m.role === 'trace_panel')
    expect(panel).toBeTruthy()
    expect(panel.content.rounds).toHaveLength(1)
    expect(panel.content.rounds[0].round).toBe(1)
    const thinkItem = panel.content.rounds[0].items.find(i => i.type === 'think')
    expect(thinkItem).toBeTruthy()
    // 完整内容不截断
    expect(thinkItem.text).toBe('本轮思考：先查 CVE 再路由知识智能体。')
  })

  it('should keep full multi-round think text in trace (no slice truncation)', () => {
    const longThink = '本轮思考：'.repeat(100)   // 超过旧 800 字截断阈值
    store.handleMessage({ type: 'true_react_think_content', round: 1, content: longThink })
    const panel = store.messages.find(m => m.role === 'trace_panel')
    const thinkItem = panel.content.rounds[0].items.find(i => i.type === 'think')
    expect(thinkItem.text.length).toBe(longThink.length)  // 完整保留，无截断
  })

  // ─── TrueReAct 过程时间线 (v2.5) ───
  it('should accumulate trace events into a single trace_panel grouped by round', () => {
    store.handleMessage({ type: 'true_react_act', round: 1, content: '  决定执行 2 个操作' })
    store.handleMessage({ type: 'true_react_tool_call', round: 1, tool_name: 'cve_search', arguments: { query: 'openssh' } })
    store.handleMessage({ type: 'true_react_tool_result', round: 1, tool_name: 'cve_search', success: true, content: '  [OK] **cve_search**\n```json\n{}\n```' })
    store.handleMessage({ type: 'true_react_agent_dispatch', round: 1, agent_id: 'knowledge-001', task: '查询SSH加固' })
    store.handleMessage({ type: 'true_react_agent_result', round: 1, agent_id: 'knowledge-001', structured: { verdict: 'unknown', confidence: 0.35 } })
    store.handleMessage({ type: 'true_react_agent_error', round: 2, agent_id: 'intel-001' })
    store.handleMessage({ type: 'true_react_route_correction', round: 2, from: 'analyst-001', to: 'knowledge-001', reason: '能力不匹配' })

    const panels = store.messages.filter(m => m.role === 'trace_panel')
    expect(panels).toHaveLength(1)
    const rounds = panels[0].content.rounds
    expect(rounds).toHaveLength(2)
    const r1Types = rounds[0].items.map(i => i.type)
    expect(r1Types).toContain('act')
    expect(r1Types).toContain('tool_call')
    expect(r1Types).toContain('tool_result')
    expect(r1Types).toContain('agent_dispatch')
    expect(r1Types).toContain('agent_result')
    expect(rounds[1].items[0].type).toBe('agent_error')
    expect(rounds[1].items[1].type).toBe('route_correction')
    expect(rounds[1].items[1].from).toBe('analyst-001')
  })

  it('should ignore non-trace process events that are already handled', () => {
    // true_react_observe / round_complete 也应进入时间线
    store.handleMessage({ type: 'true_react_observe', round: 1, content: '  第1轮 — 工具执行结果' })
    store.handleMessage({ type: 'true_react_round_complete', round: 1, tool_count: 1, agent_count: 0, content: '第 1 轮完成' })
    const panels = store.messages.filter(m => m.role === 'trace_panel')
    expect(panels).toHaveLength(1)
    const items = panels[0].content.rounds[0].items
    expect(items.map(i => i.type)).toContain('observe')
    expect(items.map(i => i.type)).toContain('round_complete')
  })

  // ─── 完整报告展示 (v2.5) ───
  it('should append full report on true_react_complete', () => {
    store.handleMessage({ type: 'orchestrator_start' })
    const report = '## 综合分析结果\n\n**状态**: 分析完成\n\n### 最终判定\n- **判定**: unknown'
    store.handleMessage({ type: 'true_react_complete', content: report, total_duration_ms: 2000 })
    const agentMsgs = store.messages.filter(m => m.role === 'agent' && m.agentId === 'orch-001')
    expect(agentMsgs).toHaveLength(1)
    expect(agentMsgs[0].content).toContain('## 综合分析结果')
  })

  it('should not duplicate report when last message already contains it', () => {
    store.addMessage('agent', '## 综合分析结果\n\n已有报告', 'orch-001', 'SecAgentX')
    store.handleMessage({ type: 'true_react_complete', content: '## 综合分析结果\n\n新报告', total_duration_ms: 1000 })
    const agentMsgs = store.messages.filter(m => m.role === 'agent' && m.agentId === 'orch-001')
    expect(agentMsgs).toHaveLength(1)
  })

  // ─── Reasoner ───
  it('should create reasoning chain on reasoner_start', () => {
    store.handleMessage({ type: 'reasoner_start' })
    const chainMsgs = store.messages.filter(m => m.role === 'reasoning_chain')
    expect(chainMsgs.length).toBe(1)
    const steps = chainMsgs[0].content.steps
    expect(steps).toHaveLength(5)
    expect(steps[0].label).toBe('Evidence Collection')
    expect(steps[0].status).toBe('running')
    expect(steps[4].label).toBe('Conclusion')
    expect(steps[4].status).toBe('pending')
  })

  it('should complete reasoning chain on reasoner_complete', () => {
    store.handleMessage({ type: 'reasoner_start' })
    store.handleMessage({
      type: 'reasoner_complete',
      winner: { title: '恶意行为' },
      confidence: 0.87,
      conflicts: [{ id: 1 }],
      evidence_count: 5,
      reasoning_chain: [
        { type: 'evidence_collection', output_summary: '收集5条证据' },
        { type: 'bayesian_update', output_summary: '后验87%' },
      ],
    })
    const chainMsgs = store.messages.filter(m => m.role === 'reasoning_chain')
    expect(chainMsgs.length).toBe(2)
    const lastSteps = chainMsgs[chainMsgs.length - 1].content.steps
    lastSteps.forEach(s => expect(s.status).toBe('completed'))
  })

  // ─── Intent/Analysis Result ───
  it('should create analysis_result message on intent', () => {
    store.handleMessage({
      type: 'intent',
      intent: { primary_intent: 'INVESTIGATE', urgency: 'HIGH', confidence: 0.85, entities: { ips: ['1.2.3.4'] } },
    })
    const analysisMsgs = store.messages.filter(m => m.role === 'analysis_result')
    expect(analysisMsgs.length).toBe(1)
    expect(analysisMsgs[0].content.intent).toBe('INVESTIGATE')
    expect(analysisMsgs[0].content.severity).toBe('HIGH')
  })

  // ─── Agent 状态列表跟踪 ───
  it('should upsert agent status in list', () => {
    store.upsertAgentStatus('analyst-001', '安全分析师', 'Running', 0, 0)
    expect(store.agentStatusList).toHaveLength(1)
    expect(store.agentStatusList[0].status).toBe('Running')

    store.upsertAgentStatus('analyst-001', '安全分析师', 'Completed', 150, 800)
    expect(store.agentStatusList).toHaveLength(1)
    expect(store.agentStatusList[0].status).toBe('Completed')
    expect(store.agentStatusList[0].durationMs).toBe(150)
    expect(store.agentStatusList[0].tokens).toBe(800)
  })

  // ─── CoT 思维链 ───
  it('should handle cot_start message', () => {
    store.handleMessage({ type: 'cot_start', agent_id: 'analyst-001', content: 'Threat Assessment...' })
    const cotMsgs = store.messages.filter(m => m.role === 'cot_start')
    expect(cotMsgs.length).toBe(1)
    expect(cotMsgs[0].content).toBe('Threat Assessment...')
    expect(store.activeAgents['analyst-001']).toBeTruthy()
  })

  it('should handle cot_step message', () => {
    store.handleMessage({
      type: 'cot_step',
      agent_id: 'analyst-001',
      step_number: 1,
      total_steps: 3,
      title: 'Initial Analysis',
      confidence: 0.65,
      analysis: '正在分析...',
    })
    const stepMsgs = store.messages.filter(m => m.role === 'cot_step')
    expect(stepMsgs.length).toBe(1)
    expect(stepMsgs[0].content.stepNumber).toBe(1)
    expect(stepMsgs[0].content.confidence).toBe(0.65)
  })

  it('should handle cot_complete message', () => {
    store.handleMessage({ type: 'cot_start', agent_id: 'analyst-001' })
    store.handleMessage({ type: 'cot_complete', agent_id: 'analyst-001', content: '分析完成' })
    expect(store.activeAgents['analyst-001'].status).toBe('done')
    const completeMsgs = store.messages.filter(m => m.role === 'cot_complete')
    expect(completeMsgs.length).toBe(1)
    expect(completeMsgs[0].content).toBe('分析完成')
  })

  // ─── Planner / TrueReAct 摘要 ───
  it('should handle planner_summary message', () => {
    store.handleMessage({ type: 'planner_summary', content: '计划摘要' })
    const agentMsgs = store.messages.filter(m => m.role === 'agent' && m.agentId === 'orch-001')
    expect(agentMsgs.length).toBe(1)
    expect(agentMsgs[0].content).toBe('计划摘要')
  })

  it('should handle true_react_max_rounds message', () => {
    store.handleMessage({ type: 'true_react_start' })
    store.handleMessage({ type: 'true_react_max_rounds', summary: '达到最大轮次' })
    expect(store.isProcessing).toBe(false)
    const lastMsg = store.messages[store.messages.length - 1]
    expect(lastMsg.content).toContain('最大推理轮次')
  })

  // ─── 向后兼容 ───
  it('should handle legacy agent_stream message', () => {
    store.addMessage('agent', '旧数据', 'legacy-agent')
    store.handleMessage({ type: 'agent_stream', agent_id: 'legacy-agent', content: '+追加' })
    expect(store.messages[0].content).toBe('旧数据+追加')
  })
})
