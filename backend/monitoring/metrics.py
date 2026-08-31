"""
SecAgentX Prometheus 监控指标

暴露指标端点: GET /api/metrics
对接 Grafana 面板实现可观测性。

指标清单:
  - secagentx_alerts_total        (Counter)  按action分: 告警总数
  - secagentx_blocks_total        (Counter)  按backend分: 封禁总数
  - secagentx_llm_duration_ms     (Histogram) LLM调用延迟
  - secagentx_active_blocks       (Gauge)    当前活跃封禁数
  - secagentx_circuit_breaker     (Gauge)    熔断器状态
  - secagentx_agent_status        (Gauge)    各Agent状态
  - secagentx_queue_size          (Gauge)    告警队列大小
"""
import logging
from functools import wraps

logger = logging.getLogger("secagentx.metrics")

# 尝试导入 prometheus_client，失败则以空实现代替
try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False
    logger.info("prometheus_client 未安装，指标模块以 no-op 模式运行")
    logger.info("  pip install prometheus-client  # 启用监控")

    # 空实现
    class _NoopMetric:
        def __init__(self, *args, **kwargs): pass
        def labels(self, **kwargs): return self
        def inc(self, n=1): pass
        def observe(self, n): pass
        def set(self, n): pass

    Counter = Histogram = Gauge = _NoopMetric
    def generate_latest(): return b""
    REGISTRY = None


# ═══════════════════════ 定义指标 ═══════════════════════

# 告警处理总数（按处置动作分类）
alerts_processed = Counter(
    "secagentx_alerts_total",
    "处理的告警总数",
    ["action"],  # auto_closed, auto_blocked, escalated, monitoring, error
)

# 封禁操作总数（按后端类型分类）
block_operations = Counter(
    "secagentx_blocks_total",
    "封禁操作总数",
    ["backend"],  # mock, iptables, nftables, aliyun, aws
)

# LLM 调用延迟分布
llm_latency = Histogram(
    "secagentx_llm_duration_ms",
    "LLM 调用延迟分布 (ms)",
    buckets=[100, 200, 500, 1000, 2000, 3000, 5000, 10000],
)

# 当前活跃封禁数
active_blocks = Gauge(
    "secagentx_active_blocks",
    "当前活跃封禁 IP 数量",
)

# 熔断器状态（0=closed, 1=open, 2=half_open）
circuit_breaker_state = Gauge(
    "secagentx_circuit_breaker",
    "熔断器状态: 0=closed, 1=open, 2=half_open",
    ["state"],
)

# Agent 状态（0=idle, 1=busy, 2=error）
agent_status = Gauge(
    "secagentx_agent_status",
    "Agent 运行状态: 0=idle, 1=busy, 2=error",
    ["agent_id", "agent_name"],
)

# 告警队列大小
queue_size = Gauge(
    "secagentx_queue_size",
    "当前告警队列中待处理的消息数",
)

# ═══════════════════════ 业务可观测性增强（v2.2.2） ═══════════════════════
# Agent 调用量（监控多智能体工作负载）
agent_calls = Counter(
    "secagentx_agent_calls_total",
    "Agent 被调用的总次数",
    ["agent_id"],  # analyst-001, intel-001, ...
)

# 工具调用量（监控工具使用分布）
tool_calls = Counter(
    "secagentx_tool_calls_total",
    "工具被调用的总次数",
    ["tool_name", "success"],  # threat_intel, geoip, firewall_manage, ...
)

# 对话轮次（TrueReAct 分析轮数分布）
conversation_rounds = Histogram(
    "secagentx_conversation_rounds",
    "TrueReAct 分析使用的轮数",
    buckets=(1, 2, 3, 4, 5, 6, 7, 8),
)

http_requests = Counter(
    "secagentx_http_requests_total",
    "HTTP 请求总数",
    ["method", "route", "status"],
)

http_duration = Histogram(
    "secagentx_http_request_duration_seconds",
    "HTTP 请求耗时（秒）",
    ["method", "route"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)


def record_alert(action: str):
    """记录一次告警处理"""
    if HAS_PROMETHEUS:
        alerts_processed.labels(action=action).inc()


def record_block(backend: str = "disabled"):
    """记录一次封禁操作"""
    if HAS_PROMETHEUS:
        block_operations.labels(backend=backend).inc()


def record_llm_latency(duration_ms: float):
    """记录 LLM 调用延迟"""
    if HAS_PROMETHEUS:
        llm_latency.observe(duration_ms)


def set_active_blocks(count: int):
    """设置活跃封禁数"""
    if HAS_PROMETHEUS:
        active_blocks.set(count)


def set_circuit_breaker(state: str):
    """设置熔断器状态"""
    if HAS_PROMETHEUS:
        state_map = {"closed": 0, "open": 1, "half_open": 2}
        val = state_map.get(state, 0)
        for s in ["closed", "open", "half_open"]:
            circuit_breaker_state.labels(state=s).set(1 if s == state else 0)


def set_agent_status(agent_id: str, agent_name: str, status: str):
    """设置 Agent 状态"""
    if HAS_PROMETHEUS:
        status_map = {"idle": 0, "busy": 1, "error": 2, "unknown": 0}
        val = status_map.get(status, 0)
        agent_status.labels(agent_id=agent_id, agent_name=agent_name).set(val)


def record_agent_call(agent_id: str):
    """记录一次 Agent 调用"""
    if HAS_PROMETHEUS:
        agent_calls.labels(agent_id=agent_id).inc()


def record_tool_call(tool_name: str, success: bool = True):
    """记录一次工具调用"""
    if HAS_PROMETHEUS:
        tool_calls.labels(tool_name=tool_name, success=str(success).lower()).inc()


def record_conversation_rounds(rounds: int):
    """记录一次 TrueReAct 对话轮数"""
    if HAS_PROMETHEUS:
        conversation_rounds.observe(rounds)


def record_http_request(method: str, route: str, status: int, duration_seconds: float):
    """记录低基数路由模板的 HTTP 数量和延迟。"""
    if HAS_PROMETHEUS:
        http_requests.labels(method=method, route=route, status=str(status)).inc()
        http_duration.labels(method=method, route=route).observe(duration_seconds)


def set_queue_size(size: int):
    """设置队列大小"""
    if HAS_PROMETHEUS:
        queue_size.set(size)


def get_metrics() -> bytes:
    """获取 Prometheus 格式的指标数据"""
    if not HAS_PROMETHEUS:
        return b"# prometheus_client not installed\n"
    return generate_latest(REGISTRY)
