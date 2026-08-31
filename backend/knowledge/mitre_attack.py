import json
import os
import threading
from typing import Optional
from collections import defaultdict

KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge_data")

# 模块级缓存 + 刷新锁
_mitre_cache = {"data": None, "lock": threading.Lock()}


def _load_mitre_json(force_reload: bool = False):
    """加载 MITRE 数据，带缓存和线程安全刷新"""
    if _mitre_cache["data"] is not None and not force_reload:
        return _mitre_cache["data"]
    with _mitre_cache["lock"]:
        # 双重检查
        if _mitre_cache["data"] is not None and not force_reload:
            return _mitre_cache["data"]
        path = os.path.join(KNOWLEDGE_BASE_DIR, "mitre_attack", "techniques.json")
        if not os.path.exists(path):
            _mitre_cache["data"] = {"tactics": [], "techniques": []}
            return _mitre_cache["data"]
        try:
            with open(path, "r", encoding="utf-8") as f:
                _mitre_cache["data"] = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            _mitre_cache["data"] = {"tactics": [], "techniques": []}
        return _mitre_cache["data"]


_MITRE_DATA = _load_mitre_json()
TACTICS_INDEX = {t["id"]: t["name"] for t in _MITRE_DATA.get("tactics", [])}
TACTICS_DETAIL = {t["id"]: t for t in _MITRE_DATA.get("tactics", [])}

# 战术执行顺序（用于攻击链展示）
TACTIC_KILL_CHAIN_ORDER = [
    "TA0043",  # 侦察
    "TA0042",  # 资源开发
    "TA0001",  # 初始访问
    "TA0002",  # 执行
    "TA0003",  # 持久化
    "TA0004",  # 权限提升
    "TA0005",  # 防御绕过
    "TA0006",  # 凭据访问
    "TA0007",  # 发现
    "TA0008",  # 横向移动
    "TA0009",  # 收集
    "TA0011",  # 命令与控制
    "TA0010",  # 数据外传
    "TA0040",  # 影响
]

# ─── phase 归一化映射 ───
# techniques.json 中 phase 字段混用三种格式：
#   1. 标准 TA 编号（TA0001~TA0043）→ 直接使用
#   2. 小写短横线（credential-access、stealth、defense-impairment...）→ 映射到 TA 编号
#   3. 非标准自定义值（STEALTH、DEFENSE-IMPAIRMENT）→ 映射到最接近的 TA 编号
# 归一化后保证所有技术都能正确分组、tactic_name 不再为"未知"。
PHASE_TO_TACTIC = {
    # 标准 TA 编号 → 自身
    "TA0001": "TA0001", "TA0002": "TA0002", "TA0003": "TA0003",
    "TA0004": "TA0004", "TA0005": "TA0005", "TA0006": "TA0006",
    "TA0007": "TA0007", "TA0008": "TA0008", "TA0009": "TA0009",
    "TA0010": "TA0010", "TA0011": "TA0011", "TA0040": "TA0040",
    "TA0042": "TA0042", "TA0043": "TA0043",
    # 小写短横线 → TA 编号
    "reconnaissance": "TA0043",       # 侦察
    "resource-development": "TA0042", # 资源开发
    "initial-access": "TA0001",       # 初始访问
    "execution": "TA0002",            # 执行
    "persistence": "TA0003",          # 持久化
    "privilege-escalation": "TA0004", # 权限提升
    "defense-impairment": "TA0005",   # 防御绕过
    "stealth": "TA0005",              # 防御绕过（旧版字段名）
    "credential-access": "TA0006",    # 凭据访问
    "discovery": "TA0007",            # 发现
    "lateral-movement": "TA0008",     # 横向移动
    "collection": "TA0009",           # 收集
    "command-and-control": "TA0011",  # 命令与控制
    "exfiltration": "TA0010",         # 数据外传
    "impact": "TA0040",               # 影响
    # 非标准大写值（数据文件中的自定义值）→ TA 编号
    "STEALTH": "TA0005",              # 防御绕过
    "DEFENSE-IMPAIRMENT": "TA0005",   # 防御绕过
}
# 各战术的中文名（供 tactic_name 展示）
TACTIC_CN_NAMES = {
    "TA0043": "侦察", "TA0042": "资源开发", "TA0001": "初始访问",
    "TA0002": "执行", "TA0003": "持久化", "TA0004": "权限提升",
    "TA0005": "防御绕过", "TA0006": "凭据访问", "TA0007": "发现",
    "TA0008": "横向移动", "TA0009": "收集", "TA0011": "命令与控制",
    "TA0010": "数据外传", "TA0040": "影响",
}


def _normalize_phase(phase: str) -> str:
    """将任意格式的 phase 归一化为标准 TA 编号"""
    if not phase:
        return ""
    return PHASE_TO_TACTIC.get(phase, phase)


TECHNIQUES_INDEX: dict[str, dict] = {}
TECHNIQUES_BY_TACTIC: dict[str, list] = defaultdict(list)

for t in _MITRE_DATA.get("techniques", []):
    tid = t["id"]
    raw_phase = t.get("phase", "")
    phase = _normalize_phase(raw_phase)
    subs = t.get("sub_techniques", {})
    sub_info = {}
    if subs and isinstance(subs, dict):
        sub_info = {k: v.get("name", v) if isinstance(v, dict) else v for k, v in subs.items()}

    entry = {
        "name": t["name"],
        "tactic": phase,
        "raw_phase": raw_phase,
        "tactic_name": TACTIC_CN_NAMES.get(phase, TACTICS_INDEX.get(phase, "未知")),
        "description": t.get("description", ""),
        "detection": t.get("detection", ""),
        "mitigation": t.get("mitigation", ""),
        "scores": t.get("scores", {}),
        "related_cves": t.get("related_cves", []),
        "sub_techniques": sub_info,
    }
    TECHNIQUES_INDEX[tid] = entry
    TECHNIQUES_BY_TACTIC[phase].append(entry)


class MitreAttackKnowledge:
    """
    MITRE ATT&CK 知识库 v2.0
    
    增强功能：
    - 结构化搜索（按战术/等级/复杂度筛选）
    - 攻击链数据（杀伤链阶段排序）
    - 技术评分体系（风险/影响/检测难度）
    - 跨引用（技术→CVE）
    - 战术画像（技术分布/风险等级统计）
    """

    def __init__(self, data_path: Optional[str] = None):
        self.data_path = data_path or KNOWLEDGE_BASE_DIR

    # ==================== 基础查询 ====================

    def get_tactic(self, tactic_id: str) -> Optional[dict]:
        tid = tactic_id.upper()
        tactic = TACTICS_DETAIL.get(tid)
        if not tactic:
            return None
        techniques = [
            {**t, "id": tech_id}
            for tech_id, t in TECHNIQUES_INDEX.items()
            if t.get("tactic") == tid
        ]
        return {
            "id": tid,
            "name": tactic["name"],
            "phase": tactic.get("phase", ""),
            "description": tactic.get("description", ""),
            "kill_chain_position": TACTIC_KILL_CHAIN_ORDER.index(tid) + 1 if tid in TACTIC_KILL_CHAIN_ORDER else 0,
            "techniques_count": len(techniques),
            "techniques": techniques,
            # 战术统计
            "stats": self._tactic_stats(techniques),
        }

    def get_technique(self, technique_id: str) -> Optional[dict]:
        tid = technique_id.upper()
        if tid in TECHNIQUES_INDEX:
            tech = TECHNIQUES_INDEX[tid]
            result = {
                "id": tid,
                "name": tech["name"],
                "tactic_id": tech.get("tactic", ""),
                "tactic_name": tech.get("tactic_name", "未知"),
                "tactic_position": TACTIC_KILL_CHAIN_ORDER.index(tech.get("tactic", "")) + 1
                if tech.get("tactic", "") in TACTIC_KILL_CHAIN_ORDER else 0,
                "description": tech.get("description", ""),
                "detection": tech.get("detection", ""),
                "mitigation": tech.get("mitigation", ""),
                "has_sub_techniques": bool(tech.get("sub_techniques")),
                "sub_techniques": tech.get("sub_techniques", {}),
                # 评分体系
                "scores": {
                    **tech.get("scores", {}),
                    "overall_rating": self._overall_rating(tech.get("scores", {})),
                },
                # 跨引用
                "related_cves": tech.get("related_cves", []),
                # 关联合规
                "related_compliance": self._get_compliance_for_technique(tid),
            }
            return result

        # 子技术查询
        for t_id, t in TECHNIQUES_INDEX.items():
            subs = t.get("sub_techniques", {})
            if tid in subs:
                return {
                    "id": tid,
                    "name": subs[tid],
                    "parent_technique_id": t_id,
                    "parent_technique_name": t["name"],
                    "tactic_id": t.get("tactic", ""),
                    "tactic_name": t.get("tactic_name", "未知"),
                    "description": "子技术，父技术描述如上",
                    "detection": t.get("detection", ""),
                    "mitigation": t.get("mitigation", ""),
                }
        return None

    # ==================== 增强搜索 ====================

    def search(self, query: str, filters: Optional[dict] = None) -> list[dict]:
        """
        增强搜索 — 支持文本匹配 + 多维筛选
        
        filters:
            risk_levels: ["紧急", "高危", "中危", "低危"]
            tactics: ["TA0001", "TA0002"]
            has_cve: True/False
            min_risk_score: float
        """
        query_lower = query.lower()
        results = []

        for tid, tech in TECHNIQUES_INDEX.items():
            score = 0
            matches = []

            # 文本匹配
            if query_lower in tid.lower() or query_lower in tech["name"].lower():
                score += 10
                matches.append("ID/名称匹配")
            if query_lower in tech.get("description", "").lower():
                score += 5
                matches.append("描述匹配")
            if query_lower in tech.get("detection", "").lower():
                score += 3
                matches.append("检测方法匹配")
            for cve in tech.get("related_cves", []):
                if query_lower in cve.lower():
                    score += 6
                    matches.append("关联CVE匹配")

            # 子技术匹配
            for sub_id, sub_name in tech.get("sub_techniques", {}).items():
                if query_lower in sub_id.lower() or query_lower in sub_name.lower():
                    score += 3
                    matches.append("子技术匹配")

            if score == 0:
                continue

            # 多维筛选
            if filters:
                if filters.get("risk_levels"):
                    rl = tech.get("scores", {}).get("risk_level", "")
                    if rl not in filters["risk_levels"]:
                        score = 0
                if filters.get("tactics"):
                    if tech.get("tactic", "") not in filters["tactics"]:
                        score = 0
                if filters.get("has_cve"):
                    if not tech.get("related_cves"):
                        score = 0
                if filters.get("min_risk_score"):
                    rs = tech.get("scores", {}).get("risk_score", 0)
                    if rs < filters["min_risk_score"]:
                        score = 0

            if score <= 0:
                continue

            results.append({
                "id": tid,
                "name": tech["name"],
                "tactic_id": tech.get("tactic", ""),
                "tactic_name": tech.get("tactic_name", "未知"),
                "type": "technique",
                "description": tech.get("description", "")[:120],
                "risk_level": tech.get("scores", {}).get("risk_level", "未评级"),
                "risk_score": tech.get("scores", {}).get("risk_score", 0),
                "has_cve": bool(tech.get("related_cves")),
                "match_score": score,
                "sub_techniques": list(tech.get("sub_techniques", {}).keys()),
            })

        # 按匹配度+风险分排序
        results.sort(key=lambda x: (x["match_score"], x["risk_score"]), reverse=True)
        return results[:20]

    # ==================== 攻击链 ====================

    def get_kill_chain(self) -> list[dict]:
        """
        获取完整杀伤链视图
        
        返回战术阶段排序列表，每个战术包含其下的技术和统计
        """
        chain = []
        for tid in TACTIC_KILL_CHAIN_ORDER:
            tactic = TACTICS_DETAIL.get(tid)
            if not tactic:
                continue
            techniques = TECHNIQUES_BY_TACTIC.get(tid, [])
            chain.append({
                "tactic_id": tid,
                "tactic_name": tactic["name"],
                "phase": tactic.get("phase", ""),
                "position": TACTIC_KILL_CHAIN_ORDER.index(tid) + 1,
                "techniques_count": len(techniques),
                "risk_distribution": self._risk_distribution(techniques),
                "top_techniques": [
                    {
                        "id": tech_id,
                        "name": t["name"],
                        "risk_level": t.get("scores", {}).get("risk_level", ""),
                        "risk_score": t.get("scores", {}).get("risk_score", 0),
                    }
                    for tech_id, t in TECHNIQUES_INDEX.items()
                    if t.get("tactic") == tid
                ][:5],
            })
        return chain

    def get_attack_flow(self, technique_ids: list[str]) -> list[dict]:
        """
        获取多技术的攻击链路径
        
        输入: ["T1190", "T1059", "T1003", "T1071", "T1041"]
        输出: 按杀伤链排序的攻击路径
        """
        flow = []
        for tid in technique_ids:
            tid = tid.upper()
            if tid in TECHNIQUES_INDEX:
                tech = TECHNIQUES_INDEX[tid]
                tactic_pos = TACTIC_KILL_CHAIN_ORDER.index(tech.get("tactic", "")) + 1
                flow.append({
                    "id": tid,
                    "name": tech["name"],
                    "tactic_id": tech.get("tactic", ""),
                    "tactic_name": tech.get("tactic_name", "未知"),
                    "kill_chain_position": tactic_pos,
                    "risk_level": tech.get("scores", {}).get("risk_level", ""),
                    "risk_score": tech.get("scores", {}).get("risk_score", 0),
                    "description": tech.get("description", "")[:100],
                })
        flow.sort(key=lambda x: x["kill_chain_position"])
        return flow

    # ==================== 统计报表 ====================

    def get_dashboard(self) -> dict:
        """获取MITRE知识库仪表盘数据"""
        all_scores = [t.get("scores", {}).get("risk_score", 0) for t in TECHNIQUES_INDEX.values()]
        risk_dist = self._risk_distribution(list(TECHNIQUES_INDEX.values()))

        # 按战术统计技术分布
        tactic_tech_count = {
            tid: len(TECHNIQUES_BY_TACTIC.get(tid, []))
            for tid in TACTIC_KILL_CHAIN_ORDER
        }

        return {
            "total_techniques": len(TECHNIQUES_INDEX),
            "total_tactics": len(TACTICS_INDEX),
            "total_sub_techniques": sum(
                len(t.get("sub_techniques", {})) for t in TECHNIQUES_INDEX.values()
            ),
            "risk_distribution": risk_dist,
            "avg_risk_score": round(sum(all_scores) / len(all_scores), 1) if all_scores else 0,
            "max_risk_techniques": self._top_risks(5),
            "tactic_technique_count": tactic_tech_count,
            "technique_with_cve": sum(1 for t in TECHNIQUES_INDEX.values() if t.get("related_cves")),
        }

    # ==================== 内部方法 ====================

    def _tactic_stats(self, techniques: list) -> dict:
        """战术级别的统计"""
        scores = [t.get("scores", {}).get("risk_score", 0) for t in techniques]
        return {
            "avg_risk_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "total_techniques": len(techniques),
            "risk_distribution": self._risk_distribution(techniques),
        }

    def _risk_distribution(self, techniques: list) -> dict:
        """风险等级分布统计"""
        dist = defaultdict(int)
        for t in techniques:
            rl = t.get("scores", {}).get("risk_level", "未评级")
            dist[rl] += 1
        return dict(dist)

    def _overall_rating(self, scores: dict) -> str:
        """综合评分文字描述"""
        rs = scores.get("risk_score", 0)
        if rs >= 8.0: return " 极高风险 — 优先处置"
        if rs >= 6.5: return " 高风险 — 尽快加固"
        if rs >= 4.5: return " 中风险 — 常规关注"
        return " 低风险 — 持续监控"

    def _top_risks(self, n: int = 5) -> list[dict]:
        """最高风险技术TOP N"""
        scored = [
            {"id": tid, "name": t["name"], "risk_score": t.get("scores", {}).get("risk_score", 0),
             "risk_level": t.get("scores", {}).get("risk_level", ""),
             "tactic_name": t.get("tactic_name", "")}
            for tid, t in TECHNIQUES_INDEX.items()
        ]
        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored[:n]

    def _get_compliance_for_technique(self, technique_id: str) -> list[str]:
        """技术关联的合规要求"""
        compliance_map = {
            "T1566": ["等保2.0 身份鉴别", "网络安全法 第二十一条"],
            "T1190": ["等保2.0 漏洞管理", "关基保护条例 安全检测"],
            "T1110": ["等保2.0 身份鉴别", "ISO 27001 A.9.4.2"],
            "T1021": ["等保2.0 访问控制", "ISO 27001 A.9.1.2"],
            "T1003": ["等保2.0 数据安全", "数据安全法 第二十七条"],
            "T1070": ["等保2.0 安全审计", "等保审计要求 三级"],
            "T1041": ["数据安全法 第三十一条", "等保2.0 数据安全"],
            "T1486": ["关基保护条例 应急演练", "网络安全法 第五十五条"],
            "T1071": ["等保2.0 通信安全", "ISO 27001 A.13.1.1"],
        }
        base_id = technique_id.upper().split(".")[0]
        return compliance_map.get(base_id, [])

    # ==================== 兼容接口 ====================

    def get_all_tactics(self) -> list[dict]:
        return [{"id": tid, "name": name} for tid, name in TACTICS_INDEX.items()]

    def count(self) -> dict:
        sub_count = sum(len(t.get("sub_techniques", {})) for t in TECHNIQUES_INDEX.values())
        return {
            "tactics": len(TACTICS_INDEX),
            "techniques": len(TECHNIQUES_INDEX),
            "sub_techniques": sub_count,
        }

    def get_mitigations(self, technique_id: str) -> list[str]:
        tid = technique_id.upper().split(".")[0]
        tech = TECHNIQUES_INDEX.get(tid)
        if tech and tech.get("mitigation"):
            return [m.strip() for m in tech["mitigation"].split("；") if m.strip()]
        return ["参考MITRE ATT&CK官方缓解建议"]

