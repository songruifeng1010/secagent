import json
import os
import hashlib
import logging
import numpy as np
import threading
from typing import Optional, AsyncGenerator

from ...llm.provider import LLMFactory
from ...knowledge.mitre_attack import MitreAttackKnowledge
from ...knowledge.compliance import ComplianceKnowledge
from ...knowledge.cve_db import CVEDatabase
from ...knowledge.threat_intel_kb import ActorKnowledge, MalwareKnowledge

KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge_data")


class AgenticRAGEngine:
    """
    Agentic-RAG 核心引擎（v2.0 — 增强防幻觉版）

    核心改进：
    1. 多知识源检索（MITRE + CVE + 合规 + 应急响应）
    2. ChromaDB 向量语义检索（本地哈希嵌入，无外部依赖）
    3. **防幻觉验证**：LLM回答必须引用知识库原文，找不到就说不知道
    4. Grounding评分：每条回答标注知识支撑度
    5. 来源追溯：每个结论都附带具体知识来源ID
    """

    EMBEDDING_DIM = 512  # BGE-small-zh-v1.5 输出维度；哈希嵌入降级时会适配此维度

    def __init__(self, llm=None, vector_store=None, max_rounds: int = 3):
        self.llm = llm
        self.mitre = MitreAttackKnowledge()
        self.compliance = ComplianceKnowledge()
        self.cve_db = CVEDatabase()
        self.actor_kb = ActorKnowledge()
        self.malware_kb = MalwareKnowledge()
        self.vector_store = vector_store
        self.max_rounds = max_rounds

    _BGE_QUERY_MODEL = None
    _BGE_LOCK = threading.Lock()
    _BGE_LOAD_ATTEMPTED = False

    @staticmethod
    def preload_bge_model():
        """加载 BGE 模型（从本地缓存读取，离线模式）"""
        if AgenticRAGEngine._BGE_LOAD_ATTEMPTED:
            return
        with AgenticRAGEngine._BGE_LOCK:
            if AgenticRAGEngine._BGE_LOAD_ATTEMPTED:
                return
            AgenticRAGEngine._BGE_LOAD_ATTEMPTED = True
            try:
                # 强制离线：模型已缓存到 ~/.cache/huggingface，禁止联网验证
                os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
                os.environ.setdefault("HF_HUB_OFFLINE", "1")
                from sentence_transformers import SentenceTransformer
                logging.getLogger("secagentx.rag").info("预加载 BGE 模型...")
                AgenticRAGEngine._BGE_QUERY_MODEL = SentenceTransformer(
                    'BAAI/bge-small-zh-v1.5', device='cpu',
                    model_kwargs={'trust_remote_code': True},
                )
                logging.getLogger("secagentx.rag").info("BGE 模型预加载完成")
            except Exception as e:
                logging.getLogger("secagentx.rag").warning(
                    f"BGE 模型预加载失败（将使用哈希嵌入降级）: {e}"
                )

    @staticmethod
    def _compute_query_embedding(text: str) -> list[float]:
        """
        计算查询向量的嵌入
        首次使用时懒加载 BGE 模型（模型已缓存到 ~/.cache，加载约 2-3 秒）
        """
        # 懒加载：首次查询时加载（非首次直接复用已加载模型）
        if AgenticRAGEngine._BGE_QUERY_MODEL is None:
            AgenticRAGEngine.preload_bge_model()

        if AgenticRAGEngine._BGE_QUERY_MODEL is not None:
            try:
                vec = AgenticRAGEngine._BGE_QUERY_MODEL.encode(
                    text, normalize_embeddings=True
                )
                return vec.tolist()
            except Exception:
                pass

        # 降级：本地哈希嵌入
        return AgenticRAGEngine._hash_embed(text)

    @staticmethod
    def _hash_embed(text: str) -> list[float]:
        """本地哈希嵌入（降级方案，numpy 已模块级导入）"""
        DIM = AgenticRAGEngine.EMBEDDING_DIM
        vec = np.zeros(DIM, dtype=np.float32)
        ngrams = set()
        for n in range(2, 6):
            for i in range(len(text) - n + 1):
                gram = text[i:i+n]
                # Compatibility hash for persisted fallback embeddings; this is
                # feature bucketing, never a password or integrity primitive.
                h = int(
                    hashlib.md5(
                        gram.encode("utf-8"), usedforsecurity=False
                    ).hexdigest(),
                    16,
                )
                idx = h % DIM
                ngrams.add(idx)
        for idx in ngrams:
            vec[idx] += 1.0
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()

    async def answer(self, query: str, context: Optional[dict] = None,
                     progress_cb=None) -> dict:
        if self.llm is None:
            result = self._fallback_answer(query)
            if progress_cb:
                for phase in ("analyze", "retrieve", "verify", "fuse", "grounding"):
                    await progress_cb({"phase": phase})
            return result

        retrieval_log = []
        all_knowledge = {"mitre": [], "cve": [], "compliance": [], "remediation": [], "general": []}

        # Step 1: 查询分析（同步方法，不需 await）
        analysis = self._analyze_query(query)
        retrieval_log.append({"step": "query_analysis", "result": analysis})
        if progress_cb:
            await progress_cb({"phase": "analyze", "result": analysis})

        # Step 2-3: 多轮检索 + 验证
        for round_num in range(self.max_rounds):
            plan = self._build_retrieval_plan(query, analysis, round_num, all_knowledge)
            retrieval_log.append({"step": f"retrieval_plan_{round_num}", "plan": plan})

            new_knowledge = self._execute_retrieval(plan, analysis)
            if progress_cb:
                await progress_cb({"phase": "retrieve", "round": round_num + 1})
            for k, v in new_knowledge.items():
                all_knowledge.setdefault(k, []).extend(v)

            verdict = self._verify_sufficiency(query, all_knowledge, round_num)
            retrieval_log.append({"step": f"verification_{round_num}", "verdict": verdict})
            if progress_cb:
                await progress_cb({"phase": "verify", "round": round_num + 1,
                                   "result": verdict})

            if verdict.get("sufficient", False):
                break
            if round_num < self.max_rounds - 1:
                analysis["refined_query"] = verdict.get("missing_info", "")

        # Step 4: 知识融合
        fused = self._fuse_knowledge(query, all_knowledge)
        retrieval_log.append({"step": "fusion", "result": fused})
        if progress_cb:
            await progress_cb({"phase": "fuse"})

        # Step 5: 防幻觉校验 — 检查是否有足够的知识支撑
        grounding_check = self._grounding_check(query, fused)
        retrieval_log.append({"step": "grounding_check", "result": grounding_check})
        if progress_cb:
            await progress_cb({"phase": "grounding", "result": grounding_check})

        # Step 6: 生成回答（必须基于知识库）
        answer = self._generate_grounded_answer(query, fused, grounding_check)

        return {
            "answer": answer,
            "sources": self._extract_sources(all_knowledge),
            "structured_sources": self._build_structured_sources(fused),
            "confidence": grounding_check["confidence"],
            "grounding_score": grounding_check["score"],
            "grounding_detail": grounding_check["detail"],
            "has_grounding": grounding_check["has_grounding"],
            "retrieval_rounds": len([l for l in retrieval_log if "retrieval_plan" in l.get("step", "")]),
            "retrieval_log": retrieval_log,
        }

    def _analyze_query(self, query: str) -> dict:
        """分析查询需要哪些知识源"""
        q = query.lower()
        entities = []

        # 提取可能的MITRE ID
        import re
        mitre_ids = re.findall(r'(T\d{4}(?:\.\d{3})?|TA\d{4})', query.upper())
        entities.extend(mitre_ids)

        # 提取可能的CVE ID
        cve_ids = re.findall(r'(CVE-\d{4}-\d+)', query.upper())
        entities.extend(cve_ids)

        requires_mitre = bool(mitre_ids) or any(k in q for k in [
            "mitre", "attack", "tactic", "technique",
            "攻", "战术", "杀伤链", "kill chain"
        ])
        requires_cve = bool(cve_ids) or any(k in q for k in [
            "cve", "漏洞", "vulnerability", "0day", "exp"
        ])
        requires_compliance = any(k in q for k in [
            "合规", "等保", "网络安全法", "数据安全法", "个人信息保护",
            "监管", "gdpr", "pci", "等级保护", "关基", "iso 27001"
        ])
        requires_remediation = any(k in q for k in [
            "应急", "处置", "响应", "修复", "加固",
            "playbook", "怎么处理", "怎么办"
        ])
        requires_actor = any(k in q for k in [
            "apt", "攻击组织", "hacker group", "threat group",
            "威胁组织", "黑客组织", "fancy", "lazarus", "kimsuky",
            "朝鲜", "俄罗斯", "伊朗", "中国"
        ])
        requires_malware = any(k in q for k in [
            "木马", "后门", "蠕虫", "病毒", "trojan", "backdoor",
            "ransomware", "勒索", "挖矿", "coinminer", "恶意软件",
            "cobaltstrike", "plugx", "winnti", "agenttesla"
        ])

        return {
            "entities": entities,
            "requires_mitre": requires_mitre,
            "requires_cve": requires_cve,
            "requires_compliance": requires_compliance,
            "requires_remediation": requires_remediation,
            "requires_actor": requires_actor,
            "requires_malware": requires_malware,
            "intent": "分析查询",
            "sub_queries": [query],
        }

    def _build_retrieval_plan(self, query: str, analysis: dict,
                              round_num: int, current_knowledge: dict) -> dict:
        plan = {
            "mitre_lookup": [],
            "cve_lookup": [],
            "compliance_lookup": [],
            "remediation_lookup": [],
            "actor_lookup": [],
            "malware_lookup": [],
            "vector_search": [],
        }

        # MITRE检索
        if analysis.get("requires_mitre") or round_num == 0:
            for entity in analysis.get("entities", []):
                if entity.startswith("T"):
                    plan["mitre_lookup"].append({"type": "technique", "id": entity})
                elif entity.startswith("TA"):
                    plan["mitre_lookup"].append({"type": "tactic", "id": entity})
            if not plan["mitre_lookup"]:
                plan["mitre_lookup"].append({"type": "search", "query": query})

        # CVE检索
        if analysis.get("requires_cve") or round_num == 0:
            for entity in analysis.get("entities", []):
                if entity.startswith("CVE"):
                    plan["cve_lookup"].append({"type": "exact", "id": entity})
            if not plan.get("cve_lookup"):
                plan["cve_lookup"].append({"type": "search", "query": query})

        # 合规检索
        if analysis.get("requires_compliance"):
            plan["compliance_lookup"].append({"type": "search", "query": query})

        # 应急响应检索
        if analysis.get("requires_remediation"):
            plan["remediation_lookup"].append({"type": "search", "query": query})

        # 威胁情报检索
        if analysis.get("requires_actor"):
            plan["actor_lookup"].append({"type": "search", "query": query})
        if analysis.get("requires_malware"):
            plan["malware_lookup"].append({"type": "search", "query": query})

        # 不足时补充检索
        if not current_knowledge.get("mitre") and not plan["mitre_lookup"]:
            plan["mitre_lookup"].append({"type": "search", "query": query})

        # 始终添加向量搜索（使用原始查询补全语义理解）
        plan["vector_search"].append({"query": query, "k": 3})

        return plan

    def _execute_retrieval(self, plan: dict, analysis: dict = None) -> dict:
        knowledge = {"mitre": [], "cve": [], "compliance": [], "remediation": [],
                     "actors": [], "malware": [], "general": []}

        # ─── Step 1: ChromaDB 向量检索（语义召回） ───
        vector_hits = {}  # {"mitre": [{"id": "T1566", "score": 0.92}, ...], ...}
        if self.vector_store is not None:
            try:
                vector_hits = self._vector_retrieve(plan)
            except Exception:
                pass

        # ─── Step 2: 从 plan + vector_hits 构建完整查询列表 ───
        # MITRE IDs to look up
        mitre_ids_to_fetch = set()
        for lookup in plan.get("mitre_lookup", []):
            if lookup["type"] == "technique":
                mitre_ids_to_fetch.add(lookup["id"])
            elif lookup["type"] == "search":
                # 关键词搜索 + 向量搜索补充
                results = self.mitre.search(lookup["query"])
                for r in results[:3]:
                    mitre_ids_to_fetch.add(r["id"])
        for hit in vector_hits.get("mitre", []):
            hid = hit.get("id", "")
            if hid:
                mitre_ids_to_fetch.add(hid)

        # CVE IDs to look up
        cve_ids_to_fetch = set()
        for lookup in plan.get("cve_lookup", []):
            if lookup["type"] == "exact":
                cve_ids_to_fetch.add(lookup["id"])
        for hit in vector_hits.get("cve", []):
            hid = hit.get("id", "")
            if hid:
                cve_ids_to_fetch.add(hid)

        # ─── Step 3: 从 JSON 知识库获取完整内容 ───
        for tid in mitre_ids_to_fetch:
            detail = self.mitre.get_technique(tid)
            if detail:
                knowledge["mitre"].append(detail)

        for cid in cve_ids_to_fetch:
            vuln = self.cve_db.get_by_id(cid)
            if vuln:
                knowledge["cve"].append(vuln)

        # 如果没有通过向量/计划找到任何 MITRE 结果，回退到关键词搜索
        if not knowledge["mitre"]:
            # 尝试以所有查询词在 MITRE 中搜索
            for lookup in plan.get("mitre_lookup", []):
                if lookup.get("type") == "search":
                    for r in self.mitre.search(lookup["query"])[:5]:
                        detail = self.mitre.get_technique(r["id"])
                        if detail and detail not in knowledge["mitre"]:
                            knowledge["mitre"].append(detail)

        # 合规检索
        for lookup in plan.get("compliance_lookup", []):
            if lookup["type"] == "search":
                results = self.compliance.search(lookup["query"])
                knowledge["compliance"].extend(results[:5])

        # 应急响应检索
        for lookup in plan.get("remediation_lookup", []):
            if lookup["type"] == "search":
                results = self._search_remediation(lookup["query"])
                knowledge["remediation"].extend(results[:3])

        # 威胁情报检索 — 攻击组织
        for lookup in plan.get("actor_lookup", []):
            if lookup["type"] == "search":
                results = self.actor_kb.search(lookup["query"])
                knowledge["actors"].extend(results[:5])

        # 威胁情报检索 — 恶意软件
        for lookup in plan.get("malware_lookup", []):
            if lookup["type"] == "search":
                results = self.malware_kb.search(lookup["query"])
                knowledge["malware"].extend(results[:5])

        # 如果未命中但也提取到了实体ID，尝试精确查询
        if not knowledge["actors"]:
            for eid in analysis.get("entities", []):
                if eid.startswith("G"):
                    actor = self.actor_kb.get_actor(eid)
                    if actor:
                        knowledge["actors"].append(actor)

        return knowledge

    # ═══════════════════ ChromaDB 向量检索 ═══════════════════

    def _vector_retrieve(self, plan: dict) -> dict:
        """
        使用 ChromaDB 向量检索，返回匹配的知识 ID 列表。
        向量搜索仅做"召回"，具体内容仍从 JSON 知识库读取（确保数据一致性）。
        """
        if self.vector_store is None:
            return {"mitre": [], "cve": [], "compliance": [], "remediation": [], "general": []}

        result = {"mitre": [], "cve": [], "compliance": [], "remediation": [], "general": []}
        search_queries = set()

        # 从 plan 中提取查询词
        for lookup in plan.get("mitre_lookup", []):
            if lookup.get("type") == "search" and lookup.get("query"):
                search_queries.add(lookup["query"])
        for lookup in plan.get("cve_lookup", []):
            if lookup.get("type") == "search" and lookup.get("query"):
                search_queries.add(lookup["query"])
        for lookup in plan.get("compliance_lookup", []):
            if lookup.get("type") == "search" and lookup.get("query"):
                search_queries.add(lookup["query"])
        for lookup in plan.get("remediation_lookup", []):
            if lookup.get("type") == "search" and lookup.get("query"):
                search_queries.add(lookup["query"])

        # 也加入原始的 vector_search 条目
        for vs in plan.get("vector_search", []):
            if vs.get("query"):
                search_queries.add(vs["query"])

        if not search_queries:
            return result

        COLLECTION_MAP = {
            "mitre": "mitre_techniques",
            "cve": "cve_database",
            "compliance": "compliance",
            "remediation": "remediation",
        }

        for query in search_queries:
            # 计算查询的本地哈希嵌入（避免触发 ONNX 模型下载）
            query_emb = self._compute_query_embedding(query)
            for target_type, coll_name in COLLECTION_MAP.items():
                try:
                    docs = self.vector_store.similarity_search(
                        coll_name, query, k=3, query_embeddings=query_emb
                    )
                    for doc in docs:
                        metadata = doc.get("metadata", {})
                        result[target_type].append({
                            "id": metadata.get("id", ""),
                            "name": metadata.get("name", ""),
                            "score": 1.0 - doc.get("distance", 0.0),
                        })
                except Exception:
                    pass

        # 去重，按 score 排序
        for key in result:
            seen = set()
            sorted_items = sorted(result[key], key=lambda x: x.get("score", 0), reverse=True)
            unique = []
            for item in sorted_items:
                item_id = item.get("id", "")
                if item_id and item_id not in seen:
                    seen.add(item_id)
                    unique.append(item)
            result[key] = unique[:5]

        return result

    def _search_remediation(self, query: str) -> list[dict]:
        """从应急响应知识库检索"""
        remediation_data = self._load_remediation()
        q = query.lower()
        results = []
        for playbook in remediation_data:
            scenario = playbook.get("scenario", "").lower()
            if q in scenario or any(kw in scenario for kw in q.split()):
                results.append(playbook)
        return results

    def _load_remediation(self) -> list:
        path = os.path.join(KNOWLEDGE_BASE_DIR, "remediation", "remediation.json")
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("remediation_playbooks", [])
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _verify_sufficiency(self, query: str, knowledge: dict, round_num: int) -> dict:
        total = sum(len(v) for v in knowledge.values())
        has_any = total > 0
        return {
            "sufficient": has_any,
            "total_docs": total,
            "missing_info": "需要补充信息" if not has_any else "",
            "confidence": min(0.9, 0.2 + total * 0.15),
        }

    def _fuse_knowledge(self, query: str, knowledge: dict) -> dict:
        """融合多知识源（含威胁情报）"""
        return {
            "mitre_techniques": knowledge.get("mitre", []),
            "cve_vulnerabilities": knowledge.get("cve", []),
            "compliance_regulations": knowledge.get("compliance", []),
            "remediation_playbooks": knowledge.get("remediation", []),
            "actor_profiles": knowledge.get("actors", []),
            "malware_profiles": knowledge.get("malware", []),
            "general_knowledge": knowledge.get("general", []),
        }

    def _grounding_check(self, query: str, fused: dict) -> dict:
        """
        防幻觉校验 — 核心防幻觉机制
        
        检查是否有知识库支撑，计算接地评分：
        - score=1.0: 有直接匹配的知识库条目
        - score=0.5: 有部分相关知识
        - score=0.0: 没有任何知识库支撑
        """
        total_items = (
            len(fused.get("mitre_techniques", [])) +
            len(fused.get("cve_vulnerabilities", [])) +
            len(fused.get("compliance_regulations", [])) +
            len(fused.get("remediation_playbooks", [])) +
            len(fused.get("actor_profiles", [])) +
            len(fused.get("malware_profiles", []))
        )

        if total_items >= 3:
            score = 1.0
            detail = "知识库支撑充足"
            has_grounding = True
            confidence = 0.9
        elif total_items >= 1:
            score = 0.5
            detail = "知识库部分支撑"
            has_grounding = True
            confidence = 0.6
        else:
            score = 0.0
            detail = " 知识库无相关记录，回答可能依赖LLM自身知识，存在幻觉风险"
            has_grounding = False
            confidence = 0.1

        return {
            "score": score,
            "detail": detail,
            "has_grounding": has_grounding,
            "confidence": confidence,
            "total_sources": total_items,
        }

    def _generate_grounded_answer(self, query: str, fused: dict, grounding: dict) -> str:
        """
        生成接地回答 — 只回答知识库中有依据的内容
        
        防幻觉规则：
        1. 每个结论必须标注来源（MITRE ID / CVE ID / 法规名称）
        2. 无知识库支撑时，必须明确说"知识库中未找到相关信息"
        3. 禁止LLM自由发挥编造安全知识
        """
        parts = []

        # 防幻觉：无知识支撑时直接说明
        if not grounding["has_grounding"]:
            parts.append("## 知识库查询结果\n")
            parts.append(">  **知识库中未找到与您问题直接匹配的安全知识内容。**\n")
            parts.append("我无法基于已有知识库对此问题给出有依据的回答。")
            parts.append("建议您：")
            parts.append("- 尝试使用更精确的关键词重新搜索")
            parts.append("- 查阅官方安全文档或MITRE ATT&CK官网")
            parts.append("- 联系安全厂商获取专业支持\n")
            parts.append(f"*知识库接地评分: {grounding['score']} — {grounding['detail']}*")
            return "\n".join(parts)

        # === 有知识支撑 ===
        parts.append("## 知识库检索结果\n")
        parts.append(f">  **知识库接地评分: {grounding['score']}** — {grounding['detail']}")
        parts.append("")

        # MITRE ATT&CK 信息
        if fused.get("mitre_techniques"):
            parts.append("---")
            parts.append("###  MITRE ATT&CK 相关信息\n")
            for tech in fused["mitre_techniques"]:
                tid = tech.get("id", "")
                name = tech.get("name", "")
                tactic = tech.get("tactic_name", "")
                desc = tech.get("description", "")
                detection = tech.get("detection", "")
                mitigation = tech.get("mitigation", "")

                parts.append(f"**{tid}: {name}**")
                if tactic:
                    parts.append(f"- 战术阶段: {tactic}")
                if desc:
                    parts.append(f"- 描述: {desc}")
                if detection:
                    parts.append(f"-  检测方法: {detection}")
                if mitigation:
                    parts.append(f"-  缓解措施: {mitigation}")

                # 子技术
                subs = tech.get("sub_techniques", {})
                if isinstance(subs, dict) and subs:
                    parts.append(f"- 子技术:")
                    for sid, sname in subs.items():
                        sn = sname if isinstance(sname, str) else sname.get("name", str(sname))
                        parts.append(f"  - `{sid}`: {sn}")

                # CVE关联
                related_cves = self.cve_db.get_by_mitre_technique(tid)
                if related_cves:
                    parts.append(f"-  相关漏洞:")
                    for cv in related_cves[:3]:
                        parts.append(f"  - {cv['id']} ({cv.get('severity', '')})")

                parts.append("")

        # CVE漏洞信息
        if fused.get("cve_vulnerabilities"):
            parts.append("---")
            parts.append("###  CVE漏洞信息\n")
            for vuln in fused["cve_vulnerabilities"]:
                vid = vuln.get("id", "")
                severity = vuln.get("severity", "")
                cvss = vuln.get("cvss_score", "")
                desc = vuln.get("description", "")
                affected = vuln.get("affected", "")
                impact = vuln.get("impact", "")
                detection = vuln.get("detection", "")
                remediation = vuln.get("remediation", "")

                parts.append(f"**{vid}** | 严重程度: {severity} | CVSS: {cvss}")
                if desc:
                    parts.append(f"- 描述: {desc}")
                if affected:
                    parts.append(f"- 影响版本: {affected}")
                if impact:
                    parts.append(f"- 影响: {impact}")
                if detection:
                    parts.append(f"-  检测: {detection}")
                if remediation:
                    parts.append(f"-  修复: {remediation}")
                parts.append("")

        # 攻击组织信息
        if fused.get("actor_profiles"):
            parts.append("---")
            parts.append("###  攻击组织信息\n")
            for actor in fused["actor_profiles"]:
                name = actor.get("name", "?")
                aid = actor.get("id", "")
                country = actor.get("country", "未知")
                motivation = actor.get("motivation", "")
                industries = actor.get("target_industries", [])
                techs = actor.get("associated_techniques", [])
                malwares = actor.get("associated_malware", [])
                cves = actor.get("associated_cves", [])

                parts.append(f"**{name}** ({aid})")
                parts.append(f"- 归属国家: {country}")
                if motivation:
                    parts.append(f"- 动机: {motivation}")
                if industries:
                    parts.append(f"- 目标行业: {', '.join(industries)}")
                if techs:
                    parts.append(f"- 关联技术: {', '.join(techs[:8])}")
                if malwares:
                    parts.append(f"- 恶意软件: {', '.join(malwares[:5])}")
                if cves:
                    parts.append(f"- 关联CVE: {', '.join(cves[:5])}")
                parts.append("")

        # 恶意软件信息
        if fused.get("malware_profiles"):
            parts.append("---")
            parts.append("###  恶意软件信息\n")
            for mw in fused["malware_profiles"]:
                name = mw.get("name", "?")
                mid = mw.get("id", "")
                mtype = mw.get("type", "")
                platform = mw.get("platform", "")
                actors = mw.get("associated_actors", [])
                techs = mw.get("associated_techniques", [])

                parts.append(f"**{name}** ({mid})")
                parts.append(f"- 类型: {mtype}")
                if platform:
                    parts.append(f"- 平台: {platform}")
                if actors:
                    parts.append(f"- 关联组织: {', '.join(actors[:5])}")
                if techs:
                    parts.append(f"- 关联技术: {', '.join(techs[:6])}")
                parts.append("")

        # 合规信息
        if fused.get("compliance_regulations"):
            parts.append("---")
            parts.append("###  合规监管要求\n")
            for reg in fused["compliance_regulations"]:
                name = reg.get("name", "")
                abbr = reg.get("abbr", "")
                penalties = reg.get("penalties", "")
                reqs = reg.get("key_requirements", [])

                parts.append(f"**{name}** ({abbr})")
                if penalties:
                    parts.append(f"-  处罚: {penalties}")
                if reqs:
                    parts.append("- 核心要求:")
                    for r in reqs[:5]:
                        parts.append(f"  - {r}")
                parts.append("")

        # 应急响应信息
        if fused.get("remediation_playbooks"):
            parts.append("---")
            parts.append("###  应急响应指南\n")
            for pb in fused["remediation_playbooks"]:
                scenario = pb.get("scenario", "")
                indicators = pb.get("indicators", "")
                actions = pb.get("immediate_actions", [])

                parts.append(f"**{scenario}**")
                if indicators:
                    parts.append(f"- 识别指标: {indicators}")
                if actions:
                    parts.append("- 立即处置:")
                    for a in actions[:5]:
                        parts.append(f"  - {a}")
                parts.append("")

        # 知识来源汇总
        parts.append("---")
        parts.append("###  知识来源\n")
        sources = self._extract_sources_raw(fused)
        for s in sources:
            parts.append(f"- {s}")

        return "\n".join(parts)

    def _extract_sources_raw(self, fused: dict) -> list[str]:
        sources = []
        for tech in fused.get("mitre_techniques", []):
            if tech.get("id"):
                sources.append(f"MITRE ATT&CK: {tech['id']} - {tech.get('name', '')}")
        for vuln in fused.get("cve_vulnerabilities", []):
            if vuln.get("id"):
                sources.append(f"CVE: {vuln['id']} ({vuln.get('severity', '')})")
        for reg in fused.get("compliance_regulations", []):
            if reg.get("name"):
                sources.append(f"合规: {reg['name']}")
        for pb in fused.get("remediation_playbooks", []):
            if pb.get("scenario"):
                sources.append(f"应急响应指南: {pb['scenario']}")
        for actor in fused.get("actor_profiles", []):
            if actor.get("name"):
                sources.append(f"攻击组织: {actor['name']} ({actor.get('country', '')})")
        for mw in fused.get("malware_profiles", []):
            if mw.get("name"):
                sources.append(f"恶意软件: {mw['name']} ({mw.get('type', '')})")
        return sources[:15]

    def _build_structured_sources(self, fused: dict) -> list[dict]:
        """将检索结果转换为前端稳定消费的结构化来源，最多返回 20 条。"""
        specs = (
            ("mitre_techniques", "mitre", "id", "name"),
            ("cve_vulnerabilities", "cve", "id", "_cve_name"),
            ("compliance_regulations", "compliance", "abbr", "name"),
            ("remediation_playbooks", "remediation", "scenario", "scenario"),
            ("actor_profiles", "actor", "id", "name"),
            ("malware_profiles", "malware", "id", "name"),
        )
        result = []
        seen = set()
        for collection, source_type, id_key, title_key in specs:
            for item in fused.get(collection, []) or []:
                if not isinstance(item, dict):
                    continue
                source_id = str(item.get(id_key) or item.get("id") or "").strip()
                title = str(item.get(title_key) or item.get("name") or
                            item.get("description") or source_id).strip()
                identity = (source_type, source_id, title)
                if not source_id or identity in seen:
                    continue
                seen.add(identity)
                result.append({
                    "source_type": source_type,
                    "id": source_id,
                    "title": title,
                    "score": float(item.get("score", 1.0)),
                })
                if len(result) >= 20:
                    return result
        return result

    def _extract_sources(self, knowledge: dict) -> list[str]:
        """兼容旧接口"""
        sources = []
        for k in knowledge.get("mitre", []):
            if k.get("id"):
                tid = k["id"]
                sources.append(f"MITRE ATT&CK: {tid}")
        for k in knowledge.get("cve", []):
            if k.get("id"):
                sources.append(f"CVE: {k['id']}")
        for k in knowledge.get("compliance", []):
            if k.get("abbr"):
                sources.append(f"合规: {k['abbr']}")
        for k in knowledge.get("remediation", []):
            if k.get("scenario"):
                sources.append(f"应急响应: {k['scenario']}")
        for k in knowledge.get("actors", []):
            if k.get("name"):
                sources.append(f"攻击组织: {k['name']}")
        for k in knowledge.get("malware", []):
            if k.get("name"):
                sources.append(f"恶意软件: {k['name']}")
        if knowledge.get("general"):
            sources.append("知识库向量检索")
        return sources

    def _fallback_answer(self, query: str) -> dict:
        """降级模式：无LLM时直接查知识库（优先使用向量检索）"""
        # 优先使用 ChromaDB 向量检索
        mitre_results = []
        cve_results = []
        compliance_results = []
        remediation_results = []

        if self.vector_store is not None:
            try:
                query_emb = self._compute_query_embedding(query)
                vs_plan = {
                    "mitre_lookup": [{"type": "search", "query": query}],
                    "cve_lookup": [{"type": "search", "query": query}],
                    "compliance_lookup": [{"type": "search", "query": query}],
                    "remediation_lookup": [{"type": "search", "query": query}],
                    "vector_search": [{"query": query, "k": 5}],
                }
                vector_hits = self._vector_retrieve(vs_plan)
                # 通过 ID 从 JSON 知识库获取完整信息
                for hit in vector_hits.get("mitre", []):
                    tid = hit.get("id", "")
                    if tid:
                        detail = self.mitre.get_technique(tid)
                        if detail:
                            mitre_results.append(detail)
                for hit in vector_hits.get("cve", []):
                    cid = hit.get("id", "")
                    if cid:
                        vuln = self.cve_db.get_by_id(cid)
                        if vuln:
                            cve_results.append(vuln)
                for hit in vector_hits.get("compliance", []):
                    cid = hit.get("id", "")
                    for reg in self.compliance.search(cid):
                        if reg and reg not in compliance_results:
                            compliance_results.append(reg)
                for hit in vector_hits.get("remediation", []):
                    sid = hit.get("id", "")
                    for pb in self._search_remediation(sid):
                        if pb and pb not in remediation_results:
                            remediation_results.append(pb)
            except Exception:
                pass

        # 如果没有向量结果，回退到关键词搜索
        if not mitre_results:
            mitre_results = self.mitre.search(query)
            # 关键词检索对包含自然语言后缀的技术 ID 不稳定，显式 ID 应始终
            # 走精确查询，确保离线降级路径可追溯。
            for entity in self._analyze_query(query).get("entities", []):
                if entity.startswith("T"):
                    detail = self.mitre.get_technique(entity)
                    if detail and detail not in mitre_results:
                        mitre_results.insert(0, detail)
        if not cve_results:
            cve_results = self.cve_db.search(query)
            for entity in self._analyze_query(query).get("entities", []):
                if entity.startswith("CVE-"):
                    vuln = self.cve_db.get_by_id(entity)
                    if vuln and vuln not in cve_results:
                        cve_results.insert(0, vuln)
        if not compliance_results:
            compliance_results = self.compliance.search(query)

        parts = ["## 知识库查询结果\n"]

        if mitre_results:
            parts.append("### MITRE ATT&CK\n")
            for r in mitre_results[:5]:
                if isinstance(r, dict):
                    parts.append(f"- **{r.get('id', '?')}**: {r.get('name', '?')} ({r.get('tactic', '')})")
            parts.append("")

        if cve_results:
            parts.append("### CVE漏洞\n")
            for r in cve_results[:5]:
                if isinstance(r, dict):
                    parts.append(f"- **{r.get('id', '?')}**: {r.get('description', '')[:100]}")
            parts.append("")

        if remediation_results:
            parts.append("### 应急响应指南\n")
            for r in remediation_results[:5]:
                if isinstance(r, dict):
                    parts.append(f"- **{r.get('scenario', '?')}**")
            parts.append("")

        if not (mitre_results or cve_results or compliance_results or remediation_results):
            parts.append("知识库中未找到相关信息。\n")

        answer = "\n".join(parts)
        has_content = bool(mitre_results or cve_results or compliance_results or remediation_results)
        sources = []
        for r in mitre_results[:3]:
            if isinstance(r, dict):
                sources.append(f"MITRE ATT&CK: {r.get('id', '?')}")
        for r in cve_results[:3]:
            if isinstance(r, dict):
                sources.append(f"CVE: {r.get('id', '?')}")
        for r in remediation_results[:3]:
            if isinstance(r, dict):
                sources.append(f"应急响应: {r.get('scenario', '?')}")

        return {
            "answer": answer,
            "sources": sources,
            "structured_sources": self._build_structured_sources({
                "mitre_techniques": mitre_results,
                "cve_vulnerabilities": cve_results,
                "compliance_regulations": compliance_results,
                "remediation_playbooks": remediation_results,
                "actor_profiles": [],
                "malware_profiles": [],
            }),
            "confidence": 0.8 if has_content else 0.1,
            "grounding_score": 1.0 if has_content else 0.0,
            "has_grounding": has_content,
            "grounding_detail": "知识库向量匹配" if has_content else "无匹配",
            "retrieval_rounds": 1,
        }
