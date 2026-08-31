import json
import os
from typing import Optional

KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge_data")


class RemediationKnowledge:
    """应急响应剧本知识库（23 个真实攻击场景的处置方案）"""

    def __init__(self):
        self._data = self._load()

    def _load(self) -> dict:
        path = os.path.join(KNOWLEDGE_BASE_DIR, "remediation", "remediation.json")
        if not os.path.exists(path):
            return {"remediation_playbooks": [], "meta": {}}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"remediation_playbooks": [], "meta": {}}

    @property
    def playbooks(self) -> list:
        return self._data.get("remediation_playbooks", [])

    @property
    def meta(self) -> dict:
        return self._data.get("meta", {})

    def search(self, query: str = "") -> list[dict]:
        """搜索应急响应剧本"""
        query_lower = query.lower().strip()
        results = []
        for pb in self.playbooks:
            scenario = pb.get("scenario", "")
            indicators = pb.get("indicators", "")
            if not query_lower:
                results.append({
                    "scenario": scenario,
                    "indicators": indicators,
                    "immediate_actions": pb.get("immediate_actions", []),
                    "medium_term": pb.get("medium_term", []),
                    "long_term": pb.get("long_term", []),
                })
                continue
            score = 0
            if query_lower in scenario.lower():
                score += 10
            if query_lower in indicators.lower():
                score += 5
            for action_list in ["immediate_actions", "medium_term", "long_term"]:
                for action in pb.get(action_list, []):
                    if query_lower in action.lower():
                        score += 3
            if score > 0:
                results.append({
                    "scenario": scenario,
                    "indicators": indicators,
                    "immediate_actions": pb.get("immediate_actions", []),
                    "medium_term": pb.get("medium_term", []),
                    "long_term": pb.get("long_term", []),
                    "score": score,
                })
        if query_lower:
            results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return results[:20]

    def get_by_scenario(self, scenario_name: str) -> Optional[dict]:
        """按场景名称查询"""
        q = scenario_name.lower().strip()
        for pb in self.playbooks:
            if q == pb.get("scenario", "").lower().strip():
                return pb
        # 模糊匹配
        for pb in self.playbooks:
            if q in pb.get("scenario", "").lower():
                return pb
        return None

    def count(self) -> int:
        return len(self.playbooks)

