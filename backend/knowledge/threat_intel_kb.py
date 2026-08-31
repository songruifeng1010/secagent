"""
威胁情报知识库
攻击组织 + 恶意软件 结构化知识检索
"""
import json
import os
import re
from typing import Optional

KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge_data")


class ActorKnowledge:
    """攻击组织知识库（APT 组织画像）"""

    def __init__(self):
        self._data = self._load()
        self._actors_index: dict[str, dict] = {}  # name / alias / id → actor
        self._build_index()

    def _load(self) -> dict:
        path = os.path.join(KNOWLEDGE_BASE_DIR, "threat_intel", "actors.json")
        if not os.path.exists(path):
            return {"actors": []}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"actors": []}

    def _build_index(self):
        for actor in self._data.get("actors", []):
            aid = actor.get("id", "")
            name = actor.get("name", "")
            # ID 索引
            if aid:
                self._actors_index[aid.lower()] = actor
            # 名称索引
            if name:
                self._actors_index[name.lower()] = actor
            # 别名索引
            for alias in actor.get("aliases", []):
                self._actors_index[alias.lower()] = actor

    def search(self, query: str) -> list[dict]:
        """模糊搜索攻击组织"""
        q = query.lower().strip()
        if not q:
            return []

        # 精确匹配优先
        if q in self._actors_index:
            return [self._actors_index[q]]

        results = []
        for actor in self._data.get("actors", []):
            score = 0
            match_fields = []

            # ID 匹配
            if q in actor.get("id", "").lower():
                score += 15
                match_fields.append("ID")
            # 名称匹配
            if q in actor.get("name", "").lower():
                score += 10
                match_fields.append("名称")
            # 别名匹配
            for alias in actor.get("aliases", []):
                if q in alias.lower():
                    score += 8
                    match_fields.append("别名")
                    break
            # 国家匹配
            if q in actor.get("country", "").lower():
                score += 5
                match_fields.append("国家")
            # 行业匹配
            for ind in actor.get("target_industries", []):
                if q in ind.lower():
                    score += 4
                    match_fields.append("行业")
                    break
            # 恶意软件匹配
            for mw in actor.get("associated_malware", []):
                if q in mw.lower():
                    score += 6
                    match_fields.append("恶意软件")
                    break
            # 技术匹配
            for tech in actor.get("associated_techniques", []):
                if q in tech.lower():
                    score += 3
                    match_fields.append("技术")
                    break
            # CVE 匹配
            for cve in actor.get("associated_cves", []):
                if q in cve.lower():
                    score += 4
                    match_fields.append("CVE")
                    break
            # 描述匹配
            if q in actor.get("description", "").lower():
                score += 2
                match_fields.append("描述")

            if score > 0:
                results.append({
                    "actor": actor,
                    "score": score,
                    "matched_fields": match_fields,
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return [r["actor"] for r in results[:5]]

    def get_actor(self, identifier: str) -> Optional[dict]:
        """精确获取攻击组织"""
        return self._actors_index.get(identifier.lower().strip())

    def get_by_technique(self, technique_id: str) -> list[dict]:
        """根据 MITRE 技术 ID 查找使用的攻击组织"""
        tid = technique_id.upper().split(".")[0]
        results = []
        for actor in self._data.get("actors", []):
            if tid in actor.get("associated_techniques", []):
                results.append(actor)
        return results

    def get_by_malware(self, malware_name: str) -> list[dict]:
        """根据恶意软件名查找关联攻击组织"""
        q = malware_name.lower()
        results = []
        for actor in self._data.get("actors", []):
            for mw in actor.get("associated_malware", []):
                if q in mw.lower():
                    results.append(actor)
                    break
        return results

    def get_all_actors(self) -> list[dict]:
        return self._data.get("actors", [])

    def count(self) -> dict:
        actors = self._data.get("actors", [])
        countries = {}
        for a in actors:
            c = a.get("country", "未知")
            countries[c] = countries.get(c, 0) + 1
        return {
            "actors": len(actors),
            "countries": countries,
        }


class MalwareKnowledge:
    """恶意软件知识库"""

    def __init__(self):
        self._data = self._load()
        self._index: dict[str, dict] = {}
        self._build_index()

    def _load(self) -> dict:
        path = os.path.join(KNOWLEDGE_BASE_DIR, "threat_intel", "malware.json")
        if not os.path.exists(path):
            return {"malware": []}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"malware": []}

    def _build_index(self):
        for m in self._data.get("malware", []):
            mid = m.get("id", "")
            name = m.get("name", "")
            if mid:
                self._index[mid.lower()] = m
            if name:
                self._index[name.lower()] = m

    def search(self, query: str) -> list[dict]:
        q = query.lower().strip()
        if not q:
            return []

        if q in self._index:
            return [self._index[q]]

        results = []
        for m in self._data.get("malware", []):
            score = 0
            if q in m.get("id", "").lower():
                score += 15
            if q in m.get("name", "").lower():
                score += 10
            for actor in m.get("associated_actors", []):
                if q in actor.lower():
                    score += 5
                    break
            for tech in m.get("associated_techniques", []):
                if q in tech.lower():
                    score += 3
                    break
            if q in m.get("type", "").lower():
                score += 4
            if q in m.get("description", "").lower():
                score += 2
            if score > 0:
                results.append({"malware": m, "score": score})

        results.sort(key=lambda x: x["score"], reverse=True)
        return [r["malware"] for r in results[:5]]

    def get_malware(self, identifier: str) -> Optional[dict]:
        return self._index.get(identifier.lower().strip())

    def get_by_actor(self, actor_name: str) -> list[dict]:
        q = actor_name.lower()
        results = []
        for m in self._data.get("malware", []):
            for actor in m.get("associated_actors", []):
                if q in actor.lower():
                    results.append(m)
                    break
        return results

    def get_by_technique(self, technique_id: str) -> list[dict]:
        tid = technique_id.upper().split(".")[0]
        results = []
        for m in self._data.get("malware", []):
            if tid in m.get("associated_techniques", []):
                results.append(m)
        return results

    def count(self) -> int:
        return len(self._data.get("malware", []))

    def get_types(self) -> dict:
        types = {}
        for m in self._data.get("malware", []):
            t = m.get("type", "未知")
            types[t] = types.get(t, 0) + 1
        return types

