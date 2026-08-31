import json
import os
from typing import Optional

KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge_data")


class ComplianceKnowledge:
    """行业监管合规知识库（等保2.0、网络安全法、数据安全法、个人信息保护法、GDPR等）"""

    def __init__(self):
        self._data = self._load()

    def _load(self) -> dict:
        path = os.path.join(KNOWLEDGE_BASE_DIR, "compliance", "regulations.json")
        if not os.path.exists(path):
            return {"regulations": []}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"regulations": []}

    @property
    def regulations(self) -> list[dict]:
        return self._data.get("regulations", [])

    def search(self, query: str) -> list[dict]:
        """搜索匹配的法规要求"""
        query_lower = query.lower()
        results = []
        for reg in self.regulations:
            score = 0
            matched_items = []
            name = reg.get("name", "")
            abbr = reg.get("abbr", "")
            desc = reg.get("description", "")

            if query_lower in name.lower() or query_lower in abbr.lower():
                score += 10
                matched_items.append(f"法规名称匹配")

            for req in reg.get("key_requirements", []):
                if query_lower in req.lower():
                    score += 3
                    matched_items.append(req)

            if query_lower in desc.lower():
                score += 5

            if score > 0:
                results.append({
                    "name": name,
                    "abbr": abbr,
                    "score": score,
                    "matched_items": matched_items[:5],
                    "key_requirements": reg.get("key_requirements", []),
                    "penalties": reg.get("penalties", ""),
                    "description": desc,
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:5]

    def get_regulation(self, name_or_abbr: str) -> Optional[dict]:
        """按名称或简称查询具体法规"""
        query = name_or_abbr.lower()
        for reg in self.regulations:
            if query in reg.get("name", "").lower() or query in reg.get("abbr", "").lower():
                return reg
        return None

    def check_compliance(self, scenario: str) -> list[dict]:
        """检查某场景涉及哪些合规要求"""
        scenario_lower = scenario.lower()
        related = []
        keywords_map = {
            "数据泄露|数据安全|数据保护|personal data": ["数据安全法", "个人信息保护法", "GDPR", "网络安全法"],
            "等级保护|等保|分级保护": ["网络安全等级保护2.0"],
            "关键信息基础设施|关基|CII": ["关键信息基础设施安全保护条例"],
            "支付|信用卡|银行卡|持卡人": ["PCI DSS v4.0"],
            "日志|审计|audit": ["等级保护安全审计要求", "ISO/IEC 27001:2022"],
            "信息安全管理|ISMS": ["ISO/IEC 27001:2022"],
            "个人信息|隐私|用户信息": ["个人信息保护法", "GDPR"],
            "跨境|出境|数据转移|transfer": ["数据安全法", "GDPR", "个人信息保护法"],
            "密码|口令|身份鉴别|认证": ["等保2.0", "ISO/IEC 27001:2022"],
            "网络安全|事件|应急": ["网络安全法", "关键信息基础设施安全保护条例"],
        }

        for keywords, reg_names in keywords_map.items():
            if any(kw in scenario_lower for kw in keywords.split("|")):
                for reg_name in reg_names:
                    reg = self.get_regulation(reg_name)
                    if reg and reg not in related:
                        related.append(reg)

        return related

    def count(self) -> int:
        return len(self.regulations)

