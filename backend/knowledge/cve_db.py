import json
import os
from datetime import datetime
from typing import Optional

KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge_data")


class CVEDatabase:
    """CVE漏洞知识库（从JSON加载最新/高危漏洞）"""

    def __init__(self):
        self._data = self._load()

    def _load(self) -> dict:
        path = os.path.join(KNOWLEDGE_BASE_DIR, "cve", "vulnerabilities.json")
        if not os.path.exists(path):
            return {"cve_database": []}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"cve_database": []}

    @property
    def vulnerabilities(self) -> list[dict]:
        return self._data.get("cve_database", [])

    def get_by_id(self, cve_id: str) -> Optional[dict]:
        """按CVE编号查询"""
        cve_id_upper = cve_id.upper().strip()
        for vuln in self.vulnerabilities:
            if vuln.get("id", "").upper() == cve_id_upper:
                return vuln
            # 支持部分匹配
            if cve_id_upper.startswith(vuln.get("id", "").upper().split("-")[0]):
                if cve_id_upper in vuln.get("id", "").upper():
                    return vuln
        return None

    def search(self, query: str) -> list[dict]:
        """搜索CVE漏洞"""
        query_lower = query.lower()
        results = []

        for vuln in self.vulnerabilities:
            score = 0
            cve_id = vuln.get("id", "").lower()
            desc = vuln.get("description", "").lower()
            affected = vuln.get("affected", "").lower()
            mitre_mappings = vuln.get("mitre_techniques", vuln.get("mitre_mapping", []))

            if query_lower in cve_id:
                score += 10
            if query_lower in desc:
                score += 5
            if query_lower in affected:
                score += 5
            for mt in mitre_mappings:
                if query_lower in mt.lower():
                    score += 3

            if score > 0:
                results.append({
                    "id": vuln["id"],
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "cvss_score": vuln.get("cvss_score", 0),
                    "description": vuln["description"],
                    "affected": vuln.get("affected", ""),
                    "impact": vuln.get("impact", ""),
                    "detection": vuln.get("detection", ""),
                    "remediation": vuln.get("remediation", ""),
                    "score": score,
                    "mitre_mapping": mitre_mappings,
                })

        results.sort(key=lambda x: (x["score"], x["cvss_score"]), reverse=True)
        return results[:10]

    def get_critical_recent(self, days: int = 365) -> list[dict]:
        """获取近期严重漏洞"""
        return [
            v for v in self.vulnerabilities
            if v.get("severity") in ("CRITICAL", "HIGH")
        ][:10]

    def get_by_mitre_technique(self, technique_id: str) -> list[dict]:
        """通过MITRE ATT&CK技术ID查找相关CVE"""
        tid = technique_id.upper().split(".")[0]
        results = []
        for vuln in self.vulnerabilities:
            mappings = vuln.get("mitre_techniques", vuln.get("mitre_mapping", []))
            for mt in mappings:
                if mt.upper().startswith(tid):
                    results.append(vuln)
                    break
        return results

    def count(self) -> int:
        return len(self.vulnerabilities)
