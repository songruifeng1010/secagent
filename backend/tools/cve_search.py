"""
CVE 漏洞查询工具

封装 CVEDatabase 为可调用的安全工具，供 Planner 动态调度。
"""

import time
from typing import Optional
from .base import BaseTool, ToolResult
from ..knowledge.cve_db import CVEDatabase


class CVESearchTool(BaseTool):
    name = "cve_search"
    description = "查询CVE漏洞详情，支持按CVE编号精确查询或按关键词模糊搜索"
    parameters = {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE编号，如 CVE-2024-3094。优先使用精确CVE编号查询。"
            },
            "keyword": {
                "type": "string",
                "description": "搜索关键词，如 'OpenSSH' 'RCE' 'Apache'。当没有cve_id时使用。"
            }
        },
        "description": "查询CVE漏洞。建议: 有cve_id时传入cve_id，没有时传入keyword，两者都不传则返回近期严重漏洞。"
    }

    def __init__(self):
        self.db = CVEDatabase()

    async def execute(self, cve_id: str = "", keyword: str = "") -> ToolResult:
        start = time.time()

        if cve_id:
            # 精确查询 — 统一返回格式 {total, results}
            vuln = self.db.get_by_id(cve_id)
            elapsed = (time.time() - start) * 1000
            data = {
                "query_type": "cve_id",
                "cve_id": cve_id,
                "total": 1 if vuln else 0,
                "results": [vuln] if vuln else [],
            }
            return ToolResult(success=True, data=data, duration_ms=elapsed)

        elif keyword:
            # 关键词搜索
            results = self.db.search(keyword)
            elapsed = (time.time() - start) * 1000
            return ToolResult(
                success=True,
                data={
                    "query_type": "keyword",
                    "keyword": keyword,
                    "total": len(results),
                    "results": results,
                },
                duration_ms=elapsed,
            )

        else:
            # 返回近期严重漏洞
            critical = self.db.get_critical_recent()
            elapsed = (time.time() - start) * 1000
            return ToolResult(
                success=True,
                data={
                    "query_type": "recent_critical",
                    "total": len(critical),
                    "results": critical,
                },
                duration_ms=elapsed,
            )

