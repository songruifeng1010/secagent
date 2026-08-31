"""
工具结果信任检查器

在 Orchestrator 汇总结果时检查各工具返回结果的可信度。
防止"安静地撒谎"——工具执行成功但结果是假的。
"""


class TrustChecker:
    """检查工具执行结果的可信度"""

    @staticmethod
    def check_threat_intel(result: dict) -> dict:
        """检查威胁情报结果的可信度"""
        warnings = []

        # 部分情报源失败检查
        errors = result.get("errors", [])
        if errors:
            for err in errors:
                warnings.append(f"部分情报源查询失败: {err}")

        # 情报源覆盖度检查（修复：把"未查询/缺失"显式暴露，而非当"无恶意"）
        coverage = result.get("coverage")
        missing = result.get("missing_sources", [])
        total = result.get("total_sources", 0)
        if coverage is not None:
            if coverage < 1.0:
                detail = f"，缺失 {', '.join(missing)}" if missing else ""
                warnings.append(
                    f"情报源覆盖不足: 可用 {coverage:.0%}{detail}"
                )
        elif total < 3:
            warnings.append(
                f"可用情报源仅 {total}/3 个，结果可能不完整"
            )

        return {
            "trustworthy": len(warnings) == 0,
            "warnings": warnings,
            "score": (
                1.0
                if len(warnings) == 0
                else max(0.1, 1.0 - len(warnings) * 0.3)
            ),
        }

    @staticmethod
    def check_firewall(result: dict) -> dict:
        """检查防火墙操作结果的可信度"""
        warnings = []
        action = result.get("action", "")

        if action == "blocked":
            duration = result.get("duration_minutes", 0)
            if duration <= 0:
                warnings.append(" 封禁时长为 0 分钟，封禁将立即失效")

        if action == "list":
            total = result.get("total", 0)
            if total < 0:
                warnings.append("封禁列表返回异常数量")

        return {
            "trustworthy": len(warnings) == 0,
            "warnings": warnings,
        }

    @staticmethod
    def check_all(agent_id: str, result: dict) -> dict:
        """统一入口：根据 Agent ID 自动选择检查器"""
        if agent_id == "intel-001":
            return TrustChecker.check_threat_intel(result)
        elif agent_id == "responder-001":
            return TrustChecker.check_firewall(result)
        return {"trustworthy": True, "warnings": []}
