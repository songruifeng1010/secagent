"""模型制品注册与只读扫描。

该模块不加载模型、不执行训练，只读取 ``model/<dataset>`` 下的制品和报告，
便于 API、CLI 和控制台展示真实部署状态。
"""

from __future__ import annotations

import json
from pathlib import Path


SUPPORTED_DATASETS = ("nsl-kdd", "unsw-nb15", "cic-ids-2018")

# 这是“允许被运行时自动加载”的最低质量门槛，不代表研究实验的通过标准。
# 采用 F1/召回率/ROC-AUC 联合判断，避免类别不平衡时仅凭准确率误判。
MIN_DEPLOYABLE_METRICS = {
    "f1_score": 0.50,
    "recall": 0.20,
    "roc_auc": 0.70,
}
MAX_DEPLOYABLE_OVERFIT_GAP = 0.15


def assess_model_report(report: dict) -> tuple[bool, list[str]]:
    """判断模型报告是否足以进入运行时自动加载候选。"""
    metrics = report.get("metrics") or {}
    reasons: list[str] = []
    for name, minimum in MIN_DEPLOYABLE_METRICS.items():
        value = metrics.get(name)
        if value is None:
            reasons.append(f"缺少 {name}")
        else:
            try:
                if float(value) < minimum:
                    reasons.append(f"{name}={float(value):.4f} < {minimum:.2f}")
            except (TypeError, ValueError):
                reasons.append(f"{name} 不是有效数值")
    overfitting = report.get("overfitting_check") or {}
    gap = overfitting.get("gap")
    if gap is not None:
        try:
            if float(gap) > MAX_DEPLOYABLE_OVERFIT_GAP:
                reasons.append(
                    f"overfit_gap={float(gap):.4f} > {MAX_DEPLOYABLE_OVERFIT_GAP:.2f}"
                )
        except (TypeError, ValueError):
            reasons.append("overfitting_check.gap 不是有效数值")
    return not reasons, reasons


def scan_model_artifacts(model_root: str | Path | None = None) -> list[dict]:
    root = Path(model_root) if model_root else Path(__file__).resolve().parents[2] / "model"
    results: list[dict] = []
    for dataset in SUPPORTED_DATASETS:
        dataset_dir = root / dataset
        artifacts = sorted(dataset_dir.glob("threat_model_*.joblib"), key=lambda p: p.stat().st_mtime, reverse=True) if dataset_dir.is_dir() else []
        item = {
            "dataset": dataset,
            "artifact_present": bool(artifacts),
            "model_path": str(artifacts[0]) if artifacts else "",
            "version": "",
            "algorithm": "",
            "metrics": {},
            "note": "未训练或未部署",
            "deployable": False,
            "quality_reasons": ["未找到模型报告"],
        }
        if artifacts:
            artifact = artifacts[0]
            report_path = artifact.with_name(artifact.stem + "_report.json")
            if report_path.is_file():
                try:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    item.update({
                        "version": report.get("version", ""),
                        "algorithm": report.get("algorithm", ""),
                        "metrics": report.get("metrics", {}),
                    })
                    deployable, reasons = assess_model_report(report)
                    item["deployable"] = deployable
                    item["quality_reasons"] = reasons
                except (OSError, ValueError) as exc:
                    item["error"] = str(exc)
                    item["quality_reasons"] = [f"报告读取失败: {exc}"]
            item["note"] = "模型制品存在；启动时需成功加载后才可调用"
        results.append(item)
    return results
