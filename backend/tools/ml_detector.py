"""
ML 威胁检测工具 — 将训练好的 ML 模型暴露给 Agent 系统

在 main.py 初始化时加载已经训练并验证的模型，Agent 可通过此工具
对网络流量进行 ML 驱动的恶意检测。
"""
import os
import numpy as np
import logging
from typing import Optional

from .base import BaseTool, ToolResult
from ..ml_model.trainer import MLTrainer
from ..ml_model.pipeline import MLPipeline

logger = logging.getLogger("secagentx.tools.ml_detector")

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "model")


class MLThreatDetectorTool(BaseTool):
    """基于机器学习的威胁检测工具。"""

    name = "ml_threat_detector"
    description = (
        "对网络流量特征进行机器学习威胁检测。支持 NSL-KDD、UNSW-NB15 和 "
        "CSE-CIC-IDS2018 模型制品，返回恶意概率和威胁评估。支持批量检测。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "features": {
                "type": "array",
                "items": {
                    "type": "object",
                    "description": "流量特征字典（KDD Cup 99 格式，41个特征 + protocol_type/service/flag）"
                },
                "description": "单条或批量流量特征列表"
            }
        },
        "required": ["features"]
    }

    # 内置一组典型流量特征名称（用于检测时做特征对齐）
    REQUIRED_FEATURES = [
        'duration', 'protocol_type', 'service', 'flag',
        'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
        'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count',
        'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate',
    ]

    def __init__(self, trainer: Optional[MLTrainer] = None,
                 pipeline: Optional[MLPipeline] = None,
                 model_path: Optional[str] = None):
        super().__init__()
        self.trainer = trainer
        # 模型路径：支持指定版本；默认自动选择最新的带版本模型
        self._model_path = model_path or self._find_latest_model()
        model_parent = os.path.basename(os.path.dirname(self._model_path))
        self.dataset_name = model_parent if model_parent in {"nsl-kdd", "unsw-nb15", "cic-ids-2018"} else "nsl-kdd"
        self.pipeline = pipeline or MLPipeline(use_smote=True, dataset_name=self.dataset_name)
        self._loaded = False
        self._last_error = ""

    def _find_latest_model(self) -> str:
        """自动选择最新版本的模型文件。

        优先级：
          1. 带版本号的模型（threat_model_<algo>_<version>.joblib），取最新
          2. 无版本的基础模型（threat_model_<algo>.joblib）作为兜底
        """
        import glob
        import json
        from backend.ml_model.model_registry import assess_model_report
        candidates = glob.glob(os.path.join(MODEL_DIR, "**", "threat_model_*.joblib"), recursive=True)
        if not candidates:
            return os.path.join(MODEL_DIR, "threat_model_xgboost.joblib")

        # 训练成功不等于可以上线。没有报告或未达到最低 F1/召回率/ROC-AUC
        # 的制品只保留在 API 展示中，不能被运行时自动选中。
        deployable = []
        for path in candidates:
            report_path = os.path.splitext(path)[0] + "_report.json"
            try:
                with open(report_path, "r", encoding="utf-8") as handle:
                    report = json.load(handle)
                ok, _ = assess_model_report(report)
                if ok:
                    deployable.append(path)
            except (OSError, ValueError):
                continue
        if deployable:
            candidates = deployable
        else:
            # 返回不存在的路径，让 initialize() 给出明确的部署提示，
            # 而不是悄悄加载未经验证的实验模型。
            return os.path.join(MODEL_DIR, "threat_model_xgboost.joblib")

        def _sort_key(path):
            # 带版本号的文件名更长，优先；同长度按 mtime
            base = os.path.basename(path)
            versioned = "_v" in base or any(c.isdigit() for c in base.split("_")[-1])
            return (1 if versioned else 0, os.path.getmtime(path))

        candidates.sort(key=_sort_key, reverse=True)
        return candidates[0]

    async def initialize(self):
        """初始化时加载或训练模型。"""
        if self.trainer is not None and self.trainer.is_trained:
            self._loaded = True
            self._last_error = ""
            logger.info("ML 模型已就绪（传入的训练器）")
            return

        # 尝试加载已有模型
        if os.path.exists(self._model_path):
            try:
                self.trainer = MLTrainer()
                self.trainer.load(self._model_path)
                self._loaded = True
                # 旧版模型文件未持久化 feature_names/scaler，用同一数据管线重建
                if not self.trainer.feature_names or self.trainer.scaler is None:
                    self._rebuild_pipeline_metadata()
                logger.info(f"ML 模型已加载: {self._model_path}")
                self._last_error = ""
                return
            except Exception as e:
                self._last_error = str(e)
                logger.warning(f"ML 模型加载失败: {e}，将重新训练")

        self._last_error = (
            "未找到经过真实数据训练并验证的 ML 模型；请先离线训练并部署模型"
        )
        raise RuntimeError(
            "未找到经过真实数据训练并验证的 ML 模型。"
            "请使用 NSL-KDD 或企业标注数据离线训练后配置模型文件；运行时不会自动使用合成数据训练。"
        )

    def _rebuild_pipeline_metadata(self):
        """重建特征名与 scaler（旧模型文件未持久化这些推理元数据）。

        用与训练完全相同的 NSL-KDD 管线（同一随机种子、同一划分）重建，
        保证特征顺序和标准化参数与模型训练时一致。
        """
        if self.pipeline.feature_names and self.pipeline.scaler is not None:
            return
        data = self.pipeline.run_pipeline(n_samples=15000, dataset=self.dataset_name)
        # 同步到 trainer，供预测使用
        if self.trainer:
            self.trainer.feature_names = list(self.pipeline.feature_names)
            self.trainer.scaler = self.pipeline.scaler
        expected = None
        if self.trainer and hasattr(self.trainer.model, 'n_features_in_'):
            expected = self.trainer.model.n_features_in_
        actual = len(self.pipeline.feature_names)
        if expected and actual != expected:
            logger.warning(
                f"ML 特征数不匹配: 管线重建={actual}, 模型期望={expected}，"
                f"预测可能不准确"
            )
        logger.info(f"ML 特征管线重建完成: {actual} 特征 (数据源: {data['info']})")

    async def execute(self, **kwargs) -> ToolResult:
        """执行 ML 威胁检测。"""
        if not self._loaded:
            try:
                await self.initialize()
            except Exception as e:
                return ToolResult(
                    success=False,
                    error=f"ML 模型未就绪: {e}",
                    data={"note": "请先用真实、已标注的数据完成离线训练并部署模型"}
                )

        features_list = kwargs.get("features", [])
        if not features_list:
            return ToolResult(success=False, error="未提供流量特征")

        if not isinstance(features_list, list):
            features_list = [features_list]

        results = []
        for idx, features in enumerate(features_list):
            result = self._predict_single(features)
            results.append(result)

        return ToolResult(success=True, data={
            "total": len(results),
            "malicious_count": sum(1 for r in results if r["is_malicious"]),
            "results": results,
            "algorithm": self.trainer.algorithm if self.trainer else "unknown",
            "model_accuracy": round(self.trainer.metrics.accuracy, 4) if self.trainer and self.trainer.metrics else 0,
        })

    def _predict_single(self, features: dict) -> dict:
        """单条流量预测。"""
        if self.trainer is None or not self._loaded:
            return {"error": "模型未就绪", "is_malicious": False, "malicious_probability": 0}

        # 特征对齐
        try:
            import pandas as pd

            # 优先使用 trainer 中持久化的特征名与 scaler（与模型强绑定）
            feature_names = self.trainer.feature_names or self.pipeline.feature_names
            scaler = self.trainer.scaler if self.trainer.scaler is not None else self.pipeline.scaler

            if not feature_names:
                return {
                    "error": "特征管线未初始化，无法预测",
                    "is_malicious": False, "malicious_probability": 0,
                }

            # 一次性构造全特征行：先置 0，再填已知值（避免逐列 insert 的性能问题）
            row_data = {col: 0 for col in feature_names}
            row_data.update({k: v for k, v in features.items() if k in row_data})
            row_df = pd.DataFrame([row_data])

            # 对齐顺序（与模型训练时一致）
            row_df = row_df[feature_names]

            X = row_df.values.astype(np.float64)

            # 标准化
            if scaler is not None:
                X = scaler.transform(X)

            # 预测
            y_pred, y_score = self.trainer.predict(X)

            return {
                "is_malicious": bool(y_pred[0]),
                "malicious_probability": round(float(y_score[0]), 4),
                "threat_level": "高危" if y_score[0] > 0.8 else (
                    "中危" if y_score[0] > 0.5 else "低危" if y_score[0] > 0.3 else "正常"
                ),
                "confidence": round(float(y_score[0]), 4),
            }
        except Exception as e:
            logger.warning(f"单条预测失败: {e}")
            return {"error": str(e), "is_malicious": False, "malicious_probability": 0}

    def get_model_summary(self) -> dict:
        """获取模型摘要。"""
        if self.trainer:
            return self.trainer.get_summary()
        return {"is_trained": False}

    def get_model_status(self) -> dict:
        """返回可供 API/控制台展示的模型状态，不触发训练或下载。"""
        exists = os.path.isfile(self._model_path)
        summary = self.get_model_summary()
        loaded = bool(self._loaded)
        is_trained = bool(summary.get("is_trained", False))
        return {
            "available": bool(exists and (loaded or is_trained)),
            "artifact_present": exists,
            "loaded": loaded,
            "is_trained": is_trained,
            "model_path": self._model_path,
            "algorithm": summary.get("algorithm", ""),
            "threshold": summary.get("threshold"),
            "metrics": summary.get("metrics", {}),
            "error": self._last_error,
            "note": (
                "模型已加载，可供 Agent 调用"
                if loaded or is_trained else
                "模型文件存在但尚未加载；运行时初始化后才可调用"
                if exists else
                "未部署模型；请使用真实、已标注数据离线训练"
            ),
        }
