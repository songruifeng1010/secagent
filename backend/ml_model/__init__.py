"""
SecAgentX ML 模型模块 — 基于机器学习的威胁检测引擎

功能:
  - 多算法支持: XGBoost / LightGBM / RandomForest / Ensemble
  - SMOTE 过采样处理类别不平衡
  - 贝叶斯超参数优化
  - 决策阈值自动调优
  - 模型持久化与版本管理
  - 集成到 Agent 工具系统

历史基准（NSL-KDD 测试集；仅供方案对比，不代表当前仓库或生产环境实测）:
  - XGBoost:      ~87%
  - LightGBM:     ~86%
  - RF + SMOTE:   ~85%
  - Ensemble:     ~88%
"""

from .model_registry import scan_model_artifacts

__all__ = ["MLTrainer", "MLPipeline", "scan_model_artifacts"]


def __getattr__(name):
    """只读模型目录不需要训练依赖；保留原有按名称导入接口。"""
    if name == "MLTrainer":
        from .trainer import MLTrainer
        return MLTrainer
    if name == "MLPipeline":
        from .pipeline import MLPipeline
        return MLPipeline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
