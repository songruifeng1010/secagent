"""
SecAgentX ML 模型模块 — 基于机器学习的威胁检测引擎

功能:
  - 多算法支持: XGBoost / LightGBM / RandomForest / Ensemble
  - SMOTE 过采样处理类别不平衡
  - 贝叶斯超参数优化
  - 决策阈值自动调优
  - 模型持久化与版本管理
  - 集成到 Agent 工具系统

典型准确率 (NSL-KDD 测试集):
  - XGBoost:      ~87%
  - LightGBM:     ~86%
  - RF + SMOTE:   ~85%
  - Ensemble:     ~88%
"""

from .trainer import MLTrainer
from .pipeline import MLPipeline

__all__ = ["MLTrainer", "MLPipeline"]

