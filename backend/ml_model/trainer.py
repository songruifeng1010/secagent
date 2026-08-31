"""
高级 ML 训练器 — 多算法 + 超参数优化 + 模型集成

核心改进（相比 v1.1 的 78.3%）:
  1. XGBoost 与 LightGBM — 梯度提升树，天然高精度
  2. 贝叶斯超参数优化 — 比 GridSearch 更高效
  3. SMOTE 过采样 — 解决类别不平衡
  4. 概率校准 — 输出更准确的置信度
  5. 软投票 Ensemble — 融合多模型优势
  6. 决策阈值调优 — 在验证集上最优 F1/Youden's J
"""
import os
import json
import time
import numpy as np
import logging
from typing import Optional, Tuple, List
from dataclasses import dataclass, field

from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, confusion_matrix, roc_auc_score,
                              classification_report, matthews_corrcoef)
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_val_score
import joblib

logger = logging.getLogger("secagentx.ml.trainer")

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    logger.warning("xgboost 未安装")

try:
    from lightgbm import LGBMClassifier
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False
    logger.warning("lightgbm 未安装")

try:
    from skopt import BayesSearchCV
    from skopt.space import Real, Integer, Categorical
    HAS_SKOPT = True
except ImportError:
    HAS_SKOPT = False
    logger.warning("scikit-optimize 未安装，使用随机搜索替代")


@dataclass
class ModelMetrics:
    """模型评估指标"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    roc_auc: float = 0.0
    mcc: float = 0.0
    false_positive_rate: float = 0.0
    confusion_matrix: Optional[np.ndarray] = None
    best_threshold: float = 0.5
    classification_report: str = ""

    def to_dict(self) -> dict:
        cm = self.confusion_matrix
        return {
            'accuracy': round(self.accuracy, 4),
            'precision': round(self.precision, 4),
            'recall': round(self.recall, 4),
            'f1_score': round(self.f1_score, 4),
            'roc_auc': round(self.roc_auc, 4),
            'mcc': round(self.mcc, 4),
            'false_positive_rate': round(self.false_positive_rate, 4),
            'best_threshold': round(self.best_threshold, 4),
            'confusion_matrix': cm.tolist() if cm is not None else [],
            'tn': int(cm[0, 0]) if cm is not None else 0,
            'fp': int(cm[0, 1]) if cm is not None else 0,
            'fn': int(cm[1, 0]) if cm is not None else 0,
            'tp': int(cm[1, 1]) if cm is not None else 0,
        }

    @property
    def is_qualified(self) -> bool:
        """是否达标（准确率≥85% 且 误报率≤10%）"""
        return self.accuracy >= 0.85 and self.false_positive_rate <= 0.10


def _find_optimal_threshold(model, X_val, y_val) -> float:
    """在验证集上搜索最优决策阈值（最大化 Youden's J = TPR - FPR）。"""
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_val)
        if proba.shape[1] >= 2:
            y_score = proba[:, 1]
        else:
            return 0.5
    else:
        return 0.5

    thresholds = np.linspace(0.05, 0.95, 37)
    best_j = -1
    best_t = 0.5
    for t in thresholds:
        y_pred = (y_score >= t).astype(int)
        tn = np.sum((y_val == 0) & (y_pred == 0))
        fp = np.sum((y_val == 0) & (y_pred == 1))
        fn = np.sum((y_val == 1) & (y_pred == 0))
        tp = np.sum((y_val == 1) & (y_pred == 1))
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        j = tpr - fpr
        if j > best_j:
            best_j = j
            best_t = t
    return best_t


class MLTrainer:
    """多算法 ML 训练器，支持超参优化与模型集成。"""

    AVAILABLE_ALGORITHMS = ['random_forest', 'xgboost', 'lightgbm', 'ensemble']

    def __init__(self, model_dir: str = "model",
                 use_bayes_opt: bool = True,
                 cv_folds: int = 5,
                 calibrate: bool = True,
                 threshold_tuning: bool = True):
        self.model_dir = model_dir
        self.use_bayes_opt = use_bayes_opt and HAS_SKOPT
        self.cv_folds = cv_folds
        self.calibrate = calibrate
        self.threshold_tuning = threshold_tuning

        self.model = None
        self.is_trained = False
        self.algorithm = ""
        self.best_params = {}
        self.metrics: Optional[ModelMetrics] = None
        self.threshold = 0.5
        self.feature_importance: dict = {}
        self.training_time: float = 0.0
        # 推理所需的预处理元数据（与模型一起持久化，避免预测时特征不匹配）
        self.feature_names: list = []
        self.scaler = None

    def _create_base_model(self, algo: str, params: dict = None):
        """创建基础模型实例。"""
        params = params or {}
        seed = params.pop('random_state', 42)

        if algo == 'random_forest':
            return RandomForestClassifier(
                n_estimators=params.get('n_estimators', 200),
                max_depth=params.get('max_depth', 15),
                min_samples_split=params.get('min_samples_split', 2),
                min_samples_leaf=params.get('min_samples_leaf', 1),
                class_weight=params.get('class_weight', 'balanced'),
                random_state=seed, n_jobs=-1
            )
        elif algo == 'xgboost' and HAS_XGB:
            return XGBClassifier(
                n_estimators=params.get('n_estimators', 200),
                max_depth=params.get('max_depth', 8),
                learning_rate=params.get('learning_rate', 0.08),
                subsample=params.get('subsample', 0.8),
                colsample_bytree=params.get('colsample_bytree', 0.8),
                scale_pos_weight=params.get('scale_pos_weight', 2),
                eval_metric='logloss',
                use_label_encoder=False,
                random_state=seed, n_jobs=-1, verbosity=0
            )
        elif algo == 'lightgbm' and HAS_LGBM:
            return LGBMClassifier(
                n_estimators=params.get('n_estimators', 200),
                max_depth=params.get('max_depth', 8),
                learning_rate=params.get('learning_rate', 0.08),
                num_leaves=params.get('num_leaves', 31),
                subsample=params.get('subsample', 0.8),
                colsample_bytree=params.get('colsample_bytree', 0.8),
                class_weight=params.get('class_weight', 'balanced'),
                random_state=seed, n_jobs=-1, verbose=-1
            )
        else:
            logger.warning(f"算法 '{algo}' 不可用，回退随机森林")
            return RandomForestClassifier(n_estimators=200, max_depth=15,
                                          class_weight='balanced',
                                          random_state=seed, n_jobs=-1)

    def _get_param_space(self, algo: str) -> dict:
        """获取超参数搜索空间（贝叶斯或随机）。"""
        spaces = {
            'random_forest': {
                'n_estimators': [100, 200, 300, 400, 500],
                'max_depth': [5, 10, 15, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
            },
            'xgboost': {
                'n_estimators': [100, 200, 300, 400],
                'max_depth': [4, 6, 8, 10, 12],
                'learning_rate': [0.01, 0.05, 0.08, 0.1, 0.15],
                'subsample': [0.6, 0.7, 0.8, 0.9, 1.0],
                'colsample_bytree': [0.6, 0.7, 0.8, 0.9, 1.0],
                'scale_pos_weight': [1, 2, 3, 5],
            },
            'lightgbm': {
                'n_estimators': [100, 200, 300, 400],
                'max_depth': [4, 6, 8, 10, 12, -1],
                'learning_rate': [0.01, 0.05, 0.08, 0.1, 0.15],
                'num_leaves': [15, 31, 63, 127],
                'subsample': [0.6, 0.7, 0.8, 0.9, 1.0],
                'colsample_bytree': [0.6, 0.7, 0.8, 0.9, 1.0],
            },
        }
        return spaces.get(algo, {})

    def train(self, X_train: np.ndarray, y_train: np.ndarray,
              X_val: Optional[np.ndarray] = None,
              y_val: Optional[np.ndarray] = None,
              algorithm: str = 'xgboost',
              feature_names: Optional[list] = None,
              tune_hyperparams: bool = True) -> 'MLTrainer':
        """
        训练模型（含可选的超参优化和阈值调优）。

        参数:
            algorithm: random_forest / xgboost / lightgbm / ensemble
        """
        start_time = time.time()
        self.algorithm = algorithm
        n_samples, n_features = X_train.shape
        logger.info(f"开始训练 | 算法: {algorithm} | 样本: {n_samples} | 特征: {n_features}")

        # 如果没有提供验证集，从训练集划分
        if X_val is None or y_val is None:
            from sklearn.model_selection import train_test_split
            X_train, X_val, y_train, y_val = train_test_split(
                X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
            )
            logger.info(f"划分验证集: 训练 {len(X_train)}, 验证 {len(X_val)}")

        if algorithm == 'ensemble':
            self._train_ensemble(X_train, y_train)
        else:
            if tune_hyperparams:
                self._train_with_optimization(X_train, y_train, algorithm)
            else:
                self.model = self._create_base_model(algorithm, {'random_state': 42})
                self.model.fit(X_train, y_train)

        # 概率校准
        if self.calibrate and hasattr(self.model, 'predict_proba'):
            try:
                self.model = CalibratedClassifierCV(
                    self.model, cv=3, method='sigmoid'
                )
                self.model.fit(X_train, y_train)
            except Exception as e:
                logger.warning(f"概率校准跳过: {e}")

        # 阈值调优
        if self.threshold_tuning and algorithm != 'ensemble':
            self.threshold = _find_optimal_threshold(self.model, X_val, y_val)
            logger.info(f"最优决策阈值: {self.threshold:.3f}")
        else:
            self.threshold = 0.5

        # 评估
        self.metrics = self.evaluate(X_val, y_val)
        self.is_trained = True
        self.training_time = time.time() - start_time

        # 特征重要性
        self.feature_importance = self._get_feature_importance(feature_names)
        # 持久化特征名，供推理时特征对齐
        if feature_names:
            self.feature_names = list(feature_names)

        logger.info(f"✅ 训练完成 | 耗时: {self.training_time:.1f}s | "
                    f"准确率: {self.metrics.accuracy:.4f} | "
                    f"F1: {self.metrics.f1_score:.4f} | "
                    f"误报率: {self.metrics.false_positive_rate:.4f}")
        return self

    def _train_with_optimization(self, X_train, y_train, algorithm):
        """超参数优化训练。"""
        param_space = self._get_param_space(algorithm)
        base_model = self._create_base_model(algorithm, {})

        if self.use_bayes_opt and HAS_SKOPT:
            # 贝叶斯优化
            from skopt import BayesSearchCV
            from skopt.space import Real, Integer, Categorical

            # 转换参数空间
            search_spaces = {}
            for k, v in param_space.items():
                if all(isinstance(x, (int, np.integer)) for x in v):
                    search_spaces[k] = Integer(min(v), max(v))
                elif all(isinstance(x, (float, np.floating)) for x in v):
                    search_spaces[k] = Real(min(v), max(v))
                else:
                    search_spaces[k] = Categorical(v)

            try:
                n_iter = min(30, 10 * len(param_space))
                opt = BayesSearchCV(
                    base_model, search_spaces,
                    n_iter=n_iter, cv=min(3, self.cv_folds),
                    scoring='roc_auc', n_jobs=-1,
                    random_state=42, verbose=0
                )
                opt.fit(X_train, y_train)
                self.model = opt.best_estimator_
                self.best_params = opt.best_params_
                logger.info(f"贝叶斯优化完成 | 最佳参数: {opt.best_params_}")
                return
            except Exception as e:
                logger.warning(f"贝叶斯优化失败: {e}，回退随机搜索")

        # 随机搜索 (fallback)
        from sklearn.model_selection import RandomizedSearchCV
        n_iter = min(20, 5 * len(param_space))
        search = RandomizedSearchCV(
            base_model, param_space,
            n_iter=n_iter, cv=min(3, self.cv_folds),
            scoring='roc_auc', n_jobs=-1,
            random_state=42, verbose=0
        )
        search.fit(X_train, y_train)
        self.model = search.best_estimator_
        self.best_params = search.best_params_
        logger.info(f"随机搜索完成 | 最佳参数: {search.best_params_}")

    def _train_ensemble(self, X_train, y_train):
        """集成模型（软投票）。"""
        estimators = []

        # RF
        rf = RandomForestClassifier(n_estimators=300, max_depth=15,
                                     class_weight='balanced',
                                     random_state=42, n_jobs=-1)
        estimators.append(('rf', rf))

        # XGBoost
        if HAS_XGB:
            xgb = XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.08,
                                 subsample=0.8, colsample_bytree=0.8,
                                 eval_metric='logloss',
                                 random_state=42, n_jobs=-1, verbosity=0)
            estimators.append(('xgb', xgb))

        # LightGBM
        if HAS_LGBM:
            lgb = LGBMClassifier(n_estimators=250, max_depth=8, learning_rate=0.08,
                                  num_leaves=31, class_weight='balanced',
                                  random_state=42, n_jobs=-1, verbose=-1)
            estimators.append(('lgb', lgb))

        self.model = VotingClassifier(
            estimators=estimators,
            voting='soft',
            weights=[1, 1, 1]
        )
        logger.info(f"集成模型: {[e[0] for e in estimators]}")
        self.model.fit(X_train, y_train)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> ModelMetrics:
        """全面评估模型性能。"""
        if not self.is_trained and self.model is None:
            raise RuntimeError("模型尚未训练")

        # 使用最优阈值进行预测
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X_test)
            if proba.shape[1] >= 2:
                y_score = proba[:, 1]
                y_pred = (y_score >= self.threshold).astype(int)
            else:
                y_pred = self.model.predict(X_test)
                y_score = proba[:, 0] if proba.shape[1] == 1 else proba[:, 0]
        else:
            y_pred = self.model.predict(X_test)
            y_score = y_pred

        # 指标计算
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        # ROC AUC
        try:
            roc_auc = roc_auc_score(y_test, y_score)
        except Exception:
            roc_auc = 0.0

        # MCC
        mcc = matthews_corrcoef(y_test, y_pred)

        # 误报率
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        # 分类报告
        report = classification_report(y_test, y_pred, output_dict=False, zero_division=0)

        return ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            roc_auc=roc_auc,
            mcc=mcc,
            false_positive_rate=fpr,
            confusion_matrix=cm,
            best_threshold=self.threshold,
            classification_report=report,
        )

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """预测，使用最优阈值。"""
        if not self.is_trained or self.model is None:
            raise RuntimeError("模型尚未训练")

        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X)
            if proba.shape[1] >= 2:
                y_score = proba[:, 1]
            else:
                y_score = proba[:, 0]
            y_pred = (y_score >= self.threshold).astype(int)
        else:
            y_pred = self.model.predict(X)
            y_score = y_pred.astype(float)

        return y_pred, y_score

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """输出概率。"""
        if not self.is_trained or self.model is None:
            raise RuntimeError("模型尚未训练")
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)
        return np.zeros((X.shape[0], 2))

    def _get_feature_importance(self, feature_names: Optional[list] = None) -> dict:
        """提取特征重要性。"""
        if self.model is None:
            return {}

        importances = None
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
        elif hasattr(self.model, 'coef_'):
            importances = np.abs(self.model.coef_[0]) if self.model.coef_.ndim > 1 else np.abs(self.model.coef_)

        if importances is None:
            return {}

        # 处理集成模型
        if isinstance(self.model, VotingClassifier):
            # 取各模型平均
            all_imp = []
            for name, est in self.model.named_estimators_.items():
                if hasattr(est, 'feature_importances_'):
                    all_imp.append(est.feature_importances_)
            if all_imp:
                importances = np.mean(all_imp, axis=0)

        if importances is None:
            return {}

        names = feature_names or [f"f{i}" for i in range(len(importances))]
        top_n = min(20, len(names))
        top_idx = np.argsort(importances)[::-1][:top_n]
        return {
            'top_features': [
                {'name': names[i], 'importance': round(float(importances[i]), 4)}
                for i in top_idx
            ],
            'total_features': len(names),
        }

    def save(self, path: str = None, scaler=None, feature_names: Optional[list] = None) -> str:
        """保存模型与元数据。

        参数:
            scaler: 特征标准化器（StandardScaler），推理时需用同一 scaler 变换
            feature_names: 训练特征名列表（顺序与模型输入一致）
        """
        if path is None:
            os.makedirs(self.model_dir, exist_ok=True)
            path = os.path.join(self.model_dir, f"threat_model_{self.algorithm}.joblib")

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)

        if scaler is not None:
            self.scaler = scaler
        if feature_names:
            self.feature_names = list(feature_names)

        model_data = {
            'model': self.model,
            'algorithm': self.algorithm,
            'threshold': self.threshold,
            'best_params': self.best_params,
            'feature_importance': self.feature_importance,
            'metrics': self.metrics.to_dict() if self.metrics else {},
            'training_time': self.training_time,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names,
            'scaler': self.scaler,
        }
        joblib.dump(model_data, path)

        # 同时保存可读 JSON 报告
        report_path = path.replace('.joblib', '_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump({
                'algorithm': self.algorithm,
                'threshold': self.threshold,
                'metrics': self.metrics.to_dict() if self.metrics else {},
                'best_params': self.best_params,
                'feature_importance': self.feature_importance,
                'training_time_seconds': round(self.training_time, 2),
            }, f, indent=2, ensure_ascii=False)

        logger.info(f"✅ 模型已保存: {path}")
        return path

    def load(self, path: str) -> 'MLTrainer':
        """加载已训练的模型。"""
        if not os.path.exists(path):
            raise FileNotFoundError(f"模型文件不存在: {path}")

        model_data = joblib.load(path)
        self.model = model_data['model']
        self.algorithm = model_data.get('algorithm', 'unknown')
        self.threshold = model_data.get('threshold', 0.5)
        self.best_params = model_data.get('best_params', {})
        self.feature_importance = model_data.get('feature_importance', {})
        self.is_trained = model_data.get('is_trained', True)
        # 恢复推理所需的预处理元数据（旧模型可能缺失，由调用方重建）
        self.feature_names = model_data.get('feature_names', []) or []
        self.scaler = model_data.get('scaler', None)

        metrics_data = model_data.get('metrics', {})
        if metrics_data:
            self.metrics = ModelMetrics(**{
                k: v for k, v in metrics_data.items()
                if k in ModelMetrics.__dataclass_fields__
            })

        logger.info(f"✅ 模型已加载: {path} (算法: {self.algorithm}, "
                    f"准确率: {self.metrics.accuracy if self.metrics else 'N/A'})")
        return self

    @classmethod
    def quick_train(cls, X_train, y_train, X_test=None, y_test=None,
                    algorithm='xgboost', **kwargs) -> 'MLTrainer':
        """一键训练 + 评估。"""
        trainer = cls(**kwargs)
        trainer.train(X_train, y_train, X_test, y_test, algorithm=algorithm)
        return trainer

    def get_summary(self) -> dict:
        """获取模型摘要（供前端展示）。"""
        return {
            'algorithm': self.algorithm,
            'is_trained': self.is_trained,
            'threshold': self.threshold,
            'metrics': self.metrics.to_dict() if self.metrics else {},
            'best_params': self.best_params,
            'feature_importance': self.feature_importance,
            'training_time_seconds': round(self.training_time, 2),
        }


def train_and_evaluate(use_smote: bool = True, algorithm: str = 'xgboost',
                       n_samples: int = 10000) -> Tuple[MLTrainer, dict]:
    """便捷函数：完整训练+评估管道。"""
    from .pipeline import MLPipeline

    pipeline = MLPipeline(use_smote=use_smote)
    data = pipeline.run_pipeline(n_samples=n_samples)

    trainer = MLTrainer(use_bayes_opt=True)
    trainer.train(data['X_train'], data['y_train'],
                  data['X_test'], data['y_test'],
                  algorithm=algorithm,
                  feature_names=data['feature_names'])

    return trainer, trainer.get_summary()


if __name__ == '__main__':
    from pipeline import MLPipeline
    print("=" * 60)
    print("SecAgentX ML 模型训练")
    print("=" * 60)

    pipeline = MLPipeline(use_smote=True)
    data = pipeline.run_pipeline(n_samples=15000)

    print(f"\n数据: {data['info']}")
    print(f"训练集: {data['X_train'].shape}, 测试集: {data['X_test'].shape}")

    for algo in ['xgboost', 'lightgbm', 'random_forest', 'ensemble']:
        print(f"\n--- 训练 {algo} ---")
        trainer = MLTrainer(use_bayes_opt=True, threshold_tuning=True)
        trainer.train(data['X_train'], data['y_train'],
                      data['X_test'], data['y_test'],
                      algorithm=algo, feature_names=data['feature_names'])
        print(f"准确率: {trainer.metrics.accuracy:.4f} | "
              f"精确率: {trainer.metrics.precision:.4f} | "
              f"召回率: {trainer.metrics.recall:.4f} | "
              f"F1: {trainer.metrics.f1_score:.4f} | "
              f"误报率: {trainer.metrics.false_positive_rate:.4f}")
        trainer.save(f"model/threat_model_{algo}.joblib")

