"""
数据流水线 — 从原始数据到训练就绪的特征矩阵

支持:
  - KDD Cup 99 / NSL-KDD 数据集（基于 DARPA 真实网络流量）
    - 来源: https://www.unb.ca/cic/datasets/nsl.html
    - 数据: 121,938 条网络流记录, 39 种攻击类型
    - 特征: 41 个网络流特征 (协议/服务/标志/流量统计等)
  - SMOTE 过采样
  - 特征工程与标准化
  - 混合编码 (数值标准化 + 类别独热)

注意:
  NSL-KDD 是 KDD Cup 99 的改进版本，解决了数据冗余和重复问题。
  虽然数据集较老（2009年发布），但它是网络安全 ML 领域最广泛使用的
  基准数据集之一，适合验证模型架构。生产环境建议使用更近期的数据集
  （如 CIC-IDS2017、UNSW-NB15）重新训练。
"""
import numpy as np
import pandas as pd
import os
import logging
from typing import Optional, Tuple
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from imblearn.over_sampling import SMOTE

logger = logging.getLogger("secagentx.ml")

# ─── KDD Cup 99 特征定义 ───
KDD_FEATURE_NAMES = [
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
    'dst_host_srv_rerror_rate', 'label'
]

CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
NUMERIC_FEATURES = [c for c in KDD_FEATURE_NAMES if c not in CATEGORICAL_FEATURES + ['label']]


class MLPipeline:
    """端到端数据流水线：加载 → 预处理 → 特征工程 → 划分 → 标准化 → SMOTE"""

    def __init__(self, use_smote: bool = True, test_size: float = 0.25,
                 random_state: int = 42, scale_data: bool = True):
        self.use_smote = use_smote
        self.test_size = test_size
        self.random_state = random_state
        self.scale_data = scale_data
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: list = []
        self.label_encoder: Optional[LabelEncoder] = None
        self.is_multiclass = False

    # ─── 真实数据加载 ───
    def load_nsl_kdd(self, train_path: str = 'dataset/KDDTrain.csv',
                     test_path: str = 'dataset/KDDTest.csv') -> pd.DataFrame:
        """加载 NSL-KDD 真实数据集。"""
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        train_path = os.path.join(project_root, train_path) if not os.path.isabs(train_path) else train_path
        test_path = os.path.join(project_root, test_path) if not os.path.isabs(test_path) else test_path

        cols = KDD_FEATURE_NAMES[:41] + ['label', 'difficulty']
        dfs = []
        for path in [train_path, test_path]:
            if os.path.exists(path):
                df = pd.read_csv(path, header=None, names=cols, on_bad_lines='skip')
                dfs.append(df)
                logger.info(f"加载 NSL-KDD: {path} ({len(df)} 条)")

        if not dfs:
            raise FileNotFoundError(f"NSL-KDD 数据集未找到: {train_path} 或 {test_path}")

        combined = pd.concat(dfs, ignore_index=True)
        combined['label'] = combined['label'].astype(str).str.strip().str.lower().str.rstrip('.')
        combined = combined.drop(columns=['difficulty'], errors='ignore')

        attack_counts = combined[combined['label'] != 'normal']['label'].value_counts()
        logger.info(f"NSL-KDD 加载完成: {len(combined)} 条, "
                    f"攻击类型: {len(attack_counts)} 种")
        return combined

    # ─── 预处理 ───
    def preprocess(self, df: pd.DataFrame, binary: bool = True
                   ) -> Tuple[np.ndarray, np.ndarray]:
        """完整预处理：编码 + 清洗。"""
        if 'label' not in df.columns:
            raise ValueError("数据缺少 'label' 列")

        df = df.copy()

        # 标签处理
        self.is_multiclass = not binary
        if binary:
            y = df['label'].apply(lambda x: 0 if str(x).strip().lower().rstrip('.') == 'normal' else 1).values.astype(int)
        else:
            le = LabelEncoder()
            y = le.fit_transform(df['label'].astype(str).str.strip().str.lower().str.rstrip('.'))
            self.label_encoder = le

        X_df = df.drop(columns=['label'])

        # 类别特征独热编码
        present_cats = [c for c in CATEGORICAL_FEATURES if c in X_df.columns]
        X_df = pd.get_dummies(X_df, columns=present_cats, drop_first=False)

        # 全部转为数值
        for col in X_df.columns:
            X_df[col] = pd.to_numeric(X_df[col], errors='coerce').fillna(0)

        self.feature_names = X_df.columns.tolist()
        X = X_df.values.astype(np.float64)

        logger.info(f"预处理完成: {len(X)} 样本, {X.shape[1]} 特征, "
                    f"{'二分类' if binary else f'多分类({len(np.unique(y))}类)'}")
        return X, y

    def split_and_scale(self, X: np.ndarray, y: np.ndarray
                        ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """划分训练/测试集 + 标准化 + SMOTE。"""
        # 划分
        stratify = y if len(np.unique(y)) > 1 else None
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.test_size, random_state=self.random_state,
            stratify=stratify
        )

        # 标准化
        if self.scale_data:
            self.scaler = StandardScaler()
            X_train = self.scaler.fit_transform(X_train)
            X_test = self.scaler.transform(X_test)

        # SMOTE — 仅对二分类使用
        if self.use_smote and not self.is_multiclass:
            unique_train, counts_train = np.unique(y_train, return_counts=True)
            if len(unique_train) > 1:
                min_class_count = counts_train.min()
                max_class_count = counts_train.max()
                if min_class_count < max_class_count * 0.5:
                    k_neighbors = min(5, min_class_count - 1) if min_class_count > 1 else 1
                    if k_neighbors >= 1:
                        try:
                            smote = SMOTE(random_state=self.random_state, k_neighbors=k_neighbors)
                            X_train, y_train = smote.fit_resample(X_train, y_train)
                            logger.info(f"SMOTE 过采样后训练集: {X_train.shape[0]} 样本")
                        except Exception as e:
                            logger.warning(f"SMOTE 跳过: {e}")

        return X_train, X_test, y_train, y_test

    def run_pipeline(self, df: Optional[pd.DataFrame] = None,
                     n_samples: int = 10000, binary: bool = True
                     ) -> dict:
        """一键执行完整流水线。"""
        # 加载数据
        if df is None:
            try:
                df = self.load_nsl_kdd()
                logger.info("✅ 使用 NSL-KDD 真实数据集")
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    "未找到 NSL-KDD 真实数据集；已禁止自动生成合成训练数据。"
                    "请提供 dataset/KDDTrain.csv 和 dataset/KDDTest.csv，或显式传入真实 DataFrame。"
                ) from exc

        X, y = self.preprocess(df, binary=binary)
        X_train, X_test, y_train, y_test = self.split_and_scale(X, y)

        info = f"真实标注数据: {len(df)} 条"

        return {
            'X_train': X_train, 'X_test': X_test,
            'y_train': y_train, 'y_test': y_test,
            'feature_names': self.feature_names,
            'scaler': self.scaler,
            'is_multiclass': self.is_multiclass,
            'label_encoder': self.label_encoder,
            'label_map': dict(enumerate(self.label_encoder.classes_)) if self.label_encoder else {},
            'info': info,
        }
