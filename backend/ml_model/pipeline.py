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
                 random_state: int = 42, scale_data: bool = True,
                 dataset_name: str = "nsl-kdd"):
        self.use_smote = use_smote
        self.test_size = test_size
        self.random_state = random_state
        self.scale_data = scale_data
        self.dataset_name = str(dataset_name or "nsl-kdd").strip().lower()
        self.dataset_metadata: dict = {}
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: list = []
        self.label_encoder: Optional[LabelEncoder] = None
        self.is_multiclass = False

    # ─── 真实数据加载 ───
    @staticmethod
    def _resolve_path(path: str) -> str:
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        return os.path.join(project_root, path) if not os.path.isabs(path) else path

    @classmethod
    def _resolve_dataset_file(cls, path: str, official_name: str) -> str:
        """解析数据文件；默认示例名不存在时兼容官方 ``+.txt`` 命名。"""
        resolved = cls._resolve_path(path)
        if os.path.exists(resolved):
            return resolved
        # 只对默认 dataset 路径做回退，显式传入的自定义路径仍应严格报错。
        default_name = os.path.join('dataset', official_name + '.csv')
        if path == default_name:
            fallback = cls._resolve_path(os.path.join('dataset', official_name + '+.txt'))
            if os.path.exists(fallback):
                return fallback
        return resolved

    @staticmethod
    def _read_nsl_frame(path: str) -> pd.DataFrame:
        """读取并规范化一个 NSL-KDD CSV 文件。"""
        cols = KDD_FEATURE_NAMES[:41] + ['label', 'difficulty']
        df = pd.read_csv(path, header=None, names=cols, on_bad_lines='skip')
        df['label'] = df['label'].astype(str).str.strip().str.lower().str.rstrip('.')
        return df.drop(columns=['difficulty'], errors='ignore')

    def load_nsl_kdd_splits(self, train_path: str = 'dataset/KDDTrain.csv',
                            test_path: str = 'dataset/KDDTest.csv') -> tuple[pd.DataFrame, pd.DataFrame]:
        """分别加载 NSL-KDD 官方训练集和测试集，严禁先合并再随机切分。"""
        train_path = self._resolve_dataset_file(train_path, 'KDDTrain')
        test_path = self._resolve_dataset_file(test_path, 'KDDTest')
        if not os.path.exists(train_path) or not os.path.exists(test_path):
            raise FileNotFoundError(
                f"NSL-KDD 训练/测试数据集未找到: {train_path} 或 {test_path}"
            )
        train_df = self._read_nsl_frame(train_path)
        test_df = self._read_nsl_frame(test_path)
        logger.info("加载 NSL-KDD 官方划分: train=%d, test=%d", len(train_df), len(test_df))
        return train_df, test_df

    def load_nsl_kdd(self, train_path: str = 'dataset/KDDTrain.csv',
                     test_path: str = 'dataset/KDDTest.csv') -> pd.DataFrame:
        """加载并合并 NSL-KDD 数据（兼容旧调用；训练流程使用 split 版本）。"""
        train_path = self._resolve_dataset_file(train_path, 'KDDTrain')
        test_path = self._resolve_dataset_file(test_path, 'KDDTest')
        dfs = [self._read_nsl_frame(path) for path in (train_path, test_path) if os.path.exists(path)]
        if not dfs:
            raise FileNotFoundError(f"NSL-KDD 数据集未找到: {train_path} 或 {test_path}")
        combined = pd.concat(dfs, ignore_index=True)

        attack_counts = combined[combined['label'] != 'normal']['label'].value_counts()
        logger.info(f"NSL-KDD 加载完成: {len(combined)} 条, "
                    f"攻击类型: {len(attack_counts)} 种")
        return combined

    # ─── 预处理 ───
    def preprocess(self, df: pd.DataFrame, binary: bool = True,
                   label_encoder: Optional[LabelEncoder] = None
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
            le = label_encoder or LabelEncoder()
            labels = df['label'].astype(str).str.strip().str.lower().str.rstrip('.')
            if label_encoder is None:
                y = le.fit_transform(labels)
            else:
                known = set(le.classes_)
                y = np.asarray([le.transform([v])[0] if v in known else -1 for v in labels])
            self.label_encoder = le

        X_df = df.drop(columns=['label'])

        # KDD 使用固定的三列类别字段；其他数据集按 object/category/bool 推断。
        if self.dataset_name == "nsl-kdd":
            present_cats = [c for c in CATEGORICAL_FEATURES if c in X_df.columns]
        else:
            # 流量 CSV 可能把异常值列识别为 object；禁止对高基数列做独热编码，
            # 否则一个列就可能产生数万维特征并耗尽内存。
            present_cats = []
            max_categories = 64
            for column in list(X_df.columns):
                dtype = str(X_df[column].dtype)
                if dtype not in {"object", "category", "bool"}:
                    continue
                unique_count = int(X_df[column].nunique(dropna=True))
                if unique_count <= max_categories:
                    present_cats.append(column)
                    continue
                numeric = pd.to_numeric(X_df[column], errors="coerce")
                if numeric.notna().mean() >= 0.9:
                    X_df[column] = numeric
                else:
                    logger.warning(
                        "跳过高基数文本特征 %s (%d categories)", column, unique_count
                    )
                    X_df = X_df.drop(columns=[column])
        X_df = pd.get_dummies(X_df, columns=present_cats, drop_first=False)

        # 部分流量数据导出时会出现重复表头；保留首列，避免按名称取值返回二维表。
        if X_df.columns.duplicated().any():
            duplicate_count = int(X_df.columns.duplicated().sum())
            logger.warning("去除重复特征列: %d", duplicate_count)
            X_df = X_df.loc[:, ~X_df.columns.duplicated()]

        # 全部转为数值
        for col in X_df.columns:
            X_df[col] = pd.to_numeric(X_df[col], errors='coerce').fillna(0)
        # CIC 流量速率字段可能包含 Infinity（除零结果）；训练前统一清洗。
        X_df = X_df.replace([np.inf, -np.inf], np.nan).fillna(0)

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

    def _postprocess_train_test(self, X_train: np.ndarray, X_test: np.ndarray,
                                y_train: np.ndarray, y_test: np.ndarray
                                ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """只在训练集拟合 scaler/SMOTE，避免测试数据泄漏。"""
        if self.scale_data:
            self.scaler = StandardScaler()
            X_train = self.scaler.fit_transform(X_train)
            X_test = self.scaler.transform(X_test)

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
                     n_samples: int = 10000, binary: bool = True,
                     dataset: Optional[str] = None, max_rows: Optional[int] = None,
                     sampling: Optional[str] = None
                     ) -> dict:
        """一键执行完整流水线。"""
        selected_dataset = str(dataset or self.dataset_name or "nsl-kdd").strip().lower()
        self.dataset_name = selected_dataset
        # 加载数据
        if df is None:
            try:
                if selected_dataset == "nsl-kdd":
                    train_df, test_df = self.load_nsl_kdd_splits()
                    self.dataset_metadata = {
                        "dataset": "nsl-kdd",
                        "version": "official",
                        "train_rows": len(train_df),
                        "test_rows": len(test_df),
                    }
                else:
                    from .datasets import get_dataset_adapter
                    adapter = get_dataset_adapter(selected_dataset)
                    train_df, test_df, self.dataset_metadata = adapter.load_and_validate(
                        max_rows=max_rows,
                        sampling=sampling,
                    )
                    if max_rows:
                        self.dataset_metadata["max_rows_per_split"] = int(max_rows)
                        self.dataset_metadata["sampling"] = sampling or "adapter_default"
                X_train, y_train = self.preprocess(train_df, binary=binary)
                train_features = list(self.feature_names)
                train_encoder = self.label_encoder
                X_test, y_test = self.preprocess(
                    test_df, binary=binary, label_encoder=train_encoder,
                )
                # 独热编码后的列集合可能不同，测试集按训练特征对齐并补零。
                test_features = list(self.feature_names)
                X_test = pd.DataFrame(X_test, columns=test_features).reindex(
                    columns=train_features, fill_value=0,
                ).to_numpy(dtype=np.float64)
                self.feature_names = train_features
                X_train, X_test, y_train, y_test = self._postprocess_train_test(
                    X_train, X_test, y_train, y_test,
                )
                info = (
                    f"{selected_dataset} 官方/指定划分: "
                    f"训练 {len(train_df)} 条，测试 {len(test_df)} 条"
                )
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
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"未找到或无法校验 {selected_dataset} 真实数据集；已禁止自动生成合成训练数据。"
                    "请按 dataset/README.md 准备官方训练/测试文件，或显式传入真实 DataFrame。"
                ) from exc

        X, y = self.preprocess(df, binary=binary)
        X_train, X_test, y_train, y_test = self.split_and_scale(X, y)

        info = f"{selected_dataset} 真实标注数据: {len(df)} 条"

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
