"""NSL-KDD 官方训练/测试划分适配器。"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd

from .base import DatasetAdapter, DatasetSpec


NSL_KDD_SPEC = DatasetSpec(
    name="nsl-kdd",
    display_name="NSL-KDD",
    description="经典网络入侵检测基准；仅用于可复现实验和回归测试。",
    train_files=("KDDTrain.csv", "KDDTrain+.txt", "KDDTrain+.csv"),
    test_files=("KDDTest.csv", "KDDTest+.txt", "KDDTest+.csv"),
)


class NSLKDDAdapter(DatasetAdapter):
    spec = NSL_KDD_SPEC

    # 41 个特征 + label + difficulty（官方 TXT 无表头）。
    COLUMNS = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
        "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
        "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
        "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
    ]

    def load_splits(
        self,
        max_rows: int | None = None,
        sampling: str | None = None,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        import pandas as pd
        self.train_path = self._find_file(self.spec.train_files, "训练集")
        self.test_path = self._find_file(self.spec.test_files, "测试集")
        train = pd.read_csv(self.train_path, header=None, names=self.COLUMNS, on_bad_lines="skip")
        test = pd.read_csv(self.test_path, header=None, names=self.COLUMNS, on_bad_lines="skip")
        for frame in (train, test):
            frame["label"] = frame["label"].astype(str).str.strip().str.lower().str.rstrip(".")
        return (
            train.drop(columns=["difficulty"], errors="ignore"),
            test.drop(columns=["difficulty"], errors="ignore"),
        )
