"""UNSW-NB15 数据集适配器。"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd

from .base import DatasetAdapter, DatasetSpec


UNSW_NB15_SPEC = DatasetSpec(
    name="unsw-nb15",
    display_name="UNSW-NB15",
    description="包含正常流量和 9 类攻击的网络入侵检测数据集。",
    train_files=("UNSW_NB15_training-set.csv", "UNSW-NB15_training-set.csv", "unsw_nb15/train.csv"),
    test_files=("UNSW_NB15_testing-set.csv", "UNSW-NB15_testing-set.csv", "unsw_nb15/test.csv"),
)


class UNSWNB15Adapter(DatasetAdapter):
    spec = UNSW_NB15_SPEC

    def load_splits(
        self,
        max_rows: int | None = None,
        sampling: str | None = None,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        self.train_path = self._find_file(self.spec.train_files, "训练集")
        self.test_path = self._find_file(self.spec.test_files, "测试集")
        train = self._normalize(self._read_csv(self.train_path))
        test = self._normalize(self._read_csv(self.test_path))
        if max_rows:
            train, test = train.head(max_rows), test.head(max_rows)
        return train, test

    @staticmethod
    def _normalize(frame: pd.DataFrame) -> pd.DataFrame:
        frame = DatasetAdapter._normalize_label_column(frame)
        # id 和攻击子类不作为特征，避免把数据集内部编号/标签泄漏给模型。
        drop = [c for c in frame.columns if str(c).strip().lower() in {"id", "attack_cat"}]
        frame = frame.drop(columns=drop, errors="ignore")
        frame["label"] = frame["label"].map(
            lambda value: "normal" if str(value).strip().lower() in {"0", "normal", "benign"} else "attack"
        )
        return frame
