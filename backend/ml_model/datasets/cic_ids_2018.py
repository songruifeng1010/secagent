"""CSE-CIC-IDS2018 预处理流量 CSV 适配器。

由于该数据集通常按日期/场景拆成多个文件，项目要求使用者先准备
``train.csv`` 和 ``test.csv`` 两个明确划分的汇总文件，避免适配器擅自
随机切分或把测试数据混入训练。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
import numpy as np

from .base import DatasetAdapter, DatasetSpec


CIC_IDS_2018_SPEC = DatasetSpec(
    name="cic-ids-2018",
    display_name="CSE-CIC-IDS2018",
    description="覆盖暴力破解、僵尸网络、DoS/DDoS、Web 攻击和内网渗透等场景。",
    train_files=("cic_ids_2018/train.csv", "cic-ids-2018/train.csv", "CSE-CIC-IDS2018_train.csv"),
    test_files=("cic_ids_2018/test.csv", "cic-ids-2018/test.csv", "CSE-CIC-IDS2018_test.csv"),
)


class CICIDS2018Adapter(DatasetAdapter):
    spec = CIC_IDS_2018_SPEC

    def load_splits(
        self,
        max_rows: int | None = None,
        sampling: str | None = None,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        self.train_path = self._find_file(self.spec.train_files, "训练集")
        self.test_path = self._find_file(self.spec.test_files, "测试集")
        mode = sampling or ("stratified" if max_rows else "full")
        return (
            self._read_limited(self.train_path, max_rows, sampling=mode),
            self._read_limited(self.test_path, max_rows, sampling=mode),
        )

    @classmethod
    def _read_limited(
        cls,
        path,
        max_rows: int | None,
        sampling: str = "head",
    ) -> pd.DataFrame:
        """分块读取 CSE 文件；max_rows 用于内存受限环境的显式抽样。"""
        import pandas as pd
        if not max_rows:
            return cls._normalize(cls._read_csv(path))
        if sampling == "stratified":
            return cls._read_stratified(path, int(max_rows))
        if sampling != "head":
            raise ValueError(f"不支持的 CSE 抽样方式: {sampling}")
        chunks = []
        remaining = int(max_rows)
        for chunk in pd.read_csv(path, chunksize=50000, low_memory=False, on_bad_lines="skip"):
            normalized = cls._normalize(chunk)
            take = normalized.head(remaining)
            chunks.append(take)
            remaining -= len(take)
            if remaining <= 0:
                break
        if not chunks:
            return pd.DataFrame()
        return pd.concat(chunks, ignore_index=True)

    @classmethod
    def _read_stratified(cls, path, max_rows: int, seed: int = 42) -> pd.DataFrame:
        """在整个文件范围内按标签做可复现的分层蓄水池抽样。

        与 ``head`` 抽样相比，这会覆盖整个日期/场景文件，避免受限训练
        只看到文件开头而造成严重的时间分布偏差。标签计数使用轻量首列
        扫描，特征数据仍按块读取，内存占用约为目标样本量。
        """
        import pandas as pd

        if max_rows <= 0:
            return cls._normalize(cls._read_csv(path))

        header = pd.read_csv(path, nrows=0)
        label_col = next(
            (c for c in header.columns if str(c).strip().lower() == "label"),
            None,
        )
        if label_col is None:
            raise ValueError(f"CSE 文件缺少 label/Label 列: {path}")

        counts = {"normal": 0, "attack": 0}
        for chunk in pd.read_csv(
            path,
            usecols=[label_col],
            chunksize=100_000,
            low_memory=False,
            on_bad_lines="skip",
        ):
            labels = chunk[label_col].map(
                lambda value: "normal"
                if str(value).strip().lower() in {"0", "normal", "benign"}
                else "attack"
            )
            value_counts = labels.value_counts()
            for label in counts:
                counts[label] += int(value_counts.get(label, 0))

        total = counts["normal"] + counts["attack"]
        if total == 0:
            return pd.DataFrame()
        targets = {
            "normal": min(counts["normal"], max(1, round(max_rows * counts["normal"] / total))),
            "attack": min(counts["attack"], max(1, round(max_rows * counts["attack"] / total))),
        }
        # 舍入后总数可能比上限多 1；优先从占比更大的类别扣除。
        while sum(targets.values()) > max_rows:
            label = max(targets, key=targets.get)
            if targets[label] > 1:
                targets[label] -= 1
            else:
                break

        rng = np.random.default_rng(seed)
        reservoirs: dict[str, pd.DataFrame] = {label: pd.DataFrame() for label in targets}
        reservoir_keys: dict[str, np.ndarray] = {
            label: np.empty(0, dtype=float) for label in targets
        }
        seen = {label: 0 for label in targets}

        for chunk in pd.read_csv(
            path,
            chunksize=50_000,
            low_memory=False,
            on_bad_lines="skip",
        ):
            frame = cls._normalize(chunk)
            normalized_labels = frame["label"]
            for label, target in targets.items():
                rows = frame.loc[normalized_labels == label].reset_index(drop=True)
                if rows.empty or target <= 0:
                    continue
                start = seen[label]
                positions = start + np.arange(1, len(rows) + 1)
                keys = rng.random(len(rows)) ** (1.0 / positions)
                seen[label] += len(rows)

                if len(reservoirs[label]) == 0:
                    combined = rows
                    combined_keys = keys
                else:
                    combined = pd.concat([reservoirs[label], rows], ignore_index=True)
                    combined_keys = np.concatenate(
                        [reservoir_keys[label], keys]
                    )
                if len(combined) > target:
                    keep = np.argpartition(
                        combined_keys, -target
                    )[-target:]
                    reservoirs[label] = combined.iloc[keep].reset_index(drop=True)
                    reservoir_keys[label] = combined_keys[keep]
                else:
                    reservoirs[label] = combined
                    reservoir_keys[label] = combined_keys

        result = pd.concat(
            [reservoirs[label] for label in targets if not reservoirs[label].empty],
            ignore_index=True,
        )
        return result.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    @staticmethod
    def _normalize(frame: pd.DataFrame) -> pd.DataFrame:
        frame = DatasetAdapter._normalize_label_column(frame)
        # CIC CSV 常带时间戳和高基数流标识；它们会造成严重记忆/泄漏风险。
        drop = []
        for column in frame.columns:
            key = str(column).strip().lower().replace(" ", "")
            if key in {"timestamp", "date", "time", "flowid", "flowid"}:
                drop.append(column)
        frame = frame.drop(columns=drop, errors="ignore")
        frame["label"] = frame["label"].map(
            lambda value: "normal" if str(value).strip().lower() in {"0", "normal", "benign"} else "attack"
        )
        return frame
