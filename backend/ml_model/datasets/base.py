"""ML 数据集适配器的通用契约。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd


@dataclass(frozen=True)
class DatasetSpec:
    """可审计的数据集描述，不包含实际数据文件。"""

    name: str
    display_name: str
    description: str
    train_files: Tuple[str, ...]
    test_files: Tuple[str, ...]
    label_columns: Tuple[str, ...] = ("label", "Label")
    version: str = "official"
    license_note: str = "请遵循原数据集许可并保留引用"
    extra: Dict[str, Any] = field(default_factory=dict)


class DatasetAdapter:
    """所有数据集适配器必须实现的最小接口。"""

    spec: DatasetSpec

    def __init__(self, root_dir: str | Path | None = None):
        project_root = Path(__file__).resolve().parents[3]
        self.root_dir = Path(root_dir) if root_dir else project_root / "dataset"

    def _find_file(self, candidates: Tuple[str, ...], split: str) -> Path:
        for candidate in candidates:
            path = self.root_dir / candidate
            if path.is_file():
                return path
        options = ", ".join(str(self.root_dir / item) for item in candidates)
        raise FileNotFoundError(
            f"{self.spec.display_name} {split} 文件未找到，已检查: {options}"
        )

    @staticmethod
    def _read_csv(path: Path) -> pd.DataFrame:
        import pandas as pd
        # NSL-KDD 的 .txt 也是无表头逗号分隔文件，统一交给 pandas 读取。
        return pd.read_csv(path, low_memory=False, on_bad_lines="skip")

    def load_splits(
        self,
        max_rows: int | None = None,
        sampling: str | None = None,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        raise NotImplementedError

    def validate(self, train_df: pd.DataFrame, test_df: pd.DataFrame) -> dict:
        """校验训练/测试集，返回可写入报告的统计信息。"""
        errors: list[str] = []
        for split, frame in (("train", train_df), ("test", test_df)):
            if frame is None or frame.empty:
                errors.append(f"{split} 数据为空")
                continue
            normalized = {str(c).strip().lower() for c in frame.columns}
            if "label" not in normalized:
                errors.append(f"{split} 缺少 label 列")
        if errors:
            raise ValueError(f"{self.spec.display_name} 数据校验失败: {'; '.join(errors)}")
        return {
            "dataset": self.spec.name,
            "version": self.spec.version,
            "train_rows": int(len(train_df)),
            "test_rows": int(len(test_df)),
            "train_columns": int(len(train_df.columns)),
            "test_columns": int(len(test_df.columns)),
            "train_file": str(getattr(self, "train_path", "")),
            "test_file": str(getattr(self, "test_path", "")),
        }

    @staticmethod
    def _normalize_label_column(frame: pd.DataFrame) -> pd.DataFrame:
        """将大小写不同的标签列统一为 ``label``。"""
        frame = frame.copy()
        label = next((c for c in frame.columns if str(c).strip().lower() == "label"), None)
        if label is None:
            raise ValueError("数据缺少 label/Label 列")
        if label != "label":
            frame = frame.rename(columns={label: "label"})
        return frame

    def load_and_validate(
        self,
        max_rows: int | None = None,
        sampling: str | None = None,
    ) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
        train_df, test_df = self.load_splits(max_rows=max_rows, sampling=sampling)
        train_df = self._normalize_label_column(train_df)
        test_df = self._normalize_label_column(test_df)
        metadata = self.validate(train_df, test_df)
        return train_df, test_df, metadata
