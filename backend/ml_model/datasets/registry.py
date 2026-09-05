"""内置 ML 数据集注册表。"""

from __future__ import annotations

from .base import DatasetAdapter, DatasetSpec
from .cic_ids_2018 import CICIDS2018Adapter
from .nsl_kdd import NSLKDDAdapter
from .unsw_nb15 import UNSWNB15Adapter


DATASET_REGISTRY: dict[str, type[DatasetAdapter]] = {
    "nsl-kdd": NSLKDDAdapter,
    "unsw-nb15": UNSWNB15Adapter,
    "cic-ids-2018": CICIDS2018Adapter,
}


def get_dataset_adapter(name: str, root_dir=None) -> DatasetAdapter:
    key = str(name or "").strip().lower()
    if key not in DATASET_REGISTRY:
        supported = ", ".join(sorted(DATASET_REGISTRY))
        raise ValueError(f"未知数据集 {name!r}；支持: {supported}")
    return DATASET_REGISTRY[key](root_dir=root_dir)


def list_dataset_specs() -> list[DatasetSpec]:
    return [adapter().spec for adapter in DATASET_REGISTRY.values()]
