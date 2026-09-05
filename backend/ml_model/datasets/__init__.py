"""SecAgentX ML 数据集适配层。

数据集文件不随仓库分发；适配器只负责读取、校验和标准化标签，
不会下载数据或生成合成样本。
"""

from .base import DatasetAdapter, DatasetSpec
from .registry import DATASET_REGISTRY, get_dataset_adapter, list_dataset_specs

__all__ = [
    "DatasetAdapter",
    "DatasetSpec",
    "DATASET_REGISTRY",
    "get_dataset_adapter",
    "list_dataset_specs",
]
