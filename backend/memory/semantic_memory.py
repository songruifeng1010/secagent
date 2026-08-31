"""
SemanticMemory — 语义记忆（v2.4 M4）

长期向量记忆：将高价值事实（已确认 IOC、资产偏好、历史结论）写入 ChromaDB
独立 collection `session_memory`，支持：
  - add: 写入带置信度的语义事实
  - recall: 向量相似度召回（可用本地哈希嵌入降级）
  - forget: 按 ID 删除
  - count: 记忆条数

设计纪律:
  - 写入时必须带置信度阈值（低于阈值不沉淀，避免噪声污染长期记忆）
  - 召回结果带 distance 分数，低相似度（高距离）不注入
"""
import hashlib
import time
import logging
from typing import Optional

logger = logging.getLogger("secagentx.memory")

# 默认 collection 名
COLLECTION_NAME = "session_memory"
# 写入置信度阈值
MIN_CONFIDENCE_TO_STORE = 0.7
# 归一化距离阈值：超过则视为"不相关"，不注入
MAX_DISTANCE = 1.2

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# 嵌入维度（本地哈希降级方案）
EMBEDDING_DIM = 64


def _hash_embed(text: str) -> list[float]:
    """本地哈希嵌入降级方案（无模型时使用）：
    对文本提取 2~5-gram，以兼容哈希映射到固定维度，按词频归一化。
    """
    vec = [0.0] * EMBEDDING_DIM
    ngrams = set()
    for n in range(2, 6):
        for i in range(len(text) - n + 1):
            gram = text[i:i + n]
            # Keep persisted fallback vectors compatible. This is feature
            # bucketing and is explicitly not a security-sensitive hash.
            h = int(
                hashlib.md5(
                    gram.encode("utf-8"), usedforsecurity=False
                ).hexdigest(),
                16,
            )
            ngrams.add(h % EMBEDDING_DIM)
    for idx in ngrams:
        vec[idx] += 1.0
    norm = sum(x * x for x in vec) ** 0.5
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec


class SemanticMemory:
    """语义记忆 — 长期向量记忆（ChromaDB + 本地哈希降级）。"""

    def __init__(self, vector_store=None, min_confidence: float = MIN_CONFIDENCE_TO_STORE):
        self.vector_store = vector_store
        self.min_confidence = min_confidence

    def _store_ready(self) -> bool:
        return self.vector_store is not None

    def add(self, content: str, category: str = "general",
            confidence: float = 0.5, metadata: dict = None) -> Optional[str]:
        """写入一条语义记忆（低于置信度阈值不沉淀）。"""
        if confidence < self.min_confidence:
            logger.debug("语义记忆跳过低置信度事实: %.2f < %.2f", confidence, self.min_confidence)
            return None
        if not self._store_ready():
            return None
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
        mid = f"mem-{int(time.time() * 1000)}-{digest}"
        meta = dict(metadata or {})
        meta["category"] = category
        meta["confidence"] = confidence
        meta["created_at"] = time.time()
        try:
            emb = _hash_embed(content)
            self.vector_store.add_documents(
                COLLECTION_NAME,
                ids=[mid],
                documents=[content],
                metadatas=[meta],
                embeddings=[emb],
            )
            return mid
        except Exception as e:
            logger.debug("语义记忆写入失败（旁路）: %s", e)
            return None

    def recall(self, query: str, k: int = 5, category: str = None) -> list[dict]:
        """向量召回相似记忆，过滤距离过远 + 可选按类别过滤。"""
        if not self._store_ready():
            return []
        try:
            emb = _hash_embed(query)
            items = self.vector_store.similarity_search(
                COLLECTION_NAME, k=k * 3, query_embeddings=emb,
            )
            out = []
            for it in items:
                if it.get("distance", 0) > MAX_DISTANCE:
                    continue
                meta = it.get("metadata") or {}
                if category and meta.get("category") != category:
                    continue
                out.append({
                    "id": it.get("id"),
                    "content": it.get("document", ""),
                    "category": meta.get("category", "general"),
                    "confidence": meta.get("confidence", 0.5),
                    "distance": round(it.get("distance", 0), 4),
                    "created_at": meta.get("created_at", 0),
                })
            return out[:k]
        except Exception as e:
            logger.debug("语义记忆召回失败（旁路）: %s", e)
            return []

    def count(self) -> int:
        if not self._store_ready():
            return 0
        try:
            return self.vector_store.count(COLLECTION_NAME)
        except Exception:
            return 0

    def forget(self, mem_id: str) -> bool:
        """删除单条记忆（按 ID）。"""
        if not self._store_ready():
            return False
        try:
            coll = self.vector_store.get_or_create_collection(COLLECTION_NAME)
            coll.delete(ids=[mem_id])
            return True
        except Exception as e:
            logger.debug("语义记忆删除失败（旁路）: %s", e)
            return False

    def clear(self) -> bool:
        """清空全部语义记忆。"""
        if not self._store_ready():
            return False
        try:
            self.vector_store.delete_collection(COLLECTION_NAME)
            return True
        except Exception:
            return False


__all__ = ["SemanticMemory", "_hash_embed", "COLLECTION_NAME"]
