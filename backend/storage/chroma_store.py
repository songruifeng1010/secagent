import os
from typing import Optional

try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False


PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "data/chromadb")


class VectorStore:
    def __init__(self, persist_dir: Optional[str] = None):
        self.persist_dir = persist_dir or PERSIST_DIR
        self._client = None
        self._collections: dict = {}

    def _ensure_client(self):
        if self._client is not None:
            return
        if not HAS_CHROMADB:
            raise RuntimeError("chromadb not installed: pip install chromadb")
        os.makedirs(self.persist_dir, exist_ok=True)
        self._client = chromadb.PersistentClient(
            path=self.persist_dir,
            settings=Settings(anonymized_telemetry=False),
        )

    def get_or_create_collection(self, name: str) -> any:
        self._ensure_client()
        if name not in self._collections:
            try:
                self._collections[name] = self._client.get_collection(name)
            except ValueError:
                self._collections[name] = self._client.create_collection(name)
        return self._collections[name]

    def add_documents(self, collection_name: str, ids: list[str],
                      documents: list[str], metadatas: Optional[list[dict]] = None,
                      embeddings: Optional[list[list[float]]] = None):
        coll = self.get_or_create_collection(collection_name)
        coll.add(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)

    def similarity_search(self, collection_name: str, query: str,
                          k: int = 5,
                          query_embeddings: Optional[list[float]] = None) -> list[dict]:
        coll = self.get_or_create_collection(collection_name)
        if query_embeddings:
            results = coll.query(query_embeddings=[query_embeddings], n_results=k,
                                 include=["documents", "metadatas", "distances"])
        else:
            results = coll.query(query_texts=[query], n_results=k,
                                 include=["documents", "metadatas", "distances"])
        items = []
        if not results["ids"]:
            return items
        for i in range(len(results["ids"][0])):
            items.append({
                "id": results["ids"][0][i],
                "document": results["documents"][0][i] if results["documents"] else "",
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "distance": results["distances"][0][i] if results["distances"] else 0.0,
            })
        return items

    def count(self, collection_name: str) -> int:
        coll = self.get_or_create_collection(collection_name)
        return coll.count()

    def delete_collection(self, name: str):
        self._ensure_client()
        try:
            self._client.delete_collection(name)
            self._collections.pop(name, None)
        except ValueError:
            pass
