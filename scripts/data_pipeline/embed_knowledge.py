"""
知识库批量嵌入管道 (v2.0)
将 JSON 知识数据批量向量化并写入 ChromaDB

支持三种嵌入模式:
  1. BGE-small-zh-v1.5 (默认) — 中文优化语义嵌入，384维，推荐
  2. 本地哈希嵌入 (降级方案)  — 无网络依赖，召回率较低

用法:
    python scripts/data_pipeline/embed_knowledge.py            # 全量嵌入(BGE)
    python scripts/data_pipeline/embed_knowledge.py --reindex  # 重建索引
    python scripts/data_pipeline/embed_knowledge.py --hash     # 使用哈希嵌入
    python scripts/data_pipeline/embed_knowledge.py --status   # 查看索引状态
"""
import os
import sys
import json
import time
import hashlib
import math
import logging
import numpy as np
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.utils.logger import setup_logger

logger = setup_logger("pipeline.embed")

KNOWLEDGE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "knowledge_data")
CHROMA_PERSIST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "chromadb")
EMBEDDING_DIM = 512  # BGE-small-zh-v1.5 输出维度；哈希嵌入会自动适配此维度

# BGE 全局缓存
_BGE_MODEL = None


def _get_bge():
    """懒加载 BGE 模型"""
    global _BGE_MODEL
    if _BGE_MODEL is None:
        try:
            from sentence_transformers import SentenceTransformer
            import torch
            logger.info("加载 BGE-small-zh-v1.5 嵌入模型...")
            # 使用 CPU，显存紧张时也可运行
            _BGE_MODEL = SentenceTransformer(
                'BAAI/bge-small-zh-v1.5',
                device='cpu',
                model_kwargs={'trust_remote_code': True},
            )
            dim = _BGE_MODEL.get_sentence_embedding_dimension()
            logger.info(f"BGE 模型加载成功 (维度={dim})")
        except Exception as e:
            logger.warning(f"BGE 模型加载失败: {e}")
            logger.warning("将使用本地哈希嵌入作为降级方案")
            return None
    return _BGE_MODEL


def smart_embed(texts: list[str]) -> list[list[float]]:
    """
    智能嵌入：BGE 语义嵌入优先，哈希嵌入降级
    BGE 输出已经是归一化向量，可直接用于余弦相似度
    """
    model = _get_bge()
    if model is not None:
        try:
            vecs = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
            return vecs.tolist()
        except Exception as e:
            logger.warning(f"BGE 嵌入异常，降级到哈希: {e}")

    return local_embed(texts)


def local_embed(texts: list[str]) -> list[list[float]]:
    """
    本地哈希嵌入 — 不依赖外部模型下载
    使用 n-gram 哈希 + 归一化，产生 384 维向量
    """
    embeddings = []
    DIM = EMBEDDING_DIM

    for text in texts:
        vec = np.zeros(DIM, dtype=np.float32)
        ngrams = set()

        # 提取字符 n-gram (2-5 gram)
        for n in range(2, 6):
            for i in range(len(text) - n + 1):
                gram = text[i:i+n]
                h = int(hashlib.md5(gram.encode("utf-8")).hexdigest(), 16)
                idx = h % DIM
                ngrams.add(idx)

        for idx in ngrams:
            vec[idx] += 1.0

        # 归一化
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm

        embeddings.append(vec.tolist())

    return embeddings


def _build_mitre_documents(data: dict) -> tuple:
    documents, ids, metadatas = [], [], []

    for tech in data.get("techniques", []):
        tid = tech["id"]
        name = tech["name"]
        parts = [
            f"MITRE ATT&CK Technique: {tid} - {name}",
            f"战术阶段: {', '.join(tech.get('tactic_names', []))}",
            f"描述: {tech.get('description', '')[:2000]}" if tech.get("description") else "",
        ]
        if tech.get("detection"):
            parts.append(f"检测方法: {tech['detection'][:1000]}")
        if tech.get("mitigation"):
            parts.append(f"缓解措施: {tech['mitigation'][:1000]}")

        subs = tech.get("sub_techniques", {})
        if subs:
            sub_strs = []
            for sid, sinfo in list(subs.items())[:20]:
                sname = sinfo.get("name", str(sinfo)) if isinstance(sinfo, dict) else str(sinfo)
                sub_strs.append(f"  {sid}: {sname}")
            parts.append("子技术:\n" + "\n".join(sub_strs))

        documents.append("\n\n".join(parts))
        ids.append(f"mitre-{tid}")
        metadatas.append({
            "id": tid, "name": name,
            "tactic_names": json.dumps(tech.get("tactic_names", []), ensure_ascii=False),
            "phase": tech.get("phase", ""),
            "type": "mitre_technique",
        })

        # 子技术独立文档
        for sid, sinfo in list(subs.items())[:20]:
            sname = sinfo.get("name", str(sinfo)) if isinstance(sinfo, dict) else str(sinfo)
            sdesc = sinfo.get("description", "") if isinstance(sinfo, dict) else ""
            doc = [
                f"MITRE ATT&CK Sub-Technique: {sid} - {sname}",
                f"所属主技术: {tid} - {name}",
                f"描述: {sdesc[:1500]}" if sdesc else "",
            ]
            documents.append("\n\n".join(doc))
            ids.append(f"mitre-{sid}")
            metadatas.append({
                "id": sid, "name": sname, "parent_id": tid, "type": "mitre_sub_technique",
            })

    logger.info(f"MITRE 文档: {len(documents)} 条")
    return ids, documents, metadatas


def _build_cve_documents(data: dict) -> tuple:
    documents, ids, metadatas = [], [], []
    for cve in data.get("cve_database", []):
        cve_id = cve["id"]
        doc = [
            f"CVE: {cve_id}",
            f"严重程度: {cve.get('severity', 'N/A')}  CVSS: {cve.get('cvss_score', 'N/A')}",
            f"描述: {cve.get('description', '')[:2000]}",
        ]
        if cve.get("affected"):
            doc.append(f"影响范围: {cve['affected'][:500]}")
        if cve.get("remediation"):
            doc.append(f"修复建议: {cve['remediation'][:500]}")
        documents.append("\n\n".join(doc))
        ids.append(f"cve-{cve_id}")
        metadatas.append({
            "id": cve_id, "severity": cve.get("severity", "LOW"),
            "cvss_score": cve.get("cvss_score", 0.0),
            "type": "cve",
        })
    logger.info(f"CVE 文档: {len(documents)} 条")
    return ids, documents, metadatas


def _build_compliance_documents(data: dict) -> tuple:
    documents, ids, metadatas = [], [], []
    for reg in data.get("regulations", []):
        reg_id = reg.get("abbr", reg.get("name", "unknown"))
        doc = [
            f"合规: {reg.get('name', '')} ({reg.get('abbr', '')})",
            f"标准编号: {reg.get('standard_id', '')}",
            f"描述: {reg.get('description', '')[:2000]}",
        ]
        if reg.get("penalties"):
            doc.append(f"违规处罚: {reg['penalties'][:500]}")
        levels = reg.get("levels", [])
        if levels:
            level_strs = []
            for lv in levels[:3]:
                reqs = lv.get("requirements", [])
                if reqs:
                    level_strs.append(f"  {lv.get('name', '')}: " + "; ".join(reqs[:10]))
            if level_strs:
                doc.append("核心要求:\n" + "\n".join(level_strs))
        documents.append("\n\n".join(doc))
        ids.append(f"compliance-{reg_id}")
        metadatas.append({
            "id": reg_id, "name": reg.get("name", ""),
            "abbr": reg.get("abbr", ""), "type": "compliance",
        })
    logger.info(f"合规文档: {len(documents)} 条")
    return ids, documents, metadatas


def _build_remediation_documents(data: dict) -> tuple:
    documents, ids, metadatas = [], [], []
    for pb in data.get("remediation_playbooks", []):
        scenario = pb.get("scenario", "unknown")
        doc = [
            f"应急响应剧本: {scenario}",
            f"识别指标: {pb.get('indicators', '')[:500]}",
        ]
        immediate = pb.get("immediate_actions", [])
        if immediate:
            doc.append("立即处置:\n" + "\n".join(f"  - {a}" for a in immediate[:10]))
        medium = pb.get("medium_term", [])
        if medium:
            doc.append("中期措施:\n" + "\n".join(f"  - {a}" for a in medium[:5]))
        if pb.get("long_term"):
            doc.append(f"长期方案: {pb['long_term'][:500]}")
        documents.append("\n\n".join(doc))
        ids.append(f"remediation-{scenario.lower().replace(' ', '_')}")
        metadatas.append({"id": scenario, "scenario": scenario, "type": "remediation"})
    logger.info(f"应急响应文档: {len(documents)} 条")
    return ids, documents, metadatas


def _build_threat_intel_documents(data: dict) -> tuple:
    """构建威胁情报文档 — 攻击组织 + 恶意软件"""
    documents, ids, metadatas = [], [], []
    actor_count = 0
    malware_count = 0

    # 攻击组织
    for actor in data.get("actors", []):
        aid = actor["id"]
        name = actor["name"]
        doc = [
            f"攻击组织: {name} ({aid})",
            f"归属国家: {actor.get('country', '未知')}",
            f"动机: {actor.get('motivation', '')}",
            f"目标行业: {', '.join(actor.get('target_industries', []))}",
            f"目标国家: {', '.join(actor.get('target_countries', []))}",
            f"描述: {actor.get('description', '')[:2000]}",
        ]
        techniques = actor.get("associated_techniques", [])
        if techniques:
            doc.append(f"关联MITRE技术: {', '.join(techniques[:15])}")
        malware = actor.get("associated_malware", [])
        if malware:
            doc.append(f"关联恶意软件: {', '.join(malware[:10])}")
        cves = actor.get("associated_cves", [])
        if cves:
            doc.append(f"关联CVE: {', '.join(cves[:8])}")

        documents.append("\n\n".join(doc))
        ids.append(f"actor-{aid}")
        metadatas.append({
            "id": aid, "name": name, "type": "actor",
            "country": actor.get("country", ""),
        })
        actor_count += 1

    # 恶意软件
    for mw in data.get("malware", []):
        mid = mw["id"]
        name = mw["name"]
        doc = [
            f"恶意软件: {name} ({mid})",
            f"类型: {mw.get('type', '')}",
            f"平台: {mw.get('platform', '')}",
            f"描述: {mw.get('description', '')[:2000]}",
        ]
        actors = mw.get("associated_actors", [])
        if actors:
            doc.append(f"关联组织: {', '.join(actors[:8])}")
        techniques = mw.get("associated_techniques", [])
        if techniques:
            doc.append(f"关联MITRE技术: {', '.join(techniques[:10])}")
        documents.append("\n\n".join(doc))
        ids.append(f"malware-{mid}")
        metadatas.append({
            "id": mid, "name": name, "type": "malware",
            "malware_type": mw.get("type", ""),
        })
        malware_count += 1

    logger.info(f"威胁情报文档: {actor_count} actors + {malware_count} malware = {len(documents)} 条")
    return ids, documents, metadatas


BUILDERS = {
    "mitre_techniques": _build_mitre_documents,
    "cve_database": _build_cve_documents,
    "compliance": _build_compliance_documents,
    "remediation": _build_remediation_documents,
    "threat_intel": _build_threat_intel_documents,
}


def embed_all(reindex: bool = False, use_hash: bool = False) -> dict:
    """
    将所有知识源嵌入到 ChromaDB

    Args:
        reindex: 是否重建所有索引
        use_hash: 是否强制使用哈希嵌入（默认使用 BGE）
    """
    try:
        import chromadb
        from chromadb.config import Settings
        import chromadb.errors
    except ImportError:
        logger.error("chromadb 未安装: pip install chromadb")
        return {"success": False, "error": "chromadb not installed"}

    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)

    if use_hash:
        logger.info("嵌入模式: 本地哈希 (轻量, 召回率较低)")
        embed_fn = local_embed
    else:
        logger.info("嵌入模式: BGE-small-zh-v1.5 (语义嵌入, 推荐)")
        # 预加载测试
        model = _get_bge()
        if model is None:
            logger.warning("BGE 不可用，降级到哈希嵌入")
            embed_fn = local_embed
        else:
            embed_fn = smart_embed

    client = chromadb.PersistentClient(
        path=CHROMA_PERSIST_DIR,
        settings=Settings(anonymized_telemetry=False),
    )

    results = {}
    collections_config = [
        ("mitre_techniques", os.path.join(KNOWLEDGE_DIR, "mitre_attack", "techniques.json")),
        ("cve_database", os.path.join(KNOWLEDGE_DIR, "cve", "vulnerabilities.json")),
        ("compliance", os.path.join(KNOWLEDGE_DIR, "compliance", "regulations.json")),
        ("remediation", os.path.join(KNOWLEDGE_DIR, "remediation", "remediation.json")),
        ("threat_intel", os.path.join(KNOWLEDGE_DIR, "threat_intel", "actors.json"),
         os.path.join(KNOWLEDGE_DIR, "threat_intel", "malware.json")),
    ]

    for entry in collections_config:
        coll_name = entry[0]
        data_paths = entry[1:]

        logger.info(f"\n{'='*50}")
        logger.info(f"处理 collection: {coll_name}")

        # 检查数据文件是否存在
        if coll_name == "threat_intel":
            # 威胁情报需要合并两个文件
            combined = {"actors": [], "malware": []}
            all_ok = True
            for p in data_paths:
                if os.path.exists(p):
                    try:
                        with open(p, "r", encoding="utf-8") as f:
                            part = json.load(f)
                        if "actors" in part:
                            combined["actors"].extend(part["actors"])
                        if "malware" in part:
                            combined["malware"].extend(part["malware"])
                    except Exception as e:
                        logger.warning(f"读取 {p} 失败: {e}")
                        all_ok = False
                else:
                    logger.warning(f"文件不存在: {p}")
                    all_ok = False
            if not all_ok or (not combined["actors"] and not combined["malware"]):
                logger.warning(f"跳过: {coll_name} (无数据)")
                continue
            data = combined
        else:
            data_path = data_paths[0]
            if not os.path.exists(data_path):
                logger.warning(f"数据文件不存在: {data_path}")
                continue
            with open(data_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        builder = BUILDERS[coll_name]
        ids, documents, metadatas = builder(data)

        if not ids:
            logger.warning(f"跳过: {coll_name} (无文档)")
            continue

        # 重建模式
        if reindex:
            try:
                client.delete_collection(coll_name)
                logger.info(f"删除旧 collection: {coll_name}")
            except (ValueError, chromadb.errors.NotFoundError):
                pass
            collection = client.create_collection(coll_name)
            logger.info(f"创建新 collection: {coll_name}")
        else:
            try:
                collection = client.get_collection(coll_name)
                existing = collection.count()
                if existing >= len(ids) * 0.8:
                    logger.info(f"跳过: {coll_name} 已有 {existing}/{len(ids)} 条")
                    results[coll_name] = {"status": "skipped", "total": existing}
                    continue
                # 增量
                existing_ids = set(collection.get()["ids"])
                new_ids, new_docs, new_metas = [], [], []
                for i, did in enumerate(ids):
                    if did not in existing_ids:
                        new_ids.append(did)
                        new_docs.append(documents[i])
                        new_metas.append(metadatas[i])
                if not new_ids:
                    logger.info(f"无新数据: {coll_name}")
                    results[coll_name] = {"status": "skipped", "total": existing}
                    continue
                ids, documents, metadatas = new_ids, new_docs, new_metas
                logger.info(f"增量新增: {len(ids)} 条")
            except (ValueError, chromadb.errors.NotFoundError):
                collection = client.create_collection(coll_name)
                logger.info(f"创建新 collection: {coll_name}")

        # 批量嵌入
        batch_size = 64
        total = len(ids)

        logger.info(f"开始嵌入 {total} 条 (批大小={batch_size})...")
        start_time = time.time()

        for start in range(0, total, batch_size):
            end = min(start + batch_size, total)
            batch_ids = ids[start:end]
            batch_docs = documents[start:end]
            batch_metas = metadatas[start:end]

            embeddings = embed_fn(batch_docs)
            collection.add(
                ids=batch_ids,
                documents=batch_docs,
                metadatas=batch_metas,
                embeddings=embeddings,
            )

            elapsed = time.time() - start_time
            rate = end / elapsed if elapsed > 0 else 0
            logger.info(f"  [{start+1}-{end}/{total}] {rate:.0f}条/秒")

        final_count = collection.count()
        elapsed = time.time() - start_time
        logger.info(f"完成: {coll_name} = {final_count} 条 ({elapsed:.1f}s)")
        results[coll_name] = {"status": "ok", "total": final_count, "time_s": round(elapsed, 1)}

    # 摘要
    logger.info(f"\n{'='*50}")
    logger.info("嵌入完成摘要")
    logger.info(f"{'='*50}")
    total = 0
    for coll, res in results.items():
        logger.info(f"  {coll}: {res.get('total', 0)} 条 [{res.get('status', '?')}]")
        total += res.get("total", 0)
    logger.info(f"  总计: {total} 条嵌入向量")
    logger.info(f"  存储: {CHROMA_PERSIST_DIR}")

    return {"success": True, "results": results, "total": total}


def show_status():
    """查看 ChromaDB 索引状态"""
    try:
        import chromadb
        from chromadb.config import Settings
    except ImportError:
        logger.error("chromadb 未安装")
        return

    client = chromadb.PersistentClient(
        path=CHROMA_PERSIST_DIR,
        settings=Settings(anonymized_telemetry=False),
    )

    print(f"\n{'='*50}")
    print(f"  ChromaDB 索引状态")
    print(f"{'='*50}")
    total = 0
    for col in client.list_collections():
        n = col.count()
        total += n
        print(f"  {col.name:25s} {n:6d} 条")
    print(f"  {'─'*35}")
    print(f"  {'总计':25s} {total:6d} 条")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    reindex = "--reindex" in sys.argv
    use_hash = "--hash" in sys.argv

    if "--status" in sys.argv:
        show_status()
        sys.exit(0)

    use_bge = not use_hash
    logger.info(f"BGE 模式: {'启用' if use_bge else '禁用(哈希)'}")
    result = embed_all(reindex=reindex, use_hash=use_hash)
    if not result.get("success"):
        sys.exit(1)
    sys.exit(0)
