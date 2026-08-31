"""
MITRE ATT&CK 全量数据摄取器
从 MITRE CTI 官方仓库 (STIX 2.1 JSON) 下载并解析全部技术/子技术
https://github.com/mitre/cti
"""
import os
import sys
import json
import re
import httpx
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.utils.logger import setup_logger
logger = setup_logger("pipeline.mitre")

# ─── 配置 ───
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data", "mitre_attack"
)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "techniques.json")
THREAT_INTEL_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data", "threat_intel"
)
ACTORS_FILE = os.path.join(THREAT_INTEL_DIR, "actors.json")
MALWARE_FILE = os.path.join(THREAT_INTEL_DIR, "malware.json")

# MITRE 战术 ID → 中文名称
TACTIC_CN = {
    "TA0043": "侦察", "TA0042": "资源开发", "TA0001": "初始访问",
    "TA0002": "执行", "TA0003": "持久化", "TA0004": "权限提升",
    "TA0005": "防御绕过", "TA0006": "凭据访问", "TA0007": "发现",
    "TA0008": "横向移动", "TA0009": "收集", "TA0011": "命令与控制",
    "TA0010": "数据外传", "TA0040": "影响",
}


def extract_technique_data(stix_bundle: dict) -> dict:
    """从 STIX 2.1 Bundle 中提取攻击技术和战术"""
    tactics_map = {}  # tactic_id → tactic_info
    techniques_map = {}  # technique_id → technique_info
    relationships = []  # 关联关系

    for obj in stix_bundle.get("objects", []):
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        obj_type = obj.get("type")
        obj_id = obj.get("id", "")
        obj_name = obj.get("name", "")

        if obj_type == "x-mitre-tactic":
            tactic_id = obj.get("x_mitre_shortname", "")
            if not tactic_id:
                # 从 external_references 提取
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tactic_id = ref.get("external_id", "")
                        break
            tactics_map[obj_id] = {
                "id": tactic_id,
                "name": obj_name,
                "name_cn": TACTIC_CN.get(tactic_id, obj_name),
                "description": obj.get("description", "").replace("\\n", "\n"),
                "stix_id": obj_id,
            }

        elif obj_type == "attack-pattern":
            # 提取 MITRE ATT&CK ID
            attack_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id", "")
                    break
            if not attack_id:
                continue

            # 判断是主技术还是子技术
            is_sub = "." in attack_id
            parent_id = attack_id.split(".")[0] if is_sub else ""

            # 提取数据源、平台
            datasources = obj.get("x_mitre_data_sources", [])
            platforms = obj.get("x_mitre_platforms", [])
            permissions = obj.get("x_mitre_permissions_required", [])
            defense_bypassed = obj.get("x_mitre_defense_bypassed", [])
            impact_type = obj.get("x_mitre_impact_type", [])

            # 提取 kill_chain_phases → 对应战术
            tactic_ids = []
            tactic_names = []
            for kcp in obj.get("kill_chain_phases", []):
                if kcp.get("kill_chain_name") == "mitre-attack":
                    phase = kcp.get("phase_name", "")
                    # phase_name 转 TA ID
                    reverse_map = {v: k for k, v in TACTIC_CN.items()}
                    reverse_map.update({
                        "reconnaissance": "TA0043",
                        "resource-development": "TA0042",
                        "initial-access": "TA0001",
                        "execution": "TA0002",
                        "persistence": "TA0003",
                        "privilege-escalation": "TA0004",
                        "defense-evasion": "TA0005",
                        "credential-access": "TA0006",
                        "discovery": "TA0007",
                        "lateral-movement": "TA0008",
                        "collection": "TA0009",
                        "command-and-control": "TA0011",
                        "exfiltration": "TA0010",
                        "impact": "TA0040",
                    })
                    tid = reverse_map.get(phase, phase.upper())
                    tactic_ids.append(tid)
                    tactic_names.append(TACTIC_CN.get(tid, phase))

            technique = {
                "id": attack_id,
                "name": obj_name,
                "description": obj.get("description", "").replace("\\n", "\n"),
                "tactic_ids": tactic_ids,
                "tactic_names": tactic_names,
                "phase": tactic_ids[0] if tactic_ids else "",
                "platforms": platforms,
                "data_sources": datasources,
                "permissions_required": permissions,
                "defense_bypassed": defense_bypassed,
                "impact_type": impact_type,
                "detection": (obj.get("x_mitre_detection") or "").replace("\\n", "\n"),
                "mitigation": "",
                "is_sub": is_sub,
                "parent_id": parent_id,
                "sub_techniques": {},
                "related_cves": [],
                "scores": {
                    "impact": _calc_impact_score(obj),
                    "detectability": _calc_detectability(obj),
                    "defense_bypass": _calc_defense_bypass(obj),
                },
            }
            techniques_map[attack_id] = technique

        elif obj_type == "relationship":
            source = obj.get("source_ref", "")
            target = obj.get("target_ref", "")
            rel_type = obj.get("relationship_type", "")
            if source and target:
                relationships.append({
                    "source": source,
                    "target": target,
                    "type": rel_type,
                })

    # ─── 构建父子关系 ───
    parent_children = {}  # parent_id → [child_id, ...]
    for tid, tech in techniques_map.items():
        if tech["is_sub"]:
            pid = tech["parent_id"]
            if pid not in parent_children:
                parent_children[pid] = []
            parent_children[pid].append(tid)

    for pid, children in parent_children.items():
        if pid in techniques_map:
            for cid in children:
                if cid in techniques_map:
                    sub_name = techniques_map[cid]["name"]
                    techniques_map[pid]["sub_techniques"][cid] = {
                        "name": sub_name,
                        "description": techniques_map[cid]["description"],
                    }

    # ─── 关联战术 → 技术 ───
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            continue  # 已经在上面处理
        if obj.get("type") == "relationship":
            r_source = obj.get("source_ref", "")
            r_target = obj.get("target_ref", "")
            r_type = obj.get("relationship_type", "")
            if r_type == "subtechnique-of":
                # 已经在父子关系处理过了
                pass

    # 构建战术列表
    tactics_list = []
    for stix_id, info in tactics_map.items():
        tactics_list.append(info)

    # 按 kill chain 顺序排序战术
    order = {k: i for i, k in enumerate(TACTIC_CN.keys())}
    tactics_list.sort(key=lambda t: order.get(t["id"], 999))

    # 构建技术列表（仅主技术，子技术作为 sub_techniques 嵌入）
    main_techniques = [
        t for t in techniques_map.values()
        if not t["is_sub"]
    ]
    main_techniques.sort(key=lambda t: t["id"])

    # ─── 关联 CVE ───
    # 根据技术名称或描述中的关键字做初步关联
    cve_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "knowledge_data", "cve", "vulnerabilities.json"
    )
    if os.path.exists(cve_path):
        try:
            with open(cve_path, "r", encoding="utf-8") as f:
                cve_data = json.load(f)
            cve_list = cve_data.get("cve_database", [])
            _associate_cves(main_techniques, cve_list)
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    logger.info(
        f"MITRE 解析完成: {len(tactics_list)} 战术, "
        f"{len(main_techniques)} 主技术, "
        f"{sum(len(t.get('sub_techniques', {})) for t in main_techniques)} 子技术"
    )

    return {
        "tactics": tactics_list,
        "techniques": main_techniques,
        "meta": {
            "source": "MITRE CTI STIX 2.1",
            "source_url": MITRE_STIX_URL,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "total_techniques": len(main_techniques),
            "total_sub_techniques": sum(
                len(t.get("sub_techniques", {})) for t in main_techniques
            ),
        },
    }


def _mitre_reference(obj: dict) -> tuple[str, str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", ""), ref.get("url", "")
    return "", ""


def extract_threat_intel(stix_bundle: dict) -> tuple[dict, dict]:
    """从同一份官方 ATT&CK STIX 数据生成组织和恶意软件索引。

    不推断归属国家，不生成 YARA 规则；只保留 MITRE 发布的对象和关系。
    """
    objects = {
        obj.get("id"): obj for obj in stix_bundle.get("objects", [])
        if obj.get("id") and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    }
    groups = {}
    malware = {}
    for stix_id, obj in objects.items():
        external_id, url = _mitre_reference(obj)
        if not external_id:
            continue
        if obj.get("type") == "intrusion-set":
            groups[stix_id] = {
                "id": external_id,
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "description": obj.get("description", ""),
                "associated_malware": [],
                "associated_techniques": [],
                "references": [url] if url else [],
            }
        elif obj.get("type") == "malware":
            malware[stix_id] = {
                "id": external_id,
                "name": obj.get("name", ""),
                "type": ", ".join(obj.get("malware_types", [])),
                "platform": ", ".join(obj.get("x_mitre_platforms", [])),
                "description": obj.get("description", ""),
                "associated_actors": [],
                "associated_techniques": [],
                "references": [url] if url else [],
            }

    for rel in objects.values():
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "uses":
            continue
        source_id = rel.get("source_ref", "")
        target_id = rel.get("target_ref", "")
        target = objects.get(target_id, {})
        target_external_id, _ = _mitre_reference(target)
        if source_id in groups and target_id in malware:
            groups[source_id]["associated_malware"].append(malware[target_id]["name"])
            malware[target_id]["associated_actors"].append(groups[source_id]["name"])
        elif source_id in groups and target.get("type") == "attack-pattern":
            groups[source_id]["associated_techniques"].append(target_external_id)
        elif source_id in malware and target.get("type") == "attack-pattern":
            malware[source_id]["associated_techniques"].append(target_external_id)

    for entry in [*groups.values(), *malware.values()]:
        for key in ("associated_malware", "associated_actors", "associated_techniques"):
            if key in entry:
                entry[key] = sorted(set(filter(None, entry[key])))
    meta = {
        "source": "MITRE ATT&CK STIX 2.1",
        "source_url": MITRE_STIX_URL,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    return (
        {"actors": sorted(groups.values(), key=lambda x: x["id"]), "meta": meta},
        {"malware": sorted(malware.values(), key=lambda x: x["id"]), "meta": meta},
    )


def _calc_impact_score(obj: dict) -> float:
    """计算影响分 0~1"""
    impact_types = obj.get("x_mitre_impact_type", [])
    if impact_types:
        return min(1.0, len(impact_types) * 0.4)
    return 0.5


def _calc_detectability(obj: dict) -> float:
    """计算可检测性 0~1 (越高越容易被检测)"""
    data_sources = obj.get("x_mitre_data_sources", [])
    if data_sources:
        return min(1.0, len(data_sources) * 0.2)
    return 0.3


def _calc_defense_bypass(obj: dict) -> float:
    """计算防御绕过能力 0~1"""
    bypassed = obj.get("x_mitre_defense_bypassed", [])
    if bypassed:
        return min(1.0, len(bypassed) * 0.3)
    return 0.2


def _associate_cves(techniques: list, cve_list: list):
    """根据关键词将 CVE 关联到 MITRE 技术"""
    for tech in techniques:
        tech_name = tech["name"].lower()
        tech_desc = tech.get("description", "").lower()
        matched_cves = []
        for cve in cve_list:
            cve_desc = cve.get("description", "").lower()
            # 简单关键词匹配
            keywords = tech_name.split()
            for kw in keywords:
                if len(kw) > 3 and kw in cve_desc:
                    matched_cves.append(cve["id"])
                    break
        tech["related_cves"] = matched_cves[:5]


async def download_mitre_stix() -> dict:
    """从 MITRE CTI 仓库下载 STIX JSON"""
    logger.info(f"下载 MITRE STIX: {MITRE_STIX_URL}")
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.get(MITRE_STIX_URL)
        resp.raise_for_status()
        data = resp.json()
    logger.info(f"下载完成: {len(data.get('objects', []))} 个对象")
    return data


def has_local_data() -> bool:
    """检查是否已有本地数据"""
    if not os.path.exists(OUTPUT_FILE):
        return False


def sanitize_local_threat_intel() -> None:
    """清理旧版本地快照中不可验证的检测内容并补充来源标记。"""
    for path, collection, reference_kind in (
        (ACTORS_FILE, "actors", "groups"),
        (MALWARE_FILE, "malware", "software"),
    ):
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        for item in payload.get(collection, []):
            item.pop("yara_rule", None)
            external_id = item.get("id", "")
            if external_id:
                official = f"https://attack.mitre.org/{reference_kind}/{external_id}/"
                item["references"] = sorted(set([
                    *item.get("references", []), official
                ]))
        payload["meta"] = {
            **payload.get("meta", {}),
            "source": "MITRE ATT&CK-derived curated snapshot",
            "source_url": "https://attack.mitre.org/",
            "notice": "Static public-knowledge snapshot; not live threat telemetry.",
        }
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return len(data.get("techniques", [])) > 100
    except (json.JSONDecodeError, FileNotFoundError):
        return False


async def run(force_download: bool = False):
    """主入口"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 检查是否有本地数据
    if has_local_data() and not force_download:
        logger.info("本地已有完整数据 (≥100 技术)，跳过下载")
        return True

    try:
        stix_data = await download_mitre_stix()
        result = extract_technique_data(stix_data)
        actors, malware = extract_threat_intel(stix_data)

        os.makedirs(THREAT_INTEL_DIR, exist_ok=True)
        tmp_file = OUTPUT_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        os.replace(tmp_file, OUTPUT_FILE)
        for path, payload in ((ACTORS_FILE, actors), (MALWARE_FILE, malware)):
            tmp_path = path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, path)

        logger.info(f"数据已写入: {OUTPUT_FILE}")
        logger.info(
            f"统计: {len(result['tactics'])} 战术, "
            f"{len(result['techniques'])} 主技术, "
            f"{result['meta']['total_sub_techniques']} 子技术"
        )
        return True

    except Exception as e:
        logger.error(f"MITRE 数据摄取失败: {e}")
        # 如果有旧数据则保留
        if has_local_data():
            sanitize_local_threat_intel()
            logger.info("保留现有本地数据")
            return True
        # 尝试从本地缓存文件加载（如果有备份）
        backup_path = OUTPUT_FILE + ".bak"
        if os.path.exists(backup_path):
            import shutil
            shutil.copy(backup_path, OUTPUT_FILE)
            logger.info("从备份文件恢复")
            return True
        raise


if __name__ == "__main__":
    import asyncio
    force = "--force" in sys.argv
    asyncio.run(run(force_download=force))
