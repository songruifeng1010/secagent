#!/usr/bin/env python3
"""
知识库健康度检查脚本 v1.0
检查所有知识模块的数据完整性、最新程度和质量指标
用法:
    python scripts/quality/knowledge_health.py          # 完整报告
    python scripts/quality/knowledge_health.py --score  # 仅输出评分
"""
import json
import os
import sys
from datetime import datetime, timezone
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

KNOWLEDGE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge_data")


def _load_json(path):
    """安全加载JSON"""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return None


def check_mitre():
    path = os.path.join(KNOWLEDGE_DIR, "mitre_attack", "techniques.json")
    data = _load_json(path)
    if not data:
        return {"status": "[FAIL] 未构建", "score": 0}

    techs = data.get("techniques", [])
    tactics = data.get("tactics", [])
    sub_count = sum(len(t.get("sub_techniques", {})) for t in techs)
    with_detection = sum(1 for t in techs if t.get("detection"))
    with_mitigation = sum(1 for t in techs if t.get("mitigation"))
    with_cve = sum(1 for t in techs if t.get("related_cves"))

    completeness = (with_detection + with_mitigation) / max(len(techs) * 2, 1)
    score = min(100, round(
        60 * min(len(techs) / 365, 1) +  # 数量分
        20 * completeness +               # 质量分
        10 * min(len(data.get("tactics", [])) / 14, 1) +  # 战术覆盖
        10 * min(sub_count / 400, 1)      # 子技术
    ))
    return {
        "status": "[OK] 良好",
        "techniques": len(techs),
        "sub_techniques": sub_count,
        "tactics": len(tactics),
        "with_detection": with_detection,
        "with_mitigation": with_mitigation,
        "with_cve_references": with_cve,
        "completeness_pct": round(completeness * 100, 1),
        "score": score,
    }


def check_cve():
    path = os.path.join(KNOWLEDGE_DIR, "cve", "vulnerabilities.json")
    data = _load_json(path)
    if not data:
        return {"status": "[FAIL] 未构建", "score": 0}

    cves = data.get("cve_database", [])
    if not cves:
        return {"status": "[WARN] 空库", "score": 0}

    sev_dist = dict(Counter(c.get("severity", "UNKNOWN") for c in cves))
    with_mitre = sum(1 for c in cves if c.get("mitre_techniques"))
    with_cwe = sum(1 for c in cves if c.get("cwe_ids"))
    avg_cvss = round(sum(c.get("cvss_score", 0) for c in cves) / len(cves), 2) if cves else 0
    last = max((c.get("last_synced", "") for c in cves), default="")

    # 评分：每100条得5分，满分40；MITRE覆盖最高30；质量最高30
    count_score = min(40, len(cves) / 100 * 5)
    mitre_score = min(30, with_mitre / max(len(cves), 1) * 100 * 0.3)
    cwe_score = min(30, with_cwe / max(len(cves), 1) * 100 * 0.3)
    score = min(100, round(count_score + mitre_score + cwe_score))

    return {
        "status": "[OK] 良好" if len(cves) >= 100 else "[WARN] 待扩充",
        "total": len(cves),
        "severity_distribution": sev_dist,
        "with_mitre_mapping": with_mitre,
        "mitre_coverage_pct": round(with_mitre / len(cves) * 100, 1) if cves else 0,
        "with_cwe": with_cwe,
        "avg_cvss": avg_cvss,
        "last_synced": last[:10] if last else "未知",
        "score": score,
    }


def check_compliance():
    path = os.path.join(KNOWLEDGE_DIR, "compliance", "regulations.json")
    data = _load_json(path)
    if not data:
        return {"status": "[FAIL] 未构建", "score": 0}

    regs = data.get("regulations", [])
    jurisdictions = set()
    for r in regs:
        j = r.get("jurisdiction", "中国")
        jurisdictions.add(j)

    score = min(100, round(len(regs) * 7))
    return {
        "status": "[OK] 良好" if len(regs) >= 10 else "[WARN] 待扩充",
        "total": len(regs),
        "jurisdictions": list(jurisdictions),
        "score": score,
    }


def check_remediation():
    path = os.path.join(KNOWLEDGE_DIR, "remediation", "remediation.json")
    data = _load_json(path)
    if not data:
        return {"status": "[FAIL] 未构建", "score": 0}

    pbs = data.get("remediation_playbooks", [])
    total_actions = sum(len(p.get("immediate_actions", [])) for p in pbs)

    score = min(100, round(len(pbs) * 3 + total_actions * 0.5))
    return {
        "status": "[OK] 良好" if len(pbs) >= 15 else "[WARN] 待扩充",
        "total": len(pbs),
        "total_immediate_actions": total_actions,
        "scenarios": [p.get("scenario", "") for p in pbs],
        "score": score,
    }


def check_threat_intel():
    """威胁情报知识库"""
    actors_path = os.path.join(KNOWLEDGE_DIR, "threat_intel", "actors.json")
    malware_path = os.path.join(KNOWLEDGE_DIR, "threat_intel", "malware.json")

    actors_data = _load_json(actors_path)
    malware_data = _load_json(malware_path)

    actor_count = len(actors_data.get("actors", [])) if actors_data else 0
    malware_count = len(malware_data.get("malware", [])) if malware_data else 0

    if actor_count == 0 and malware_count == 0:
        return {"status": "[FAIL] 未构建", "score": 0}

    countries = {}
    if actors_data:
        for a in actors_data.get("actors", []):
            c = a.get("country", "未知")
            countries[c] = countries.get(c, 0) + 1

    score = min(100, round(actor_count * 2 + malware_count * 1.5))
    return {
        "status": "[OK] 良好" if (actor_count >= 20 and malware_count >= 20) else "[WARN] 待扩充",
        "actors": actor_count,
        "malware": malware_count,
        "countries": countries,
        "score": score,
    }


def validate_integrity():
    """验证发布知识快照的计数、唯一性和必要来源字段。"""
    specs = (
        ("threat_intel/actors.json", "actors", "total", "id"),
        ("threat_intel/malware.json", "malware", "total", "id"),
        ("compliance/regulations.json", "regulations", "total", "name"),
        ("remediation/remediation.json", "remediation_playbooks", "total", "scenario"),
        ("cve/vulnerabilities.json", "cve_database", "total", "id"),
    )
    errors = []
    checked = 0
    for relative, list_key, total_key, identity_key in specs:
        data = _load_json(os.path.join(KNOWLEDGE_DIR, *relative.split("/")))
        if not data:
            errors.append(f"{relative}: 文件缺失或 JSON 无效")
            continue
        items = data.get(list_key, [])
        checked += len(items)
        declared = data.get("meta", {}).get(total_key)
        if declared != len(items):
            errors.append(
                f"{relative}: meta.{total_key}={declared}, 实际={len(items)}"
            )
        identities = [str(item.get(identity_key, "")).strip() for item in items]
        missing = sum(not value for value in identities)
        duplicates = sorted(
            key for key, count in Counter(identities).items() if key and count > 1
        )
        if missing:
            errors.append(f"{relative}: {missing} 条缺少 {identity_key}")
        if duplicates:
            errors.append(f"{relative}: 重复 {identity_key}: {duplicates[:10]}")
        meta = data.get("meta", {})
        if relative.startswith(("cve/", "threat_intel/")) and not meta.get("source"):
            errors.append(f"{relative}: 缺少 meta.source")
    return {"status": "[OK] 通过" if not errors else "[FAIL] 不一致",
            "checked_records": checked, "errors": errors}


def generate_report():
    """生成完整健康报告"""
    mitre = check_mitre()
    cve = check_cve()
    compliance = check_compliance()
    remediation = check_remediation()
    threat_intel = check_threat_intel()
    integrity = validate_integrity()

    # 综合评分（加权）
    weights = {"mitre": 0.25, "cve": 0.25, "compliance": 0.15,
               "remediation": 0.15, "threat_intel": 0.20}
    overall = round(
        mitre.get("score", 0) * weights["mitre"] +
        cve.get("score", 0) * weights["cve"] +
        compliance.get("score", 0) * weights["compliance"] +
        remediation.get("score", 0) * weights["remediation"] +
        threat_intel.get("score", 0) * weights["threat_intel"]
    )

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_score": overall,
        "overall_level": "[EXCEL] 优秀" if overall >= 85 else ("[OK] 良好" if overall >= 60
                          else ("[WARN] 待改进" if overall >= 30 else "[FAIL] 差")),
        "modules": {
            "mitre_attack": mitre,
            "cve_database": cve,
            "compliance": compliance,
            "remediation": remediation,
            "threat_intel": threat_intel,
        },
        "weights": weights,
        "integrity": integrity,
    }
    return report


if __name__ == "__main__":
    report = generate_report()
    if "--score" in sys.argv:
        print(report["overall_score"])
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print()
        sep = "=" * 50
        print(sep)
        print(f"  综合知识库健康评分: {report['overall_score']}/100 — {report['overall_level']}")
        print(sep)
        for name, mod in report["modules"].items():
            s = mod.get("score", 0)
            bar = "#" * (s // 10) + "-" * (10 - s // 10)
            print(f"  {name:20s} {bar} {s:3d}/100 | {mod.get('status', '')}")
        if report["integrity"]["errors"]:
            print("  完整性错误:")
            for item in report["integrity"]["errors"]:
                print(f"    - {item}")
    if "--strict" in sys.argv and report["integrity"]["errors"]:
        raise SystemExit(1)
