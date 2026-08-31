"""
CVE 漏洞库自动同步器。
从 NVD CVE API 2.0 拉取 CISA 已知被利用漏洞（KEV），支持：
- 仅收录有 NVD/CISA 可追溯记录的真实 CVE
- CWE 分类标签
- MITRE ATT&CK 自动映射（30+ 模式）
- 增量更新（保留手写检测/修复建议）
- 厂商/产品字段提取
- 元数据统计（严重程度分布）
"""
import os
import sys
import json
import time
import asyncio
import httpx
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.utils.logger import setup_logger
logger = setup_logger("pipeline.cve")

# ─── 配置 ───
OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data", "cve"
)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vulnerabilities.json")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 1.0       # 有 API Key 时可降到 0.6s
MAX_RETRIES = 3
MAX_CVES_TOTAL = 3000     # 目标最大数量限制
RESULTS_PER_PAGE = 500

# CWE 分类映射（CWSS 一级分类）
CWE_CATEGORY_MAP = {
    "CWE-20": "输入验证", "CWE-22": "路径遍历", "CWE-74": "注入",
    "CWE-77": "命令注入", "CWE-78": "OS命令注入", "CWE-79": "XSS",
    "CWE-89": "SQL注入", "CWE-94": "代码注入", "CWE-119": "内存破坏",
    "CWE-120": "缓冲区溢出", "CWE-125": "越界读取", "CWE-190": "整数溢出",
    "CWE-200": "信息泄露", "CWE-264": "权限问题", "CWE-269": "权限提升",
    "CWE-276": "默认权限不当", "CWE-287": "认证绕过", "CWE-295": "证书验证",
    "CWE-310": "密码学问题", "CWE-352": "CSRF", "CWE-362": "条件竞争",
    "CWE-400": "资源耗尽", "CWE-416": "释放后使用", "CWE-434": "文件上传",
    "CWE-476": "空指针", "CWE-502": "反序列化", "CWE-522": "凭据管理",
    "CWE-611": "XXE", "CWE-787": "越界写入", "CWE-798": "硬编码凭据",
    "CWE-862": "缺少授权", "CWE-863": "授权不正确", "CWE-918": "SSRF",
    "CWE-121": "栈缓冲区溢出", "CWE-122": "堆缓冲区溢出",
    "CWE-326": "密码强度不足", "CWE-327": "不安全加密算法",
    "CWE-444": "HTTP请求走私", "CWE-451": "UI误导",
    "CWE-532": "敏感信息日志", "CWE-601": "URL重定向",
    "CWE-754": "异常条件检查", "CWE-770": "资源分配",
}

# 增强 MITRE ATT&CK 映射表（30+ 模式）
CVE_TECH_MAP = {
    "rce|remote code|remote command|arbitrary code": ["T1190", "T1203"],
    "sql injection": ["T1190"],
    "xss|cross-site": ["T1189", "T1190"],
    "command injection|os injection": ["T1190", "T1059"],
    "buffer overflow|memory corruption|use-after-free|uaf": ["T1203", "T1068"],
    "privilege escalation|elevation of privilege|eop": ["T1068"],
    "authentication bypass|auth bypass|bypass authentication": ["T1190", "T1548"],
    "information disclosure|information leak|sensitive data": ["T1041", "T1530"],
    "denial of service|dos|ddos": ["T1498", "T1499"],
    "ransomware": ["T1486"],
    "backdoor|trojan": ["T1219", "T1071"],
    "phishing|spear phishing": ["T1566"],
    "ssrf|server-side request forgery": ["T1190", "T1557"],
    "xxe|xml external entity": ["T1190"],
    "deserialization|unserialize": ["T1190", "T1203"],
    "path traversal|directory traversal": ["T1190", "T1005"],
    "file upload|upload vulnerability": ["T1190", "T1505"],
    "hardcoded|hard-coded|default password": ["T1078", "T1552"],
    "man-in-the-middle|mitm|session hijack": ["T1557"],
    "supply chain|dependency confusion": ["T1195", "T1475"],
    "race condition|time-of-check": ["T1498"],
    "memory leak|out-of-memory": ["T1499"],
    "heap overflow|stack overflow": ["T1203"],
    "integer overflow|integer underflow": ["T1203"],
    "type confusion": ["T1203", "T1068"],
    "out-of-bounds|oob read|oob write": ["T1203"],
    "side channel|timing attack": ["T1059"],
    "dns spoof|dns cache poison": ["T1557", "T1568"],
    "http smuggling|request smuggling": ["T1190"],
    "clickjacking|ui redressing": ["T1189"],
    "open redirect": ["T1189", "T1566"],
    "csrf|cross-site request forgery": ["T1189"],
    "idor|insecure direct object": ["T1190"],
    "cors misconfiguration": ["T1190"],
    "websocket hijack": ["T1557"],
    "oauth misconfig|token theft": ["T1528", "T1557"],
    "kubernetes|k8s|container escape": ["T1611", "T1068"],
    "cloud|aws|azure|gcp|iam misconfig": ["T1525", "T1613"],
    "active directory|ad cs|kerberos": ["T1550", "T1558"],
    "vpn|ssl vpn|vulnerability": ["T1133", "T1190"],
    "kernel|kernelspace|kernel module": ["T1068", "T1203"],
    "browser|chromium|firefox|webkit": ["T1189", "T1203"],
    "firmware|uefi|bios": ["T1542"],
    "microsoft office|word|excel|ppt": ["T1566", "T1203"],
}


def _map_cve_to_techniques(cve_desc: str) -> list:
    """增强版 MITRE 映射 - 基于关键词多模式匹配"""
    desc = cve_desc.lower()
    matched = set()
    for pattern, tech_ids in CVE_TECH_MAP.items():
        keywords = pattern.split("|")
        if any(kw in desc for kw in keywords):
            for tid in tech_ids:
                matched.add(tid)
    return sorted(matched)[:8]


def _extract_vendor_product(cve_item: dict) -> str:
    """从 CVE item 提取厂商/产品名用于快速筛选"""
    vendors = set()
    try:
        for config in cve_item.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendors.add(f"{parts[3]}/{parts[4]}")
    except Exception:
        pass
    return ", ".join(sorted(vendors)[:5])


def _cwe_to_category(cwe_ids: list) -> str:
    """CWE ID → 攻击类型分类"""
    categories = set()
    for cwe in cwe_ids:
        if cwe in CWE_CATEGORY_MAP:
            categories.add(CWE_CATEGORY_MAP[cwe])
        # 前缀匹配
        prefix = cwe.rsplit("-", 1)[0] + "-"
        for cwe_id, cat in CWE_CATEGORY_MAP.items():
            if cwe.startswith(cwe_id.split("-")[0] + "-"):
                try:
                    cwe_num = int(cwe.split("-")[1])
                    start_num = int(cwe_id.split("-")[1])
                    if abs(cwe_num - start_num) < 50:
                        categories.add(cat)
                except (ValueError, IndexError):
                    pass
    return ", ".join(sorted(categories)[:3])


async def fetch_page(client: httpx.AsyncClient, params: dict) -> dict:
    """带重试的 API 请求"""
    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.get(NVD_API_BASE, params=params, timeout=90.0)
            if resp.status_code == 403:
                wait = min(120, 30 * (attempt + 1))
                logger.warning(f"NVD 403，等待 {wait}s...")
                await asyncio.sleep(wait)
                continue
            if resp.status_code == 404:
                return {"vulnerabilities": [], "totalResults": 0}
            resp.raise_for_status()
            return resp.json()
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.ConnectError) as e:
            if attempt < MAX_RETRIES - 1:
                wait = (attempt + 1) * 15
                logger.warning(f"请求失败: {e}, {wait}s 后重试...")
                await asyncio.sleep(wait)
            else:
                logger.error(f"请求最终失败: {e}")
                return {"vulnerabilities": [], "totalResults": 0}
    return {"vulnerabilities": [], "totalResults": 0}


def _parse_cve_entry(vuln: dict) -> dict | None:
    """解析单个 NVD CVE 条目为结构化知识"""
    try:
        cve_item = vuln.get("cve", {})
        cve_id = cve_item.get("id", "")
        if not cve_id:
            return None

        # 描述
        descriptions = cve_item.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d["value"]
                break
        if not description:
            description = descriptions[0]["value"] if descriptions else ""
        if not description:
            return None
        description = description[:3000]

        # CVSS 评分
        metrics = cve_item.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        severity = "UNKNOWN"
        for mt in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if mt in metrics and metrics[mt]:
                cvss_data = metrics[mt][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = _cvss_score_to_severity(cvss_score)
                break

        # CPE / 影响版本
        affected = _extract_affected_products(cve_item.get("configurations", []))

        # CWE
        weaknesses = cve_item.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc_entry in w.get("description", []):
                val = desc_entry.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        published = cve_item.get("published", "")[:10]
        last_modified = cve_item.get("lastModified", "")[:10]

        # MITRE 映射
        mitre_techniques = _map_cve_to_techniques(description)
        cwe_category = _cwe_to_category(cwe_ids)
        vendor_product = _extract_vendor_product(cve_item)

        return {
            "id": cve_id,
            "description": description,
            "severity": severity,
            "cvss_score": round(cvss_score, 1),
            "cvss_vector": cvss_vector,
            "cwe_ids": cwe_ids[:8],
            "cwe_category": cwe_category,
            "affected": affected[:800],
            "vendor_product": vendor_product,
            "published": published,
            "last_modified": last_modified,
            "source_identifier": cve_item.get("sourceIdentifier", ""),
            "vuln_status": cve_item.get("vulnStatus", ""),
            "references": [
                r.get("url", "") for r in cve_item.get("references", [])
                if r.get("url")
            ][:20],
            "cisa_kev": {
                "added": cve_item.get("cisaExploitAdd", ""),
                "action_due": cve_item.get("cisaActionDue", ""),
                "required_action": cve_item.get("cisaRequiredAction", ""),
                "vulnerability_name": cve_item.get("cisaVulnerabilityName", ""),
            },
            "mitre_techniques": mitre_techniques,
            "detection": _generate_detection(cve_id, description, cwe_category),
            "remediation": _generate_remediation(cve_id, description, severity),
            "impact": _generate_impact(severity),
            "last_synced": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.warning(f"解析CVE条目失败: {e}")
        return None


async def fetch_cves_by_range(client: httpx.AsyncClient, cvss_range: str,
                              existing: dict[str, dict],
                              cutoff_str: str, end_str: str) -> dict[str, dict]:
    """按 CVSS 范围拉取 CVE"""
    start_idx = 0
    total = None
    new_count = 0
    results = dict(existing)

    while True:
        params = {
            "pubStartDate": cutoff_str,
            "pubEndDate": end_str,
            "cvssScore": cvss_range,
            "startIndex": start_idx,
            "resultsPerPage": RESULTS_PER_PAGE,
        }

        data = await fetch_page(client, params)
        vulnerabilities = data.get("vulnerabilities", [])

        if total is None:
            total = data.get("totalResults", 0)
            logger.info(f"NVD [{cvss_range}] CVSS 范围: 共 {total} 条")

        if not vulnerabilities:
            break

        for vuln in vulnerabilities:
            cve_id = vuln.get("cve", {}).get("id", "")
            if not cve_id or cve_id in results:
                continue

            entry = _parse_cve_entry(vuln)
            if entry:
                results[cve_id] = entry
                new_count += 1

            # 达到上限则停止
            if len(results) >= MAX_CVES_TOTAL:
                logger.info(f"已达到最大限制 {MAX_CVES_TOTAL} 条，停止拉取")
                return results

        start_idx += RESULTS_PER_PAGE
        logger.info(f"  [{cvss_range}] 进度 {start_idx}/{total or '?'} | 本批新增 {new_count} | 总计 {len(results)}")

        await asyncio.sleep(REQUEST_DELAY)

        if total and start_idx >= total:
            break

    return results


async def sync_cves(api_key: str = "", force_full: bool = False) -> int:
    """同步 NVD 中带 CISA KEV 标记的漏洞。"""
    logger.info("=" * 60)
    logger.info("CVE 同步器 v2.0 启动")
    logger.info(f"  API Key: {'已配置' if api_key else '未配置（限流较严）'}")
    logger.info("  范围: CISA 已知被利用漏洞（KEV）")
    logger.info(f"  最大限制: {MAX_CVES_TOTAL} 条")
    logger.info("=" * 60)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 加载现有数据
    existing = {}
    if os.path.exists(OUTPUT_FILE) and not force_full:
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for cve in data.get("cve_database", []):
                existing[cve["id"]] = cve
            logger.info(f"现有本地 CVE: {len(existing)} 条")
        except Exception:
            pass

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    async with httpx.AsyncClient(headers=headers, timeout=90.0) as client:
        results = {} if force_full else dict(existing)
        start_idx = 0
        while len(results) < MAX_CVES_TOTAL:
            data = await fetch_page(client, {
                "hasKev": "",
                "startIndex": start_idx,
                "resultsPerPage": RESULTS_PER_PAGE,
            })
            page = data.get("vulnerabilities", [])
            if not page:
                break
            for vuln in page:
                entry = _parse_cve_entry(vuln)
                if entry:
                    results[entry["id"]] = entry
            start_idx += len(page)
            total = min(data.get("totalResults", start_idx), MAX_CVES_TOTAL)
            logger.info(f"  KEV 进度 {start_idx}/{total} | 已解析 {len(results)}")
            if start_idx >= total:
                break
            await asyncio.sleep(0.6 if api_key else 6.0)

    # 排序：CVSS 降序
    cve_list = sorted(results.values(), key=lambda x: (x.get("cvss_score", 0), x["id"]), reverse=True)

    # 统计分布
    sev_dist = {}
    for c in cve_list:
        s = c.get("severity", "UNKNOWN")
        sev_dist[s] = sev_dist.get(s, 0) + 1

    output = {
        "cve_database": cve_list,
        "meta": {
            "total": len(cve_list),
            "severity_distribution": sev_dist,
            "last_synced": datetime.now(timezone.utc).isoformat(),
            "source": "NVD API 2.0",
            "source_url": NVD_API_BASE + "?hasKev",
            "scope": "CISA Known Exploited Vulnerabilities (KEV)",
            "derived_fields": ["mitre_techniques", "detection", "remediation", "impact"],
        },
    }

    tmp_file = OUTPUT_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    os.replace(tmp_file, OUTPUT_FILE)

    logger.info(f"\n[OK] CVE 同步完成: {len(cve_list)} 条")
    logger.info(f"   分布: {sev_dist}")
    return len(cve_list)


# ═══════════════════════ 辅助函数 ═══════════════════════

def _cvss_score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >= 0.1: return "LOW"
    return "UNKNOWN"


def _extract_affected_products(configurations: list) -> str:
    parts = []
    for config in configurations[:3]:
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", [])[:8]:
                criteria = m.get("criteria", "")
                if criteria:
                    cpe_parts = criteria.split(":")
                    if len(cpe_parts) >= 5:
                        v = cpe_parts[3]
                        p = cpe_parts[4]
                        ver = cpe_parts[5] if len(cpe_parts) > 5 else "*"
                        parts.append(f"{v}/{p}:{ver}")
    return ", ".join(list(dict.fromkeys(parts))[:15])  # 去重有序


def _generate_detection(cve_id: str, desc: str, cwe_cat: str) -> str:
    desc_l = desc.lower()
    if "rce" in desc_l or "remote code" in desc_l:
        return f"监控 {cve_id} 相关服务异常进程/网络连接; 部署 WAF 虚拟补丁/WAF规则; EDR 检测可疑命令执行"
    if "sql" in desc_l:
        return "监控 SQL 查询异常模式; 部署 WAF SQL 注入规则; 审计数据库日志中的异常查询"
    if "xss" in desc_l:
        return "部署 WAF XSS 规则; 审计 Web 日志中的异常请求参数; 检测反射型/存储型 XSS payload"
    if "privilege" in desc_l or "elevation" in desc_l:
        return "监控权限变更事件 (Event ID 4672/4688); 审计认证日志中的异常 SID 历史"
    if "denial" in desc_l or "dos" in desc_l:
        return "监控网络流量异常峰值; 部署 DDoS 防护; 检查资源耗尽指标 (CPU/内存/连接数)"
    if "memory" in desc_l or "buffer" in desc_l:
        return "部署 EDR 内存保护; 监控异常进程崩溃; 启用 ASLR/CFG 缓解"
    if "bypass" in desc_l:
        return "监控认证绕过尝试; 审计登录日志中的异常成功登录; 检查 MFA 绕过迹象"
    if cwe_cat:
        return f"关注 {cve_id} 相关检测规则更新; CWE 分类: {cwe_cat}"
    return f"关注 {cve_id} 相关组件的异常行为; 及时更新检测规则和签名"


def _generate_remediation(cve_id: str, desc: str, severity: str) -> str:
    lines = [f"1. 升级受影响组件到最新版本（修复 {cve_id}）"]
    if severity in ("CRITICAL", "HIGH"):
        lines.append("2. ⚠ 如无法立即升级，应用厂商提供的临时缓解措施")
        lines.append("3. 检查环境中是否存在被利用痕迹，必要时启动事件响应流程")
    else:
        lines.append("2. 如无法升级，应用临时缓解措施或配置加固")
        lines.append("3. 按常规维护窗口安排补丁部署")
    return "\n".join(lines)


def _generate_impact(severity: str) -> str:
    impacts = {
        "CRITICAL": "可能导致远程代码执行、完全系统沦陷，影响范围广，建议立即修复",
        "HIGH": "可能导致敏感信息泄露、权限提升或服务中断，建议尽快修复",
        "MEDIUM": "可能导致有限影响的信息泄露或功能异常，按计划修复",
        "LOW": "影响较小，可在常规维护窗口修复",
        "UNKNOWN": "影响程度未定，建议评估后决定修复优先级",
    }
    return impacts.get(severity, "需要进行安全评估")


# ═══════════════════════ 入口 ═══════════════════════

async def run(api_key: str = "", force: bool = False) -> bool:
    """主入口"""
    try:
        count = await sync_cves(api_key=api_key, force_full=force)
        return count > 0
    except Exception as e:
        logger.error(f"CVE 同步失败: {e}")
        return False


if __name__ == "__main__":
    api_key = os.getenv("NVD_API_KEY", "")
    force = "--force" in sys.argv
    asyncio.run(run(api_key=api_key, force=force))
