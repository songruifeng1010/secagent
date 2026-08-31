#!/usr/bin/env python3
"""
SecAgentX 真实威胁情报 IP 更新器

从公开威胁情报源获取真实恶意 IP（已验证可达）:
  1. FireHOL Level 1     — 确认的恶意 IP，社区维护，每日更新
  2. Darklist ipsum      — 实时恶意 IP 排行榜，按威胁等级排序
  3. FireHOL Level 2     — 额外恶意 IP 集
  4. DShield             — SANS ISC 推荐封禁 IP
  5. Spamhaus DROP       — Spamhaus 拒绝路由列表

所有数据均为公开威胁情报，来源可追溯、可验证。
缓存保护：若远程不可达，保留已有数据不覆盖。
"""
import os, sys, json, ipaddress, logging, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Set, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("threat_ips")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

WORKING_FEEDS = {
    "firehol_level1": {
        "url": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
        "desc": "FireHOL Level 1 — 确认恶意 IP",
        "threat_type": "综合恶意活动",
    },
    "darklist_ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "desc": "Darklist ipsum — 实时恶意 IP 排行榜",
        "threat_type": "综合恶意活动",
        "parser": "tab",
    },
    "firehol_level2": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        "desc": "FireHOL Level 2 — 扩展恶意 IP 集",
        "threat_type": "综合恶意活动",
    },
    "dshield": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
        "desc": "DShield — SANS ISC 推荐封禁",
        "threat_type": "扫描/攻击",
    },
    "spamhaus_drop": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
        "desc": "Spamhaus DROP — 拒绝路由列表",
        "threat_type": "垃圾邮件/恶意",
    },
}

BENIGN_NETWORKS = [
    "8.8.8.8/32", "8.8.4.4/32", "1.1.1.0/24", "1.0.0.1/32",
    "9.9.9.9/32", "208.67.222.222/32", "208.67.220.220/32",
    "13.107.42.0/24", "52.84.0.0/15", "151.101.0.0/16",
]

def normalize_ip(raw: str):
    raw = raw.strip().strip('"').strip("'")
    if not raw: return None
    try:
        ip = ipaddress.ip_address(raw)
        if ip.version == 4 and not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return str(ip)
    except: pass
    return None

def is_benign(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in ipaddress.ip_network(n, strict=False) for n in BENIGN_NETWORKS)
    except: return False

def fetch_single(feed_name, feed_config):
    import urllib.request, ssl
    # 使用系统 CA 验证远端公开情报源，拒绝中间人伪造的黑名单数据。
    ctx = ssl.create_default_context()

    result = {"source": feed_name, "fetched": False, "total_raw": 0, "valid_ips": 0, "error": None, "ips": []}
    try:
        req = urllib.request.Request(feed_config["url"], headers={"User-Agent": "SecAgentX/2.1"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="replace")

        lines = content.strip().split('\n')
        parser_type = feed_config.get("parser", "plain")

        raw_ips = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'): continue
            if parser_type == "tab":
                parts = line.split('\t')
                raw_ips.append(parts[0].strip())
            else:
                raw_ips.append(line.split('/')[0].split(':')[0].strip())

        result["total_raw"] = len(raw_ips)
        valid = set()
        for rip in raw_ips:
            n = normalize_ip(rip)
            if n and not is_benign(n): valid.add(n)

        result["valid_ips"] = len(valid)
        result["ips"] = sorted(valid)
        result["fetched"] = True
        log.info(f"  ✅ {feed_name:20s} {result['total_raw']:>8,} 原始 → {result['valid_ips']:>8,} 有效")
    except Exception as e:
        result["error"] = str(e)
        log.warning(f"  ⚠️ {feed_name:20s} {str(e)[:60]}")

    return result

def fetch_all(max_workers=4):
    log.info("\n📡 获取公开威胁情报 IP...")
    log.info("=" * 60)
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fm = {ex.submit(fetch_single, n, c): n for n, c in WORKING_FEEDS.items()}
        for f in as_completed(fm):
            try: results[fm[f]] = f.result()
            except Exception as e: results[fm[f]] = {"source": fm[f], "fetched": False, "ips": [], "error": str(e)}
    return results

def merge(results):
    all_ips: Dict[str, Set[str]] = {}
    for fn, r in results.items():
        for ip in r.get("ips", []):
            all_ips.setdefault(ip, set()).add(fn)

    merged = {
        "meta": {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_unique_ips": len(all_ips),
            "source_stats": {fn: len(r.get("ips", [])) for fn, r in results.items()},
            "sources_used": sorted(results.keys()),
            "threat_distribution": {"high": 0, "medium": 0, "low": 0},
        },
        "ips": {},
    }

    for ip, sources in sorted(all_ips.items()):
        n = len(sources)
        level = "high" if n >= 3 else ("medium" if n >= 2 else "low")
        merged["meta"]["threat_distribution"][level] += 1
        merged["ips"][ip] = {
            "sources": sorted(sources),
            "threat_level": level,
            "first_seen": datetime.now(timezone.utc).isoformat(),
        }

    return merged

def save(data):
    out = str(PROJECT_ROOT / "data" / "blacklist" / "threat_ips.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    txt = str(PROJECT_ROOT / "data" / "blacklist" / "threat_ips.txt")
    with open(txt, "w") as f:
        for ip in data["ips"]: f.write(ip + "\n")

    return out, txt

def main():
    results = fetch_all()
    # 注意: 不直接使用 merge(results)，改用增量合并逻辑

    # 加载已有缓存（若有）
    existing_path = str(PROJECT_ROOT / "data" / "blacklist" / "threat_ips.json")
    cached: dict = {}
    cached_ips: Dict[str, Set[str]] = {}
    if os.path.exists(existing_path):
        with open(existing_path) as f:
            cached = json.load(f)
        for ip, info in cached.get("ips", {}).items():
            cached_ips[ip] = set(info.get("sources", []))
        log.info(f"\n📂 加载已有缓存: {len(cached_ips):,} 个 IP")

    # 增量合并：新 IP ∪ 缓存 IP（永不丢失数据）
    merged_ips: Dict[str, Set[str]] = {}
    for ip, sources_set in cached_ips.items():
        merged_ips[ip] = set(sources_set)
    for fn, r in results.items():
        for ip in r.get("ips", []):
            if ip not in merged_ips:
                merged_ips[ip] = set()
            merged_ips[ip].add(fn)

    new_count = len(merged_ips) - len(cached_ips)
    total_count = len(merged_ips)
    log.info(f"📊 合并完成: 新增 {new_count:,} 个 → 总计 {total_count:,} 个")
    if total_count == 0:
        log.error("所有威胁源均不可用且无有效缓存，拒绝写入空情报库")
        return 1

    # 构建输出
    output = {
        "meta": {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_unique_ips": total_count,
            "source_stats": {},
            "sources_used": sorted(results.keys()),
            "threat_distribution": {"high": 0, "medium": 0, "low": 0},
        },
        "ips": {},
    }
    for src in results:
        cnt = sum(1 for ip_info in merged_ips.values() if src in ip_info)
        output["meta"]["source_stats"][src] = cnt

    for ip, sources_set in sorted(merged_ips.items()):
        n = len(sources_set)
        level = "high" if n >= 3 else ("medium" if n >= 2 else "low")
        if "firehol_level1" in sources_set:
            level = "high"  # FireHOL 精选列表 → 高置信度
        output["meta"]["threat_distribution"][level] += 1
        output["ips"][ip] = {
            "sources": sorted(sources_set),
            "threat_level": level,
            "first_seen": cached.get("ips", {}).get(ip, {}).get("first_seen", datetime.now(timezone.utc).isoformat()),
        }

    json_path, txt_path = save(output)

    m = output["meta"]
    log.info("\n" + "=" * 60)
    log.info("📊 真实威胁情报 IP 报告")
    log.info("=" * 60)
    log.info(f"  来源:      {len(m['sources_used'])} 个")
    log.info(f"  唯一 IP:   {m['total_unique_ips']:,}")
    d = m['threat_distribution']
    log.info(f"  高威胁:    {d['high']:,}")
    remaining = d.get('medium', 0) + d.get('low', 0)
    log.info(f"  中/低威胁: {remaining:,}")
    for src, cnt in sorted(m['source_stats'].items()):
        desc = WORKING_FEEDS.get(src, {}).get("desc", src)
        if cnt > 0:
            log.info(f"    {desc:40s} {cnt:>8,}")

    log.info(f"\n💾 {json_path} ({total_count:,} IP)")
    log.info(f"💾 {txt_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
