#!/usr/bin/env python3
"""
知识库自动更新入口。

只调用能够把官方数据转换为 SecAgentX 内部格式的专用同步器，
不会用上游原始 JSON 覆盖应用可读的知识库。

安装 crontab:
    0 3 * * * cd /opt/secagentx && python scripts/update_knowledge.py >> logs/update.log 2>&1

依赖:
    pip install httpx

运行模式:
    python scripts/update_knowledge.py           # 仅启用源（默认 MITRE ATT&CK）
    python scripts/update_knowledge.py --all     # 全量更新
    python scripts/update_knowledge.py --source cve  # 只更新 CVE
"""
import os
import sys
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("secagentx.updater")

# 项目根目录
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.chdir(_PROJECT_ROOT)

# 数据源配置
SOURCES = {
    "mitre_attack": {
        "description": "MITRE ATT&CK 企业版技术库",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "local": "knowledge_data/mitre_attack/techniques.json",
        "enabled_by_default": True,
        "timeout": 120,
        "doc_url": "https://attack.mitre.org/",
    },
    "cve": {
        "description": "NVD CVE 2.0 中的 CISA 已知被利用漏洞（KEV）",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev",
        "local": "knowledge_data/cve/vulnerabilities.json",
        "enabled_by_default": False,  # NVD API 限流严格
        "timeout": 120,
        "doc_url": "https://nvd.nist.gov/",
    },
}


def get_source_config(source_name: str) -> dict:
    """获取数据源配置"""
    source = SOURCES.get(source_name)
    if not source:
        raise ValueError(f"未知数据源: {source_name}，可选: {', '.join(SOURCES.keys())}")
    return source


async def update_source(source_name: str, source: dict) -> int:
    """
    更新单个数据源。

    返回:
        下载的记录数
    """
    logger.info(f"[{source_name}] 开始更新: {source['description']}")
    if source_name == "mitre_attack":
        from scripts.data_pipeline.ingest_mitre import run
        ok = await run(force_download=True)
        return 1 if ok else 0
    if source_name == "cve":
        from scripts.data_pipeline.sync_cve import sync_cves
        return await sync_cves(
            api_key=os.getenv("NVD_API_KEY", ""), force_full=True
        )
    raise ValueError(f"未实现的数据源: {source_name}")


async def main():
    parser = argparse.ArgumentParser(description="SecAgentX 知识库自动更新")
    parser.add_argument("--all", action="store_true", help="全量更新所有数据源")
    parser.add_argument("--source", type=str, default="", help="仅更新指定数据源")
    parser.add_argument("--list", action="store_true", help="列出所有数据源")
    args = parser.parse_args()

    if args.list:
        print("\n可用数据源:")
        print(f"{'名称':<20} {'描述':<40} {'默认启用':<10} {'文档'}")
        print("-" * 100)
        for name, cfg in SOURCES.items():
            print(f"{name:<20} {cfg['description']:<40} {'是' if cfg['enabled_by_default'] else '否':<10} {cfg.get('doc_url', '')}")
        return

    # 确定要更新的数据源
    if args.source:
        names = [args.source]
    elif args.all:
        names = list(SOURCES.keys())
    else:
        names = [n for n, c in SOURCES.items() if c.get("enabled_by_default", False)]

    if not names:
        logger.warning("没有需要更新的数据源")
        return

    logger.info(f"=" * 60)
    logger.info(f"SecAgentX 知识库更新 开始")
    logger.info(f"数据源: {', '.join(names)}")
    logger.info(f"=" * 60)

    import asyncio
    total = 0
    for name in names:
        source = get_source_config(name)
        count = await update_source(name, source)
        total += count

    logger.info(f"=" * 60)
    logger.info(f"更新完成: 共更新 {total} 条记录")
    logger.info(f"=" * 60)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
