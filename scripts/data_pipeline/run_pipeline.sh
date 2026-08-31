#!/bin/bash
# SecAgentX 知识库数据管道 — 一键构建高质量安全知识库
#
# Usage:
#   bash scripts/data_pipeline/run_pipeline.sh               # 完整构建
#   bash scripts/data_pipeline/run_pipeline.sh --fetch-only  # 仅下载
#   bash scripts/data_pipeline/run_pipeline.sh --embed-only  # 仅重新嵌入
#   bash scripts/data_pipeline/run_pipeline.sh --force       # 强制全量重建
#   bash scripts/data_pipeline/run_pipeline.sh --status      # 查看状态
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR"

# ─── 颜色 ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查依赖
check_deps() {
    log_info "检查 Python 依赖..."
    python3 << 'PYEOF'
import importlib, sys
required = ['yaml', 'httpx', 'chromadb', 'sentence_transformers']
missing = [pkg for pkg in required if not importlib.util.find_spec(pkg)]
if missing:
    print(f'MISSING: {" ".join(missing)}')
    sys.exit(1)
print('OK')
PYEOF
    if [ $? -eq 0 ]; then
        log_ok "所有依赖已安装"
    else
        log_warn "缺少依赖，正在安装..."
        pip install httpx chromadb sentence-transformers -q
        log_ok "依赖安装完成"
    fi
}

# 显示知识库状态
show_status() {
    echo ""
    echo "========================================"
    echo "  SecAgentX 知识库状态"
    echo "========================================"

    # MITRE
    mitre_file="knowledge_data/mitre_attack/techniques.json"
    if [ -f "$mitre_file" ]; then
        techniques=$(python3 -c "import json; d=json.load(open('$mitre_file')); print(len(d.get('techniques',[])))" 2>/dev/null || echo "?")
        subs=$(python3 -c "import json; d=json.load(open('$mitre_file')); print(sum(len(t.get('sub_techniques',{})) for t in d.get('techniques',[])))" 2>/dev/null || echo "?")
        log_ok "MITRE ATT&CK: $techniques 主技术, $subs 子技术"
    else
        log_error "MITRE ATT&CK: 未构建"
    fi

    # CVE
    cve_file="knowledge_data/cve/vulnerabilities.json"
    if [ -f "$cve_file" ]; then
        cve_count=$(python3 -c "import json; d=json.load(open('$cve_file')); print(len(d.get('cve_database',[])))" 2>/dev/null || echo "?")
        log_ok "CVE漏洞库: $cve_count 条"
    else
        log_error "CVE漏洞库: 未构建"
    fi

    # 合规
    comp_file="knowledge_data/compliance/regulations.json"
    if [ -f "$comp_file" ]; then
        reg_count=$(python3 -c "import json; d=json.load(open('$comp_file')); print(len(d.get('regulations',[])))" 2>/dev/null || echo "?")
        jurisdictions=$(python3 -c "import json; d=json.load(open('$comp_file')); print(', '.join(d.get('meta',{}).get('jurisdictions',[])))" 2>/dev/null || echo "?")
        log_ok "合规法规: $reg_count 条 ($jurisdictions)"
    else
        log_error "合规法规: 未构建"
    fi

    # 应急响应
    rem_file="knowledge_data/remediation/remediation.json"
    if [ -f "$rem_file" ]; then
        pb_count=$(python3 -c "import json; d=json.load(open('$rem_file')); print(len(d.get('remediation_playbooks',[])))" 2>/dev/null || echo "?")
        log_ok "应急响应指南: $pb_count 个场景"
    else
        log_error "应急响应指南: 未构建"
    fi

    # ChromaDB
    chroma_dir="data/chromadb"
    if [ -d "$chroma_dir" ]; then
        log_ok "ChromaDB 向量库: $(ls "$chroma_dir" 2>/dev/null | head -5 | wc -l) 个集合"
        python3 -c "
try:
    import chromadb
    c = chromadb.PersistentClient(path='$chroma_dir')
    colls = c.list_collections()
    for col in colls:
        print(f'  - {col.name}: {col.count()} 条')
except:
    print('  无法读取')
" 2>/dev/null
    else
        log_warn "ChromaDB 向量库: 未构建"
    fi

    echo ""
    echo "总数据量指标:"
    total_techniques=$(python3 -c "import json; d=json.load(open('$mitre_file')); print(len(d.get('techniques',[])))" 2>/dev/null || echo "0")
    total_subs=$(python3 -c "import json; d=json.load(open('$mitre_file')); print(sum(len(t.get('sub_techniques',{})) for t in d.get('techniques',[])))" 2>/dev/null || echo "0")
    total_cves=$(python3 -c "import json; d=json.load(open('$cve_file')); print(len(d.get('cve_database',[])))" 2>/dev/null || echo "0")
    echo "  MITRE: ${total_techniques}+${total_subs} 条 | CVE: ${total_cves} 条 | 合规: ${reg_count:-?} 条 | 响应: ${pb_count:-?} 个"
}

# ─── 主流程 ───
FORCE=""
FETCH_ONLY=false
EMBED_ONLY=false
ENRICH_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --force) FORCE="--force" ;;
        --fetch-only) FETCH_ONLY=true ;;
        --embed-only) EMBED_ONLY=true ;;
        --enrich) ENRICH_ONLY=true ;;
        --cve-only) CVE_ONLY=true ;;
        --status) show_status; exit 0 ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

echo ""
echo "========================================"
echo "  SecAgentX 知识库数据管道"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
echo ""

# 检查依赖
check_deps

# Step 1: 生成合规知识
if ! $EMBED_ONLY; then
    log_info "Step 1/5: 生成国际合规知识..."
    python3 "$SCRIPT_DIR/generate_compliance.py" && log_ok "合规知识生成完成" || log_warn "合规知识生成异常"
    echo ""

    # Step 2: 生成应急响应剧本
    log_info "Step 2/5: 生成应急响应剧本..."
    python3 "$SCRIPT_DIR/generate_remediation.py" && log_ok "应急响应剧本生成完成" || log_warn "应急响应剧本生成异常"
    echo ""

    # Step 3: 下载 MITRE ATT&CK 全量数据
    log_info "Step 3/5: 下载 MITRE ATT&CK 数据..."
    python3 "$SCRIPT_DIR/ingest_mitre.py" $FORCE && log_ok "MITRE 数据已更新" || log_warn "MITRE 数据同步异常"
    echo ""

    # Step 4: 同步 CVE 漏洞库
    log_info "Step 4/5: 同步 CVE 漏洞库 (高危+中危)..."
    python3 "$SCRIPT_DIR/sync_cve.py" $FORCE && log_ok "CVE 数据已更新" || log_warn "CVE 同步异常（可在无网络时跳过）"
    echo ""

    # Step 4.5: 补充 MITRE ATT&CK 检测/缓解
    log_info "Step 4.5/5: 补充 MITRE ATT&CK 检测和缓解措施..."
    python3 "$SCRIPT_DIR/enrich_mitre.py" && log_ok "MITRE 知识补充完成" || log_warn "MITRE 补充异常"
    echo ""
fi

# CVE-only 模式
if [ "${CVE_ONLY:-false}" = true ]; then
    log_info "仅执行 CVE 同步..."
    python3 "$SCRIPT_DIR/sync_cve.py" $FORCE
    show_status
    exit 0
fi

# Step 5: 嵌入到 ChromaDB（关键步骤）
if ! $FETCH_ONLY; then
    log_info "Step 5/5: 嵌入向量到 ChromaDB..."
    log_info "  模式: $(python3 -c 'from scripts.data_pipeline.embed_knowledge import _get_bge; print(\"BGE\" if _get_bge() else \"哈希\")' 2>/dev/null || echo '自动')"
    REINDEX=""
    if [ -n "$FORCE" ]; then
        REINDEX="--reindex"
    fi
    python3 "$SCRIPT_DIR/embed_knowledge.py" $REINDEX && log_ok "向量嵌入完成" || log_error "向量嵌入失败"
    echo ""
fi

# 显示最终状态
echo "========================================"
echo "  管道执行完成"
echo "========================================"
show_status

echo ""
echo "启动命令:"
echo "  python -m backend.interface.api_server"
echo ""

