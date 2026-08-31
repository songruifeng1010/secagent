import os
import time
import json
import httpx
from typing import Optional
from .base import BaseTool, ToolResult


class ThreatIntelTool(BaseTool):
    name = "threat_intel"
    description = "查询IP、域名或文件哈希的威胁情报信息，支持多情报源交叉验证"
    parameters = {
        "type": "object",
        "properties": {
            "indicator": {
                "type": "string",
                "description": "要查询的威胁指标，可以是IP地址、域名或文件哈希"
            },
            "indicator_type": {
                "type": "string",
                "enum": ["ip", "domain", "hash"],
                "description": "指标类型: ip/domain/hash"
            }
        },
        "required": ["indicator", "indicator_type"]
    }

    CACHE_MAXSIZE = 10000  # 最多缓存 10000 条，超过时淘汰 20%

    def __init__(self):
        """威胁情报工具；只返回真实外部 API 或已安装本地情报库的结果。"""
        self._cache: dict[str, dict] = {}
        self._cache_ttl = 300
        self._cache_timestamps: dict[str, float] = {}  # key -> time.time()
        self._http: Optional[httpx.AsyncClient] = None
        # 从环境变量读取 API Keys
        def _real_key(name: str) -> str:
            value = os.getenv(name, "").strip()
            lowered = value.lower()
            if not value or value.startswith("${") or "your-" in lowered or "replace-with" in lowered:
                return ""
            return value

        self.abuseipdb_key = _real_key("ABUSEIPDB_API_KEY")
        self.otx_key = _real_key("OTX_API_KEY")
        self.vt_key = _real_key("VT_API_KEY")
        # 显式禁用的源（网络不可达/被劫持时用于剔除覆盖率分母）
        # 用法: THREAT_INTEL_DISABLED_SOURCES=otx,abuseipdb
        disabled = os.getenv("THREAT_INTEL_DISABLED_SOURCES", "").lower()
        self._disabled_sources = {s.strip() for s in disabled.split(",") if s.strip()}
        self._has_real_api = bool(self.abuseipdb_key or self.otx_key or self.vt_key)

        # ─── 本地黑名单库（v2.7：本地情报源，永不依赖外部 API） ───
        # data/blacklist/threat_ips.json 含 11.5 万真实恶意 IP（来源/威胁等级/首次发现）
        # 惰性加载：首次查询才读入内存，避免启动开销
        self._local_ips: Optional[dict] = None          # {ip: {sources, threat_level, first_seen}}
        self._local_ips_available = False
        self._local_ips_path = os.getenv(
            "THREAT_IPS_PATH",
            os.path.join(os.path.dirname(__file__), "..", "..", "data", "blacklist", "threat_ips.json"),
        )
        # 本地库是否强制启用（即使无外部 API 也查询本地库）
        self._use_local = True

    def _cache_get(self, key: str) -> Optional[dict]:
        """带 TTL 检查的缓存读取"""
        entry = self._cache.get(key)
        if entry is None:
            return None
        ts = self._cache_timestamps.get(key, 0)
        if time.time() - ts > self._cache_ttl:
            # 过期
            self._cache.pop(key, None)
            self._cache_timestamps.pop(key, None)
            return None
        return entry

    def _cache_set(self, key: str, value: dict):
        """有限大小缓存写入，超标时淘汰最旧的 20%"""
        self._cache[key] = value
        self._cache_timestamps[key] = time.time()
        if len(self._cache) > self.CACHE_MAXSIZE:
            # 按时间戳排序，淘汰最旧的 20%
            sorted_keys = sorted(self._cache_timestamps.keys(), key=lambda k: self._cache_timestamps[k])
            evict_count = max(int(self.CACHE_MAXSIZE * 0.2), 1)
            for k in sorted_keys[:evict_count]:
                self._cache.pop(k, None)
                self._cache_timestamps.pop(k, None)

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=15.0)
        return self._http

    def _source_disabled(self, name: str) -> bool:
        """该源是否被显式禁用（网络不可达/被劫持，不参与查询也不计入 coverage）"""
        return name in self._disabled_sources

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """检查是否为私有/保留IP地址"""
        try:
            first = int(ip.split(".")[0])
            second = int(ip.split(".")[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 169 and second == 254:
                return True
            if first == 0:
                return True
            return False
        except (ValueError, IndexError):
            return False

    # ═══════════ 本地黑名单库（v2.7） ═══════════

    def _load_local_ips(self) -> None:
        """
        惰性加载本地恶意 IP 库（threat_ips.json）。

        结构:
          {
            "meta": {...},
            "ips": {
              "1.2.3.4": {"sources": [...], "threat_level": "high|medium|low", "first_seen": "..."},
              ...
            }
          }
        失败时不阻断：本地库不可用则降级为仅外部 API。
        """
        if self._local_ips is not None:
            return
        try:
            if not os.path.exists(self._local_ips_path):
                self._local_ips = {}
                return
            with open(self._local_ips_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ips = data.get("ips", {}) if isinstance(data, dict) else {}
            self._local_ips = ips if isinstance(ips, dict) else {}
            self._local_ips_available = isinstance(ips, dict)
            logger_ = __import__("logging").getLogger("secagentx.tools.threat_intel")
            logger_.info("本地恶意IP库加载: %d 条 (%s)", len(self._local_ips), self._local_ips_path)
        except Exception as e:
            self._local_ips = {}
            self._local_ips_available = False
            logger_ = __import__("logging").getLogger("secagentx.tools.threat_intel")
            logger_.warning("本地恶意IP库加载失败: %s", e)

    def _local_blacklist_lookup(self, ip: str) -> Optional[dict]:
        """
        查询本地黑名单库。

        命中返回 {threat_level, sources, first_seen, score}；
        未命中返回 None（视为"本地库无记录"，不贡献评分）。
        """
        if not self._use_local:
            return None
        self._load_local_ips()
        if not self._local_ips:
            return None
        entry = self._local_ips.get(ip)
        if not entry or not isinstance(entry, dict):
            return None
        threat_level = entry.get("threat_level", "low")
        # 威胁等级 → 评分（high=90, medium=60, low=35），多源命中可叠加到 100
        base_score = {"high": 90, "medium": 60, "low": 35}.get(threat_level, 35)
        sources = entry.get("sources") or []
        score = min(100, base_score + (10 * max(0, len(sources) - 1)))
        return {
            "threat_level": threat_level,
            "sources": sources,
            "first_seen": entry.get("first_seen", ""),
            "score": score,
        }

    @staticmethod
    def _aggregate_source_score(source_details: dict) -> dict:
        """
        聚合多情报源评分，正确处理"源缺失/不可用"。

        关键原则（修复"把未查询当无恶意"的漏报缺陷 + 修复覆盖率被死源拖累）:
          - 未配置 Key 的源（status=unavailable / note=no_api_key / not_configured）:
              * 不计入评分（不贡献 0 分）
              * **不计入覆盖率分母**——这些源根本不在本次评估范围内，
                "没配置"≠"覆盖不足"，不拖累覆盖率（否则清掉死源后覆盖率反而下降）
          - 配置了但查询失败的源（status=failed）:
              * 不计入评分，计入 missing —— 这才是真正的"覆盖不足"，拉低覆盖率
          - 成功查询的源参与评分（含本地库，无论命中与否都视为"已检查"）

        返回:
          {
            "score": float,     # 0~100，仅基于可用源的评分
            "checked": int,     # 成功查询并参与评分的源数
            "missing": [str],   # 配置了但查询失败的源名（真覆盖不足）
            "unconfigured": [str],  # 未配置的源名（不计覆盖率，仅供参考）
            "coverage": float,  # checked / (checked + missing)，0.0~1.0
          }
        """
        available_scores = []
        missing = []
        disabled = []
        unconfigured = []
        for name, s in source_details.items():
            if not isinstance(s, dict):
                continue
            status = s.get("status", "ok")
            note = s.get("note", "")
            if status == "disabled" or note == "disabled":
                # 被显式禁用的源（网络不可达）：完全不参与覆盖率
                disabled.append(name)
                continue
            if note == "no_api_key" or note == "not_configured" or status == "unavailable":
                # 未配置 Key 的源：不在本次评估范围，不计覆盖率分母
                unconfigured.append(name)
                continue
            if status == "failed":
                # 配置了但查询失败：真正的覆盖不足，计入 missing 拉低覆盖率
                missing.append(name)
                continue
            # 源可用：提取数值评分（不同源字段结构不同）
            score = s.get("score")
            if score is None:
                detections = s.get("detections")
                if detections is not None:
                    total = s.get("total") or 1
                    score = min(100, (detections / total) * 100)
                else:
                    score = 35.0 if s.get("malicious") else 0.0
            available_scores.append(float(score or 0))

        checked = len(available_scores)
        total = checked + len(missing)
        return {
            "score": min(100, sum(available_scores)),
            "checked": checked,
            "missing": missing,
            "disabled": disabled,
            "unconfigured": unconfigured,
            "coverage": (checked / total) if total else 0.0,
        }

    async def execute(self, indicator: str, indicator_type: str = "ip") -> ToolResult:
        start = time.time()

        # 私有 IP 无法查询公网威胁情报，直接返回“不可查询”。
        if indicator_type == "ip" and self._is_private_ip(indicator):
            result = {
                "is_private": True,
                "indicator": indicator,
                "indicator_type": "ip",
                "malicious_count": 0,
                "total_sources": 0,
                "alerts": [f"{indicator} 是私有IP地址，无法查询公网威胁情报"],
                "score": 0,
                "risk_level": "低危",
                "is_malicious": False,
                "tags": ["private_ip"],
                "source_details": {},
                "geo_info": {"country": "内网/私有地址", "city": "", "isp": "内网"},
                "coverage": 0.0,
                "missing_sources": [],
            }
            self._cache_set(f"{indicator_type}:{indicator}", result)
            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data=result, duration_ms=elapsed)

        # ========== 无真实 API Key 时只使用实际存在的本地库 ==========
        if not self._has_real_api:
            # 本地库兜底：仅对 IP 类型查询有效（本地库只有 IP 数据）
            if indicator_type == "ip":
                self._load_local_ips()
                if not self._local_ips_available:
                    return ToolResult(
                        success=False,
                        error=(
                            "威胁情报不可用：未配置外部 API，且本地威胁 IP 库不存在。"
                            "请配置 VT_API_KEY / ABUSEIPDB_API_KEY / OTX_API_KEY，"
                            "或运行 scripts/update_threat_ips.py 获取真实公开情报。"
                        ),
                        data={"coverage": 0.0, "status": "unavailable"},
                    )
                local = self._local_blacklist_lookup(indicator)
                if local:
                    result = {
                        "is_private": False,
                        "indicator": indicator,
                        "indicator_type": "ip",
                        "malicious_count": 1,
                        "total_sources": 1,
                        "alerts": [
                            f"本地黑名单库命中（威胁等级 {local['threat_level']}, "
                            f"来源: {', '.join(local['sources'][:3])}）"
                        ],
                        "score": local["score"],
                        "risk_level": {"high": "高危", "medium": "中危", "low": "低危"}.get(
                            local["threat_level"], "中危"),
                        "is_malicious": local["threat_level"] in ("high", "medium"),
                        "tags": ["local_blacklist", f"level_{local['threat_level']}"],
                        "source_details": {
                            "local_blacklist": {
                                "score": local["score"], "status": "ok",
                                "threat_level": local["threat_level"],
                                "sources": local["sources"],
                            }
                        },
                        "geo_info": {"country": "未知", "city": "", "isp": "未知"},
                        "coverage": 1.0,
                        "missing_sources": [],
                    }
                    self._cache_set(f"{indicator_type}:{indicator}", result)
                    elapsed = (time.time() - start) * 1000
                    return ToolResult(success=True, data=result, duration_ms=elapsed)
                # 本地库无命中：如实返回"未命中"，不报错
                result = {
                    "is_private": False,
                    "indicator": indicator,
                    "indicator_type": "ip",
                    "malicious_count": 0,
                    "total_sources": 0,
                    "alerts": ["本地黑名单库未命中；未配置外部情报 API，无更多情报"],
                    "score": 0,
                    "risk_level": "低危",
                    "is_malicious": False,
                    "tags": ["no_external_api", "local_blacklist_clean"],
                    "source_details": {
                        "local_blacklist": {"score": 0, "status": "ok", "note": "未命中"}
                    },
                    "geo_info": {"country": "未知", "city": "", "isp": "未知"},
                    "coverage": 1.0,
                    "missing_sources": [],
                }
                self._cache_set(f"{indicator_type}:{indicator}", result)
                elapsed = (time.time() - start) * 1000
                return ToolResult(success=True, data=result, duration_ms=elapsed)
            return ToolResult(
                success=False,
                error=(
                    "【配置错误】威胁情报工具未配置任何真实 API Key\n\n"
                    "请设置以下环境变量之一（任选一个即可）：\n"
                    "  - VT_API_KEY=xxx        (VirusTotal，推荐)\n"
                    "  - ABUSEIPDB_API_KEY=xxx  (AbuseIPDB)\n"
                    "  - OTX_API_KEY=xxx        (AlienVault OTX)\n"
                    "\n"
                    "设置后在 .env 文件中配置即可生效。\n"
                ),
                duration_ms=0,
            )
        # ===================================================

        cache_key = f"{indicator_type}:{indicator}"

        cached = self._cache_get(cache_key)
        if cached is not None:
            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data=cached, duration_ms=elapsed)

        try:
            if indicator_type == "ip":
                result = await self._check_ip(indicator)
            elif indicator_type == "domain":
                result = await self._check_domain(indicator)
            elif indicator_type == "hash":
                result = await self._check_hash(indicator)
            else:
                return ToolResult(success=False, error=f"Unknown indicator type: {indicator_type}")
        except Exception as e:
            return ToolResult(success=False, error=f"威胁情报查询失败: {e}", duration_ms=(time.time()-start)*1000)

        is_malicious = result.get("malicious_count", 0) >= 2
        result["is_malicious"] = is_malicious
        result["indicator"] = indicator
        result["indicator_type"] = indicator_type
        result["data_source"] = "real_api" if self._has_real_api else "no_api"
        # 能走到这里说明不是私有 IP（私有 IP 已提前拦截）
        result["is_private"] = False

        if is_malicious:
            result["risk_level"] = "高危" if result.get("malicious_count", 0) >= 3 else "中危"
        else:
            result["risk_level"] = "低危"

        self._cache[cache_key] = result
        elapsed = (time.time() - start) * 1000
        return ToolResult(success=True, data=result, duration_ms=elapsed)

    # ======================== IP 查询（真实 API） ========================

    async def _check_ip(self, ip: str) -> dict:
        alerts = []
        malicious_count = 0
        source_details = {}
        errors = []

        # 0. 本地黑名单库（v2.7：本地情报源，永不依赖外部 API）
        # 本地库始终作为"已检查源"计入 coverage（命中与否都算查过了）：
        #   命中 → score>0, 计入 malicious_count
        #   未命中 → score=0（查过无记录，但不是"缺失"）
        try:
            self._load_local_ips()
            if not self._local_ips_available:
                source_details["local_blacklist"] = {
                    "score": None, "status": "unavailable", "note": "not_configured",
                }
                raise FileNotFoundError("本地威胁 IP 库未安装")
            local = self._local_blacklist_lookup(ip)
            if local:
                source_details["local_blacklist"] = {
                    "score": local["score"],
                    "threat_level": local["threat_level"],
                    "sources": local["sources"],
                    "first_seen": local.get("first_seen", ""),
                    "status": "ok",
                }
                malicious_count += 1
                alerts.append(
                    f"本地黑名单库: {ip} 命中（威胁等级 {local['threat_level']}, "
                    f"来自 {', '.join(local['sources'][:3])}）"
                )
            else:
                # 本地库已查但无记录：计入 checked（可用源，无命中），不视为缺失
                source_details["local_blacklist"] = {
                    "score": 0, "status": "ok", "note": "未命中",
                }
        except FileNotFoundError:
            pass
        except Exception as e:
            logger_ = __import__("logging").getLogger("secagentx.tools.threat_intel")
            logger_.warning("本地黑名单库查询失败: %s", e)

        # 1. AbuseIPDB
        if self._source_disabled("abuseipdb"):
            # 被显式禁用：既不查询也不计入 coverage 分母
            source_details["abuseipdb"] = {"note": "disabled", "status": "disabled"}
        elif self.abuseipdb_key:
            try:
                score, msg = await self._abuseipdb_lookup(ip)
                source_details["abuseipdb"] = {"score": score, "status": "ok"}
                if score > 0:
                    alerts.append(f"AbuseIPDB: {msg}")
                if score > 50:
                    malicious_count += 1
            except Exception as e:
                source_details["abuseipdb"] = {"error": str(e), "status": "failed"}
                errors.append(f"AbuseIPDB 查询失败: {e}")
        else:
            # 未配置 Key：显式标记为"不可用"，聚合时不计入评分
            source_details["abuseipdb"] = {"score": None, "note": "no_api_key", "status": "unavailable"}

        # 2. AlienVault OTX
        if self._source_disabled("otx"):
            source_details["otx"] = {"note": "disabled", "status": "disabled"}
        elif self.otx_key:
            try:
                otx = await self._otx_lookup(ip, "ip")
                otx["score"] = 35.0 if otx.get("malicious") else 0.0
                source_details["otx"] = {**otx, "status": "ok"}
                if otx.get("malicious"):
                    malicious_count += 1
                    alerts.append(f"AlienVault OTX: {otx.get('pulse_count', 0)} 个相关情报")
            except Exception as e:
                source_details["otx"] = {"error": str(e), "status": "failed"}
                errors.append(f"OTX 查询失败: {e}")
        else:
            source_details["otx"] = {"malicious": False, "note": "no_api_key", "status": "unavailable"}

        # 3. VirusTotal
        if self._source_disabled("virustotal"):
            source_details["virustotal"] = {"note": "disabled", "status": "disabled"}
        elif self.vt_key:
            try:
                vt = await self._vt_ip_lookup(ip)
                detections = vt.get("detections", 0)
                total = vt.get("total", 0) or 1
                vt["score"] = min(100, (detections / total) * 100)
                source_details["virustotal"] = {**vt, "status": "ok"}
                if detections > 0:
                    malicious_count += 1
                    alerts.append(f"VirusTotal: {detections}/{vt.get('total', 0)} 引擎检测")
            except Exception as e:
                source_details["virustotal"] = {"error": str(e), "status": "failed"}
                errors.append(f"VirusTotal 查询失败: {e}")
        else:
            source_details["virustotal"] = {"detections": 0, "total": 0, "note": "no_api_key", "status": "unavailable"}

        # 聚合可用源评分：缺失/不可用源不参与，避免"未查询"被当"无恶意"
        agg = self._aggregate_source_score(source_details)

        return {
            "malicious_count": malicious_count,
            "total_sources": agg["checked"],
            "alerts": alerts,
            "score": agg["score"],
            "tags": self._get_tags(ip, malicious_count),
            "source_details": source_details,
            "errors": errors,
            "has_partial_failure": len(errors) > 0,
            "coverage": agg["coverage"],
            "missing_sources": agg["missing"],
            "unconfigured_sources": agg.get("unconfigured", []),
        }

    # ======================== 域名查询 ========================

    async def _check_domain(self, domain: str) -> dict:
        alerts = []
        malicious_count = 0
        source_details = {}
        # 本地静态检查（不算外部情报源，不计入 coverage）
        local_checks = {}

        # 高风险 TLD 检查
        risky_tlds = [".xyz", ".top", ".gq", ".ml", ".cf", ".click", ".download", ".free"]
        if any(domain.lower().endswith(tld) for tld in risky_tlds):
            malicious_count += 1
            alerts.append(f"高风险TLD域名")
            local_checks["high_risk_tld"] = True

        if self._source_disabled("virustotal"):
            source_details["virustotal"] = {"note": "disabled", "status": "disabled"}
        elif self.vt_key:
            try:
                vt = await self._vt_domain_lookup(domain)
                detections = vt.get("detections", 0)
                total = vt.get("total", 0) or 1
                vt["score"] = min(100, (detections / total) * 100)
                source_details["virustotal"] = {**vt, "status": "ok"}
                if detections > 0:
                    malicious_count += 1
                    alerts.append(f"VirusTotal: {detections}/{vt.get('total', 0)} 引擎检测")
            except Exception as e:
                source_details["virustotal"] = {"error": str(e), "status": "failed"}
        else:
            source_details["virustotal"] = {"detections": 0, "total": 0, "note": "no_api_key", "status": "unavailable"}

        # OTX 域名情报（OTX 亦支持域名查询）
        if self._source_disabled("otx"):
            source_details["otx"] = {"note": "disabled", "status": "disabled"}
        elif self.otx_key:
            try:
                otx = await self._otx_lookup(domain, "domain")
                otx["score"] = 35.0 if otx.get("malicious") else 0.0
                source_details["otx"] = {**otx, "status": "ok"}
                if otx.get("malicious"):
                    malicious_count += 1
                    alerts.append(f"AlienVault OTX: {otx.get('pulse_count', 0)} 个相关情报")
            except Exception as e:
                source_details["otx"] = {"error": str(e), "status": "failed"}
        else:
            source_details["otx"] = {"malicious": False, "note": "no_api_key", "status": "unavailable"}

        agg = self._aggregate_source_score(source_details)

        return {
            "malicious_count": malicious_count,
            "total_sources": agg["checked"],
            "alerts": alerts,
            "score": agg["score"],
            "tags": self._get_tags(domain, malicious_count),
            "source_details": source_details,
            "local_checks": local_checks,
            "errors": [],
            "has_partial_failure": False,
            "coverage": agg["coverage"],
            "missing_sources": agg["missing"],
        }

    # ======================== 哈希查询 ========================

    async def _check_hash(self, file_hash: str) -> dict:
        alerts = []
        malicious_count = 0
        source_details = {}

        if self._source_disabled("virustotal"):
            source_details["virustotal"] = {"note": "disabled", "status": "disabled"}
        elif self.vt_key:
            try:
                vt = await self._vt_hash_lookup(file_hash)
                detections = vt.get("detections", 0)
                total = vt.get("total", 0) or 1
                vt["score"] = min(100, (detections / total) * 100)
                source_details["virustotal"] = {**vt, "status": "ok"}
                if detections > 0:
                    malicious_count += 1
                    alerts.append(f"VirusTotal: {detections}/{vt.get('total', 0)} 引擎检测")
            except Exception as e:
                source_details["virustotal"] = {"error": str(e), "status": "failed"}
        else:
            source_details["virustotal"] = {"detections": 0, "total": 0, "note": "no_api_key", "status": "unavailable"}

        # OTX 哈希情报（OTX 亦支持文件哈希查询）
        if self._source_disabled("otx"):
            source_details["otx"] = {"note": "disabled", "status": "disabled"}
        elif self.otx_key:
            try:
                otx = await self._otx_lookup(file_hash, "hash")
                otx["score"] = 35.0 if otx.get("malicious") else 0.0
                source_details["otx"] = {**otx, "status": "ok"}
                if otx.get("malicious"):
                    malicious_count += 1
                    alerts.append(f"AlienVault OTX: {otx.get('pulse_count', 0)} 个相关情报")
            except Exception as e:
                source_details["otx"] = {"error": str(e), "status": "failed"}
        else:
            source_details["otx"] = {"malicious": False, "note": "no_api_key", "status": "unavailable"}

        agg = self._aggregate_source_score(source_details)

        return {
            "malicious_count": malicious_count,
            "total_sources": agg["checked"],
            "alerts": alerts,
            "score": agg["score"],
            "tags": self._get_tags(file_hash, malicious_count),
            "source_details": source_details,
            "errors": [],
            "has_partial_failure": False,
            "coverage": agg["coverage"],
            "missing_sources": agg["missing"],
        }

    # ======================== 真实 API 调用 ========================

    async def _abuseipdb_lookup(self, ip: str) -> tuple:
        resp = await self.http.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        domain = data.get("domain", "")
        country = data.get("countryCode", "")
        total_reports = data.get("totalReports", 0)
        msg = f"投诉率 {score}% | {total_reports} 条举报 | {country}"
        if domain and domain != ip:
            msg += f" | 域名 {domain}"
        return score, msg

    async def _otx_lookup(self, indicator: str, indicator_type: str = "ip") -> dict:
        # OTX 按类型选择端点：
        #   ip     → /indicators/IPv4/{ip}/general
        #   domain → /indicators/domain/{domain}/general
        #   hash   → /indicators/file/{hash}/general
        type_paths = {
            "ip": "IPv4",
            "domain": "domain",
            "hash": "file",
        }
        otx_type = type_paths.get(indicator_type, "IPv4")
        resp = await self.http.get(
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general",
            headers={"X-OTX-API-Key": self.otx_key},
        )
        resp.raise_for_status()
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        families = []
        if pulse_count > 0:
            pulses = data.get("pulse_info", {}).get("pulses", [])
            for p in pulses[:5]:
                for tag in p.get("tags", []):
                    if tag not in families:
                        families.append(tag)
        return {"malicious": pulse_count > 0, "pulse_count": pulse_count, "families": families[:5]}

    async def _vt_ip_lookup(self, ip: str) -> dict:
        resp = await self.http.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self.vt_key},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {"detections": malicious, "total": total or 90}

    async def _vt_domain_lookup(self, domain: str) -> dict:
        resp = await self.http.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": self.vt_key},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {"detections": malicious, "total": total or 90}

    async def _vt_hash_lookup(self, file_hash: str) -> dict:
        resp = await self.http.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": self.vt_key},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {"detections": malicious, "total": total or 90}

    async def close(self):
        if self._http:
            await self._http.aclose()
            self._http = None

    def _get_tags(self, indicator: str, malicious_count: int) -> list[str]:
        """
        根据威胁情报数据生成标签。

        规则:
          - malicious_count >= 2: 标记为 malicious
          - malicious_count >= 3: 标记为 c2
          - 不再根据 IP 段前缀硬编码打标签（之前 "185." 匹配方式有严重误报风险）
        """
        tags = []
        if malicious_count >= 2: tags.append("malicious")
        if malicious_count >= 3: tags.append("c2")
        # 注意：不要根据 IP 段前缀打"known_attacker"标签。
        # 一个 IP 段内同时存在正常用户和攻击者，前缀匹配会导致大量误报。
        # 应由威胁情报 API 的置信度评分和举报数据来判断。
        return tags
