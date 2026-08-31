"""
GeoIP 查询工具

查询IP地址的地理位置信息（国家、城市、ISP等）。
使用 ip-api.com 免费API，无需 API Key。
查询失败时返回 unavailable 状态，不会返回虚假数据。
"""

import os
import time
import httpx
from typing import Optional
from .base import BaseTool, ToolResult


class GeoIPTool(BaseTool):
    name = "geoip"
    description = "查询IP地址的地理位置信息：国家、城市、ISP、经纬度等"
    parameters = {
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "要查询的IP地址"
            }
        },
        "required": ["ip"]
    }

    CACHE_MAXSIZE = 10000

    def __init__(self):
        self._http: Optional[httpx.AsyncClient] = None
        self._cache: dict[str, dict] = {}

    def _cache_get(self, key: str) -> Optional[dict]:
        return self._cache.get(key)

    def _cache_set(self, key: str, value: dict):
        self._cache[key] = value
        if len(self._cache) > self.CACHE_MAXSIZE:
            # 淘汰前 20%
            keys = list(self._cache.keys())
            evict = max(int(len(keys) * 0.2), 1)
            for k in keys[:evict]:
                self._cache.pop(k, None)

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=10.0)
        return self._http

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """检查是否为私有/保留IP地址"""
        try:
            first = int(ip.split(".")[0])
            second = int(ip.split(".")[1])
            # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            # 127.0.0.0/8 (loopback)
            if first == 127:
                return True
            # 169.254.0.0/16 (link-local)
            if first == 169 and second == 254:
                return True
            # 0.0.0.0/8
            if first == 0:
                return True
            return False
        except (ValueError, IndexError):
            return False

    async def execute(self, ip: str) -> ToolResult:
        start = time.time()

        # 缓存检查
        cached = self._cache_get(ip)
        if cached is not None:
            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data=self._cache[ip], duration_ms=elapsed)

        # 验证IP格式
        import re
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            elapsed = (time.time() - start) * 1000
            return ToolResult(success=False, error=f"无效的IP地址格式: {ip}", duration_ms=elapsed)

        # 检查私有IP
        if self._is_private_ip(ip):
            result = {
                "ip": ip,
                "country": "内网/私有地址",
                "country_code": "PRIVATE",
                "region": "",
                "city": "",
                "isp": "内网",
                "org": "局域网",
                "as": "",
                "lat": 0,
                "lon": 0,
                "timezone": "",
                "source": "private_range",
                "note": f"{ip} 是私有IP地址，不属于公网，无法查询地理位置",
            }
            self._cache[ip] = result
            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data=result, duration_ms=elapsed)

        try:
            # 尝试使用 ip-api.com (免费，无需API Key)
            result = await self._query_ip_api(ip)
        except Exception:
            result = {
                "ip": ip,
                "country": "未知（API查询失败）",
                "country_code": "N/A",
                "region": "",
                "city": "",
                "isp": "",
                "org": "",
                "as": "",
                "lat": 0,
                "lon": 0,
                "timezone": "",
                "source": "unavailable",
                "note": "地理位置API查询失败，无法确定该IP的地理位置",
            }

        self._cache[ip] = result
        elapsed = (time.time() - start) * 1000
        return ToolResult(success=True, data=result, duration_ms=elapsed)

    async def _query_ip_api(self, ip: str) -> dict:
        """使用 ip-api.com 免费API查询"""
        resp = await self.http.get(f"http://ip-api.com/json/{ip}", params={"lang": "zh-CN"})
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "fail":
            raise ValueError(data.get("message", "查询失败"))

        return {
            "ip": ip,
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "as": data.get("as", ""),
            "lat": data.get("lat", 0),
            "lon": data.get("lon", 0),
            "timezone": data.get("timezone", ""),
            "source": "ip-api.com",
        }

    async def close(self):
        if self._http:
            await self._http.aclose()
            self._http = None

