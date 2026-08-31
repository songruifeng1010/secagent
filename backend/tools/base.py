from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional
import os


@dataclass
class ToolResult:
    success: bool = True
    data: Any = None
    error: str = ""
    duration_ms: float = 0.0


class BaseTool(ABC):
    name: str = ""
    description: str = ""
    parameters: dict = None  # 子类在类级别重写此字段
    agent_id: str = ""

    @property
    def params(self) -> dict:
        """安全访问 parameters，兼容子类类级别定义和实例级别定义"""
        val = self.parameters
        if val is None:
            return {"type": "object", "properties": {}}
        return val

    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        ...

    def to_openai_function(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.params,
            },
        }

    def to_tool_call(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.params,
        }


# ═══════════════════════════════════════════════════════════════
# 防火墙适配器接口 — 支持多种后端实现（企业级完善）
# ═══════════════════════════════════════════════════════════════

class FirewallAdapter(ABC):
    """防火墙后端适配器抽象接口"""

    @abstractmethod
    async def block_ip(self, ip: str, reason: str = "",
                        duration_minutes: int = 120) -> tuple[bool, str]:
        ...

    @abstractmethod
    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        ...

    @abstractmethod
    async def list_rules(self) -> list[dict]:
        ...

    @abstractmethod
    async def check_ip(self, ip: str) -> dict:
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        ...


class IptablesAdapter(FirewallAdapter):
    """iptables/nftables 真实防火墙后端（生产可用）

    生产环境注意事项（已实测验证）:
      - 不使用 `-m comment` 模块：在 nf_tables 后端下，添加时带 comment
        删除时匹配不一致，会导致规则残留（实测 Bug）
      - 使用独立链 `SecAgentX-BLOCK`：封禁规则全部放到该链，
        list_rules 只查该链，不会与 INPUT 链上的其他规则混淆
      - 封禁/解封需要 root 权限：通过 sudo 执行
      - 删除规则时带完整匹配条件（-s ip -j DROP），避免误删其他规则
    """

    CHAIN = "SecAgentX-BLOCK"

    def __init__(self, chain: str = None, use_sudo: bool = True):
        self.chain = chain or self.CHAIN
        # 生产环境 iptables 通常需要 root；可配置为 False（已是 root）
        self.use_sudo = use_sudo or os.geteuid() != 0

    async def _run_iptables(self, args: list[str]) -> tuple[int, str, str]:
        import asyncio
        import subprocess
        cmd = ["sudo", "iptables", *args] if self.use_sudo else ["iptables", *args]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode or 0, stdout.decode(), stderr.decode()

    async def _ensure_chain(self):
        """确保独立链存在（不存在则创建并接入 INPUT）。"""
        rc, stdout, _ = await self._run_iptables(["-L", self.chain, "-n"])
        if rc != 0:
            # 创建独立链
            await self._run_iptables(["-N", self.chain])
            # 接入 INPUT 链（在 ACCEPT 之前插入）
            await self._run_iptables(["-I", "INPUT", "-j", self.chain])

    async def block_ip(self, ip: str, reason: str = "",
                        duration_minutes: int = 120) -> tuple[bool, str]:
        await self._ensure_chain()
        rc, _, stderr = await self._run_iptables([
            "-A", self.chain, "-s", ip, "-j", "DROP",
        ])
        if rc != 0:
            return False, f"iptables block failed: {stderr}"
        return True, ""

    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        # 在独立链中删除，带完整匹配
        rc, _, stderr = await self._run_iptables([
            "-D", self.chain, "-s", ip, "-j", "DROP",
        ])
        if rc != 0:
            # 规则可能不存在，不是致命错误
            return True, f"rule not found (already removed): {stderr}"
        return True, ""

    async def list_rules(self) -> list[dict]:
        rc, stdout, stderr = await self._run_iptables([
            "-L", self.chain, "-n",
        ])
        if rc != 0:
            return []
        rules = []
        for line in stdout.splitlines():
            parts = line.split()
            # 格式: DROP all -- <src> <dst>
            if len(parts) >= 4 and parts[0] == "DROP":
                ip = parts[3]
                if ip != "0.0.0.0/0":
                    rules.append({"ip": ip, "reason": ""})
        return rules

    async def check_ip(self, ip: str) -> dict:
        rules = await self.list_rules()
        for r in rules:
            if r["ip"] == ip:
                return {"is_blocked": True, "rule": r}
        return {"is_blocked": False}

    async def health_check(self) -> bool:
        # 确保链存在（不存在则创建并接入 INPUT）——成功即健康
        try:
            await self._ensure_chain()
            rc, _, stderr = await self._run_iptables(["-L", self.chain, "-n"])
            return rc == 0 and "Permission" not in stderr
        except Exception:
            return False


class DisabledFirewallAdapter(FirewallAdapter):
    """安全默认值：不执行也不伪造任何防火墙变更。"""

    _ERROR = "防火墙后端未配置；请显式设置 FIREWALL_BACKEND"

    async def block_ip(self, ip: str, reason: str = "",
                       duration_minutes: int = 120) -> tuple[bool, str]:
        return False, self._ERROR

    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        return False, self._ERROR

    async def list_rules(self) -> list[dict]:
        return []

    async def check_ip(self, ip: str) -> dict:
        return {"is_blocked": False, "status": "disabled"}

    async def health_check(self) -> bool:
        return False


class MockFirewallAdapter(FirewallAdapter):
    """本地 JSON 测试后端；生产不得启用。"""

    # 文件写操作锁 — 防止并发写入导致数据竞态
    _file_lock = None

    def __init__(self):
        self._rules: dict[str, dict] = {}
        if MockFirewallAdapter._file_lock is None:
            import asyncio
            MockFirewallAdapter._file_lock = asyncio.Lock()
        self._load()

    def _load(self):
        import json
        path = os.getenv("BLACKLIST_FILE", "data/blacklist/blacklist.json")
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self._rules = json.load(f)
            except Exception:
                self._rules = {}

    async def _save(self):
        import json
        path = os.getenv("BLACKLIST_FILE", "data/blacklist/blacklist.json")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        async with MockFirewallAdapter._file_lock:
            with open(tmp, "w") as f:
                json.dump(self._rules, f, indent=2)
            os.replace(tmp, path)

    async def block_ip(self, ip: str, reason: str = "",
                        duration_minutes: int = 120) -> tuple[bool, str]:
        from datetime import datetime, timezone, timedelta
        self._rules[ip] = {
            "reason": reason or "auto-block",
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "expire_at": (datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)).isoformat(),
            "duration_minutes": duration_minutes,
        }
        await self._save()
        return True, ""

    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        self._rules.pop(ip, None)
        await self._save()
        return True, ""

    async def list_rules(self) -> list[dict]:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        active = []
        for ip, rule in self._rules.items():
            expire = datetime.fromisoformat(rule["expire_at"])
            if expire > now:
                active.append({"ip": ip, **rule})
        return active

    async def check_ip(self, ip: str) -> dict:
        rules = await self.list_rules()
        for r in rules:
            if r["ip"] == ip:
                return {"is_blocked": True, "rule": r}
        return {"is_blocked": False}

    async def health_check(self) -> bool:
        return True


class NftablesAdapter(FirewallAdapter):
    """nftables 防火墙后端 — 现代 Linux 防火墙（iptables 的替代品）"""

    def __init__(self, table: str = "secagentx", chain: str = "input"):
        self.table = table
        self.chain = chain
        self._initialized = False
        # 将初始化延迟到首次使用时（避免在 __init__ 中调用异步代码）

    async def _ensure_table(self):
        """确保 nftables 表和链存在（延迟初始化）"""
        if self._initialized:
            return
        try:
            import asyncio
            import subprocess as _subprocess
            proc = await asyncio.create_subprocess_exec(
                "nft", "list", "table", "inet", self.table,
                stdout=_subprocess.PIPE, stderr=_subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                # 表不存在，创建
                await asyncio.create_subprocess_exec(
                    "nft", "add", "table", "inet", self.table,
                )
                await asyncio.create_subprocess_exec(
                    "nft", "add", "chain", "inet", self.table, self.chain,
                    "{ type filter hook input priority 0; policy accept; }",
                )
            self._initialized = True
        except Exception:
            pass  # 非 root 用户下跳过，实际封禁时会报错

    async def _run_nft(self, args: list[str]) -> tuple[int, str, str]:
        import asyncio, subprocess
        try:
            proc = await asyncio.create_subprocess_exec(
                "nft", *args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            return proc.returncode or 0, stdout.decode(), stderr.decode()
        except FileNotFoundError:
            return 127, "", "nft executable is not installed"
        except OSError as exc:
            return 1, "", str(exc)

    async def block_ip(self, ip: str, reason: str = "",
                        duration_minutes: int = 120) -> tuple[bool, str]:
        await self._ensure_table()
        comment = f"SecAgentX: {reason[:60]}" if reason else "SecAgentX: auto-block"
        rc, _, stderr = await self._run_nft([
            "add", "rule", "inet", self.table, self.chain,
            "ip", "saddr", ip, "drop",
            "comment", f'"{comment}"',
        ])
        if rc != 0:
            return False, f"nftables block failed: {stderr}"
        return True, ""

    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        await self._ensure_table()
        # nftables 没有 "delete rule by match" 的直接方式，需要 handle
        # 先列出所有规则，找到对应 handle，再删除
        rc, stdout, stderr = await self._run_nft([
            "-a", "list", "chain", "inet", self.table, self.chain,
        ])
        if rc != 0:
            return True, f"cannot list rules (may not exist): {stderr}"

        import re
        for line in stdout.splitlines():
            if f"saddr {ip}" in line and "drop" in line:
                m = re.search(r'# handle (\d+)', line)
                if m:
                    handle = m.group(1)
                    rc2, _, stderr2 = await self._run_nft([
                        "delete", "rule", "inet", self.table, self.chain,
                        "handle", handle,
                    ])
                    if rc2 == 0:
                        return True, ""
                    return False, f"nftables unblock failed: {stderr2}"
        return True, "rule not found (already removed)"

    async def list_rules(self) -> list[dict]:
        await self._ensure_table()
        import re
        rc, stdout, stderr = await self._run_nft([
            "-a", "list", "chain", "inet", self.table, self.chain,
        ])
        if rc != 0:
            return []
        rules = []
        for line in stdout.splitlines():
            if "saddr" in line and "drop" in line:
                parts = line.split()
                ip = ""
                for i, p in enumerate(parts):
                    if p == "saddr" and i + 1 < len(parts):
                        ip = parts[i + 1]
                comment_m = re.search(r'comment "([^"]*)"', line)
                handle_m = re.search(r'# handle (\d+)', line)
                rules.append({
                    "ip": ip,
                    "reason": comment_m.group(1).replace("SecAgentX: ", "") if comment_m else "",
                    "handle": handle_m.group(1) if handle_m else "",
                })
        return rules

    async def check_ip(self, ip: str) -> dict:
        await self._ensure_table()
        rules = await self.list_rules()
        for r in rules:
            if r["ip"] == ip:
                return {"is_blocked": True, "rule": r}
        return {"is_blocked": False}

    async def health_check(self) -> bool:
        await self._ensure_table()
        rc, _, _ = await self._run_nft(["list", "tables"])
        return rc == 0


class FirewallAdapterFactory:
    """防火墙适配器工厂 — 通过环境变量切换后端"""

    BACKENDS = {
        "disabled": DisabledFirewallAdapter,
        "mock": MockFirewallAdapter,
        "iptables": IptablesAdapter,
        "nftables": NftablesAdapter,
        "aliyun": None,    # 由 _lazy_load 动态加载
        "tencent": None,   # 由 _lazy_load 动态加载
        "aws": None,       # 由 _lazy_load 动态加载
    }

    _LAZY_LOADERS = {
        "aliyun": {
            "module": "backend.tools.aliyun_firewall",
            "class": "AliyunFirewallAdapter",
            "pip": "alibabacloud_ecs20140526",
        },
        "tencent": {
            "module": "backend.tools.tencent_firewall",
            "class": "TencentFirewallAdapter",
            "pip": "tencentcloud-sdk-python-vpc",
        },
        "aws": {
            "module": "backend.tools.aws_firewall",
            "class": "AWSFirewallAdapter",
            "pip": "boto3",
        },
    }

    @classmethod
    def create(cls, backend: str = None) -> FirewallAdapter:
        backend = backend or os.getenv("FIREWALL_BACKEND", "disabled")
        adapter_class = cls.BACKENDS.get(backend)

        # 延迟加载云厂商适配器
        if adapter_class is None and backend in cls._LAZY_LOADERS:
            loader = cls._LAZY_LOADERS[backend]
            try:
                import importlib
                mod = importlib.import_module(loader["module"])
                adapter_class = getattr(mod, loader["class"])
                cls.BACKENDS[backend] = adapter_class
            except ImportError as e:
                raise ValueError(
                    f"{loader['class']} 加载失败: {e}\n"
                    f"请安装: pip install {loader['pip']}"
                )

        if adapter_class is None:
            raise ValueError(
                f"不支持的防火墙后端: '{backend}'。"
                f"可选: {', '.join(k for k, v in cls.BACKENDS.items() if v)}"
            )
        return adapter_class()
