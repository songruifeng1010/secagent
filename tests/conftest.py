"""
pytest 配置 — 每个测试在独立临时目录中运行
"""
import os
import sys
import pytest
import tempfile
import logging
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 在模块加载阶段设置测试环境变量，确保所有被测试模块导入时能读到正确值
# 严禁加载开发者真实的 SecAgentX 用户档案/API Key，保证测试可复现且不触发外部模型。
os.environ["SECAGENTX_HOME"] = os.path.join(os.path.dirname(__file__), ".runtime-config")
for _runtime_key in (
    "SECAGENTX_ACTIVE_PROVIDER", "SECAGENTX_LLM_PROFILE",
    "SECAGENTX_LLM_PROVIDER_ID", "SECAGENTX_LLM_API_BASE",
    "SECAGENTX_LLM_MODEL", "SECAGENTX_LLM_AUTH_STYLE",
    "SECAGENTX_LLM_API_VERSION", "SECAGENTX_LLM_ALLOW_NO_KEY",
    "SECAGENTX_LLM_API_KEY",
):
    os.environ.pop(_runtime_key, None)
os.environ.setdefault("DEEPSEEK_API_KEY", "sk-test-deepseek-key")
os.environ.setdefault("QWEN_API_KEY", "sk-test-qwen-key")
# 注意：不设置 VT/ABUSEIPDB/OTX API Key（保持缺 Key 状态），
# 让威胁情报工具按自身逻辑决定 mock 或报错，保证 test_threat_intel 测试预期。
os.environ.pop("VT_API_KEY", None)
os.environ.pop("ABUSEIPDB_API_KEY", None)
os.environ.pop("OTX_API_KEY", None)
os.environ.setdefault("CI", "true")
# 测试环境强制使用 mock 防火墙后端，避免测试真实写入 iptables 规则
os.environ["FIREWALL_BACKEND"] = "mock"

_PROVIDER_RUNTIME_KEYS = (
    "SECAGENTX_ACTIVE_PROVIDER", "SECAGENTX_LLM_PROFILE",
    "SECAGENTX_LLM_PROVIDER_ID", "SECAGENTX_LLM_API_BASE",
    "SECAGENTX_LLM_MODEL", "SECAGENTX_LLM_AUTH_STYLE",
    "SECAGENTX_LLM_API_VERSION", "SECAGENTX_LLM_ALLOW_NO_KEY",
    "SECAGENTX_LLM_API_KEY",
)


@pytest.fixture(autouse=True)
def setup_test_env():
    """每个测试用例独立临时目录，避免污染数据"""
    with tempfile.TemporaryDirectory() as tmpdir:
        old_cwd = os.getcwd()
        os.chdir(tmpdir)

        # 每个测试前恢复"缺 Key"状态，防止 test_api.py 等模块级设置或
        # .env 加载（THREAT_INTEL_DISABLED_SOURCES=otx）泄漏到后续测试。
        # 缺 Key / 未禁用让威胁情报工具按自身逻辑 mock/标记缺失，保证测试预期。
        os.environ.pop("VT_API_KEY", None)
        os.environ.pop("ABUSEIPDB_API_KEY", None)
        os.environ.pop("OTX_API_KEY", None)
        os.environ.pop("THREAT_INTEL_DISABLED_SOURCES", None)
        os.environ.pop("THREAT_INTEL_MOCK", None)
        # onboarding 会在当前进程激活 Provider；每个测试都从无活动档案状态开始。
        for runtime_key in _PROVIDER_RUNTIME_KEYS:
            os.environ.pop(runtime_key, None)

        # 设置测试专用的临时文件路径
        os.environ["CIRCUIT_FILE"] = os.path.join(tmpdir, ".circuit_breaker.json")
        os.environ["SECAGENTX_DB_PATH"] = os.path.join(tmpdir, "test.db")
        os.environ["BLACKLIST_FILE"] = os.path.join(tmpdir, "blacklist.json")

        # 创建数据目录
        os.makedirs("data", exist_ok=True)
        os.makedirs("data/blacklist", exist_ok=True)
        os.makedirs("data/chromadb", exist_ok=True)

        yield

        for runtime_key in _PROVIDER_RUNTIME_KEYS:
            os.environ.pop(runtime_key, None)

        # Windows 不允许删除仍被日志 Handler 占用的临时文件。仅关闭本用例
        # 临时目录内创建的文件 Handler，保留控制台和项目级日志 Handler。
        for logger_obj in [logging.getLogger(), *(
            value for value in logging.Logger.manager.loggerDict.values()
            if isinstance(value, logging.Logger)
        )]:
            for handler in list(logger_obj.handlers):
                filename = getattr(handler, "baseFilename", None)
                if filename and Path(filename).resolve().is_relative_to(
                    Path(tmpdir).resolve()
                ):
                    logger_obj.removeHandler(handler)
                    handler.close()

        os.chdir(old_cwd)
