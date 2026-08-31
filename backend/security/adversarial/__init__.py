"""
对抗测试模块（v2.4 M6）— Prompt Injection 防御与测试

 scanner.py PromptInjectionScanner 多层注入检测（规则+变体+编码）
 guard.py GuardRails 运行时防御（log/warn/block 三级策略）
 redteam.py RedTeamProbe 30+ 对抗样本生成与批量执行
"""
from .scanner import PromptInjectionScanner
from .guard import GuardRails, INJECTION_GUARD
from .redteam import RedTeamProbe, PROBES, BENIGN_SAMPLES, encode_base64

__all__ = ["PromptInjectionScanner", "GuardRails", "RedTeamProbe",
 "INJECTION_GUARD", "PROBES", "BENIGN_SAMPLES", "encode_base64"]
