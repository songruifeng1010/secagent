#!/usr/bin/env python3
"""
MITRE ATT&CK 知识补充脚本
为现有 techniques 补充缺失的 detection / mitigation 字段
不从网络下载，基于内置的安全知识规则生成
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "knowledge_data", "mitre_attack")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "techniques.json")

# 根据技术类型自动生成的检测建议模板
DETECTION_TEMPLATES = {
    "execution": "监控进程创建事件（Event ID 4688），关注异常命令行参数和脚本引擎（PowerShell/WScript/CScript）启动",
    "persistence": "监控注册表自动启动项、计划任务创建和服务安装事件",
    "privilege_escalation": "监控特权提升操作（Event ID 4672/4673），关注 UAC 绕过和 Token 窃取迹象",
    "defense_evasion": "监控安全工具禁用事件、进程注入（Event ID 4688/4693）和 DLL 侧载行为",
    "credential_access": "监控 LSASS 进程访问（Event ID 4663）、SAM 注册表访问和 Kerberos TGS 请求异常",
    "discovery": "监控网络共享枚举、系统信息查询（systeminfo/net user）和 AD 查询（Event ID 4662）",
    "lateral_movement": "监控远程服务创建（SCManager）、PsExec/WMI/WinRM 远程执行和网络连接异常",
    "collection": "监控文件压缩操作、剪贴板访问（Event ID 5376）和截图工具执行",
    "command_and_control": "监控非常规端口的出站连接、DNS 请求异常和 HTTPS 流量指纹",
    "exfiltration": "监控大流量出站数据传输、压缩文件创建和云存储 API 异常调用",
    "impact": "监控文件批量修改/删除操作、服务关闭事件和卷影副本删除",
    "default": "监控相关进程异常行为、网络连接变化和系统日志中的关键事件"
}

DETECTION_BY_TECHNIQUE = {
    "T1059": "监控 powershell.exe 执行命令行参数、ScriptBlock 日志（Event ID 4104）和 AMSI 告警",
    "T1059.001": "监控 powershell.exe 执行上下文、ScriptBlock 日志和 AMSI 检测告警",
    "T1059.003": "监控 cmd.exe 执行的异常命令行参数、批处理脚本和重定向操作",
    "T1059.005": "监控 VBScript/JavaScript 执行引擎（wscript.exe/cscript.exe）启动",
    "T1059.006": "监控 Python 脚本执行、异常 python.exe 调用和 pip 安装",
    "T1059.007": "监控 JS/VBS 通过 WMI 执行、ActiveX 调用事件",
    "T1566": "监控邮件附件打开行为、URL 点击跟踪和 Web 隔离告警",
    "T1566.001": "监控包含宏的 Office 文档下载和打开、可疑附件扩展名",
    "T1566.002": "监控邮件中 URL 点击后的 Web 访问行为、短链接实际目标",
    "T1190": "监控 WAF/IPS 告警、Web 服务器状态码异常（500/403）、漏洞扫描特征",
    "T1203": "监控 Office 应用、PDF 阅读器和浏览器的异常崩溃和子进程启动",
    "T1071": "监控出站连接到非常规端口、HTTPS 流量指纹和 DNS 查询异常",
    "T1071.001": "监控 Web 请求中的异常 User-Agent、URL 路径和 POST 数据内容",
    "T1071.004": "监控 DNS 查询类型（TXT/AAAA/CNAME）异常、高频率 DNS 请求",
    "T1486": "监控文件批量加密操作、文件扩展名批量变更和勒索通知文件创建",
    "T1003": "监控 LSASS 进程内存读取（Event ID 4663）、SAM 文件访问和注册表 SAM 读取",
    "T1003.001": "监控对 lsass.exe 进程的打开操作（Event ID 4663）、ProcDump 执行",
    "T1027": "监控 Base64/Hex 编码字符串在命令行中出现、混淆脚本执行",
    "T1021": "监控远程桌面登录（Event ID 4625/4624）、PsExec/WMI 远程连接创建",
    "T1082": "监控 systeminfo/hostname/ipconfig 等系统信息查询命令执行",
    "T1105": "监控非标准端口的文件传输、BITSAdmin 使用和 certutil 下载",
    "T1110": "监控登录失败事件（Event ID 4625）集中爆发、同一账号多源登录尝试",
    "T1090": "监控代理配置修改、PAC 文件下载和 VPN 连接异常",
    "T1574": "监控 DLL 加载路径异常、DLL 侧载事件和搜索顺序劫持",
    "T1041": "监控 HTTP/HTTPS POST 请求中的异常数据量和 Base64 编码体",
    "T1505": "监控 Web 服务器目录中的可疑脚本文件、IIS 模块注册",
    "T1557": "监控 ARP 表异常、端口镜像配置修改和 SSL 证书告警",
    "T1218": "监控签名的系统二进制文件（Mshta/Rundll32/Regsvr32）异常调用",
    "T1189": "监控浏览器驱动下载、Web 隔离告警和 JavaScript 执行异常",
    "T1068": "监控提权漏洞利用（Event ID 4672/4673）、Access Token 异常操作",
    "T1548": "监控 UAC 绕过行为（如 eventvwr.exe 通过注册表劫持启动）",
    "T1529": "监控系统关闭/重启命令执行（shutdown/reboot）和服务终止",
    "T1498": "监控网络流量突发峰值、SYN Flood 特征和带宽耗尽迹象",
}

MITIGATION_BY_TECHNIQUE = {
    "T1059": "限制 PowerShell 执行策略（Restricted/ConstrainedLanguage），启用 AMSI，禁用宏",
    "T1566": "部署邮件安全网关，实施 DMARC/DKIM/SPF，培训用户识别钓鱼邮件",
    "T1190": "部署 WAF/IPS，定期漏洞扫描，及时安装安全补丁，实施最小服务暴露原则",
    "T1203": "启用 Office 受保护视图，禁用宏自动执行，启用 Attack Surface Reduction（ASR）",
    "T1071": "实施严格出站防火墙策略，部署网络流量分析（NTA），启用 DNS 日志",
    "T1486": "实施 3-2-1 备份策略，部署终端检测和响应（EDR），限制 RDP 访问",
    "T1003": "启用 Credential Guard，限制对 LSASS 的访问权限，禁用 WDigest",
    "T1027": "启用 AMSI 监控，部署 EDR 检测脚本混淆，监控编码命令执行",
    "T1021": "限制 RDP 访问（仅允许 VPN 连接），实施网络分段，启用 RDP NLA 认证",
    "T1082": "限制管理员权限，启用 Sysmon 进程监控，审计系统信息查询命令",
    "T1105": "限制 BITSAdmin 使用，出站防火墙限制非标准端口，监控下载工具执行",
    "T1110": "启用账户锁定策略，实施 MFA，监控登录失败日志（Event ID 4625）",
    "T1090": "实施代理白名单，监控代理自动配置（PAC）文件修改",
    "T1574": "启用 Safe DLL Search Mode，设置强文件权限，使用应用程序白名单",
    "T1041": "部署 NTA/NDR 检测异常出站数据，实施 DLP 策略",
    "T1505": "监控 Web 目录文件变更，限制 Web 服务器写权限，部署 WAF",
    "T1557": "启用 DHCP Snooping，实施 ARP 检测，部署 SSL 证书固定",
    "T1218": "实施应用程序白名单（AppLocker），限制签名二进制文件的不安全使用",
    "T1189": "实施浏览器隔离，部署 Web 过滤，启用 Internet 区域安全设置",
    "T1068": "及时安装安全补丁，实施最小权限原则，启用 Credential Guard",
    "T1548": "启用 UAC 最高级别，监控 UAC 绕过技术",
    "T1529": "限制关闭系统权限，监控服务终止事件（Event ID 7036）",
    "T1498": "部署 DDoS 防护（如 Cloudflare/AWS Shield），实施速率限制",
}

# 按战术的通用检测缓解
TACTIC_DETECTION = {
    "TA0001": "监控网络服务暴露面、Web 应用日志中的扫描特征和凭证填充尝试",
    "TA0002": "监控进程创建事件（Event ID 4688）、代码执行引擎启动和脚本执行",
    "TA0003": "监控自启动机制（注册表/计划任务/服务）、登录脚本和启动文件夹变更",
    "TA0004": "监控特权提升漏洞利用事件、UAC 绕过后门和 Token 窃取活动",
    "TA0005": "监控安全产品禁用、文件/进程隐藏、Rootkit 加载和签名绕过",
    "TA0006": "监控凭据访问工具（Mimikatz/ProcDump）执行、LSASS 访问和键盘记录",
    "TA0007": "监控系统信息发现命令、网络扫描和账户枚举行为（Event ID 4798）",
    "TA0008": "监控远程服务（SCManager/PsExec/WMI）使用和网络连接到内网新资产",
    "TA0009": "监控剪贴板访问、屏幕截图、键盘记录和数据归档压缩行为",
    "TA0011": "监控异常出站网络连接、DNS 请求异常、C2 通信特征和隧道工具",
    "TA0010": "监控大文件外传、压缩文件创建、云存储 API 使用和异常数据流量",
    "TA0040": "监控批量文件加密/删除、服务异常关闭和系统破坏行为（mbr/bootkit）",
}

TACTIC_MITIGATION = {
    "TA0001": "定期漏洞扫描并修复，实施最小服务暴露，配置网络访问控制",
    "TA0002": "实施应用程序白名单（AppLocker），禁用不必要的脚本执行引擎",
    "TA0003": "监控并限制自启动机制，定期审核管理员权限，实施特权访问工作站",
    "TA0004": "及时更新系统补丁，限制本地管理员权限，启用 Credential Guard",
    "TA0005": "启用 Windows Defender 受控文件夹访问，实施 EDR，禁用开发者模式",
    "TA0006": "实施多因子认证（MFA），启用 Credential Guard，降低凭据窃取风险",
    "TA0007": "限制管理员权限，系统信息查询仅限授权用户",
    "TA0008": "实施网络分段（零信任架构），限制远程管理工具使用",
    "TA0009": "实施 DLP 策略，限制数据收集类工具的安装和使用",
    "TA0011": "实施出站防火墙控制，启用 DNS 日志和威胁情报集成分析",
    "TA0010": "实施 DLP 技术，监控数据外传通道，限制外部存储设备",
    "TA0040": "实施 3-2-1 备份策略，部署离线备份，制定事件响应预案",
}


def enrich_technique(technique: dict, tactic_id: str = "") -> dict:
    """为单个技术补充缺失的检测和缓解字段"""
    tid = technique.get("id", "")
    description = technique.get("description", "").lower()
    name = technique.get("name", "")

    # 检测方法
    if not technique.get("detection"):
        detection = DETECTION_BY_TECHNIQUE.get(tid)
        if not detection:
            # 按战术通用检测
            if tactic_id in TACTIC_DETECTION:
                detection = TACTIC_DETECTION[tactic_id]
            else:
                # 根据描述关键词匹配
                if "execut" in description or "command" in description or "script" in description:
                    detection = DETECTION_TEMPLATES.get("execution", "")
                elif "persist" in description or "startup" in description or "registry" in description:
                    detection = DETECTION_TEMPLATES.get("persistence", "")
                elif "privilege" in description or "elevat" in description:
                    detection = DETECTION_TEMPLATES.get("privilege_escalation", "")
                elif "credential" in description or "password" in description or "hash" in description:
                    detection = DETECTION_TEMPLATES.get("credential_access", "")
                elif "discover" in description or "enum" in description or "scan" in description:
                    detection = DETECTION_TEMPLATES.get("discovery", "")
                elif "lateral" in description or "remote" in description or "move" in description:
                    detection = DETECTION_TEMPLATES.get("lateral_movement", "")
                elif "collect" in description or "data" in description or "capture" in description:
                    detection = DETECTION_TEMPLATES.get("collection", "")
                elif "command" in description or "c2" in description or "control" in description:
                    detection = DETECTION_TEMPLATES.get("command_and_control", "")
                elif "exfiltr" in description or "transfer" in description or "upload" in description:
                    detection = DETECTION_TEMPLATES.get("exfiltration", "")
                elif "impact" in description or "denial" in description or "destroy" in description:
                    detection = DETECTION_TEMPLATES.get("impact", "")
                else:
                    detection = DETECTION_TEMPLATES.get("default", "")
        technique["detection"] = detection

    # 缓解措施
    if not technique.get("mitigation"):
        mitigation = MITIGATION_BY_TECHNIQUE.get(tid)
        if not mitigation:
            if tactic_id in TACTIC_MITIGATION:
                mitigation = TACTIC_MITIGATION[tactic_id]
            else:
                mitigation = f"参考 MITRE ATT&CK 官方缓解建议 {tid}"
        technique["mitigation"] = mitigation

    return technique


def main():
    # 加载现有数据
    if not os.path.exists(OUTPUT_FILE):
        print(f"❌ 未找到 MITRE 数据: {OUTPUT_FILE}")
        return

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    techs = data.get("techniques", [])
    tactics_map = {}
    for t in data.get("tactics", []):
        tactics_map[t["id"]] = t["name"]

    enriched = 0
    for tech in techs:
        tactic_id = tech.get("phase", "")
        old_det = bool(tech.get("detection"))
        old_mit = bool(tech.get("mitigation"))

        tech = enrich_technique(tech, tactic_id)

        if not old_det:
            enriched += 1
        if not old_mit:
            enriched += 1

    data["techniques"] = techs
    data["meta"] = {
        **data.get("meta", {}),
        "source": data.get("meta", {}).get("source", "MITRE CTI STIX 2.1 local snapshot"),
        "source_url": data.get("meta", {}).get(
            "source_url",
            "https://github.com/mitre-attack/attack-stix-data",
        ),
        "enriched": True,
        "enrichment_time": __import__("datetime").datetime.now().isoformat(),
        "total_techniques": len(techs),
        "with_detection": sum(1 for t in techs if t.get("detection")),
        "with_mitigation": sum(1 for t in techs if t.get("mitigation")),
    }

    tmp_file = OUTPUT_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_file, OUTPUT_FILE)

    print("[OK] MITRE 知识补充完成")
    print(f"   总技术数: {len(techs)}")
    print(f"   补充字段数: {enriched}")
    print(f"   有检测字段: {data['meta']['with_detection']}/{len(techs)}")
    print(f"   有缓解字段: {data['meta']['with_mitigation']}/{len(techs)}")


if __name__ == "__main__":
    main()
