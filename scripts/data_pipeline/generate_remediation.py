"""
应急响应剧本扩展
补充常见安全事件的响应指南（从 NIST 800-61 / CISA 指南 提取）
"""
import os
import sys
import json
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.utils.logger import setup_logger
logger = setup_logger("pipeline.remediation")

OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data", "remediation"
)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "remediation.json")


ADDITIONAL_PLAYBOOKS = [
    {
        "scenario": "Web应用漏洞利用",
        "indicators": "WAF告警；Web日志中异常URL参数、SQL注入payload、XSS payload；文件包含特征；目录遍历尝试",
        "immediate_actions": [
            "确认WAF是否已拦截攻击payload",
            "临时封禁攻击源IP",
            "检查Web服务器日志确认攻击是否成功",
            "如果成功，检查是否有webshell写入（/tmp、/uploads等目录）",
            "隔离受影响的Web服务器",
        ],
        "medium_term": [
            "修复漏洞（SQL注入参数化查询/XSS输出编码等）",
            "加固WAF规则，添加虚拟补丁",
            "对Web应用进行代码审计",
            "部署RASP（运行时应用自我保护）",
        ],
        "long_term": [
            "建立安全开发生命周期（SDL）",
            "定期Web应用渗透测试",
            "自动化SAST/DAST集成到CI/CD",
        ],
    },
    {
        "scenario": "DNS劫持/篡改",
        "indicators": "用户无法访问正常网站；DNS解析返回异常IP；域名注册信息被修改；DNS TTL异常变化",
        "immediate_actions": [
            "确认DNS解析状态，检查域名注册商账户安全",
            "联系域名注册商锁定域名（Registrar Lock）",
            "检查并修改DNS记录，清除恶意解析",
            "重置域名注册商账户密码，启用MFA",
            "通知用户使用备用DNS（如114.114.114.114、8.8.8.8）",
        ],
        "medium_term": [
            "启用DNSSEC（DNS安全扩展）",
            "使用DNS监控服务实时告警DNS变更",
            "审核域名注册商安全历史",
            "迁移到声誉更好的DNS托管服务",
        ],
        "long_term": [
            "实施多因素认证保护域名注册账户",
            "定期审计DNS记录完整性",
            "建立域名续费预警机制",
        ],
    },
    {
        "scenario": "云凭证泄露",
        "indicators": "云平台API调用量异常；非工作时间大量资源创建；陌生地域的API访问；云成本突增；Github仓库中发现AK/SK",
        "immediate_actions": [
            "立即撤销泄露的访问密钥",
            "检查IAM角色和权限，最小化权限",
            "审计所有使用泄露凭证的API调用记录",
            "检查是否创建了后门用户或角色",
            "检查是否有新增的云资源（EC2、OSS、RDS等）",
            "启用CloudTrail/操作审计全面记录",
        ],
        "medium_term": [
            "使用临时凭证（STS）替代永久AK/SK",
            "实施基础设施即代码（IaC）确保环境一致性",
            "配置密钥自动轮转策略",
            "部署密钥泄露检测工具（如GitGuardian、静默扫描）",
        ],
        "long_term": [
            "实施零信任架构",
            "使用Secrets Manager统一管理凭证",
            "定期审计Github仓库中的敏感信息",
            "建立云安全态势管理（CSPM）",
        ],
    },
    {
        "scenario": "容器逃逸/集群攻击",
        "indicators": "容器内发现根用户；意外的主机进程访问；/var/run/docker.sock暴露；Kubernetes API未授权访问；容器内安装新工具",
        "immediate_actions": [
            "隔离受影响的节点（kubectl cordon）",
            "驱逐可疑Pod（kubectl drain）",
            "检查容器镜像是否包含恶意软件",
            "审计Kubernetes审计日志",
            "验证kubelet配置安全性",
        ],
        "medium_term": [
            "配置Pod安全策略（PSP/Pod Security Admission）",
            "启用容器运行时安全（AppArmor/Seccomp）",
            "限制容器权限（readOnlyRootFilesystem、drop capabilities）",
            "使用镜像扫描工具（Trivy/Clair）扫描镜像漏洞",
            "配置网络策略（NetworkPolicy）实现微隔离",
        ],
        "long_term": [
            "实施容器安全生命周期管理",
            "部署容器安全平台（如Aqua/Twistlock）",
            "定期集群安全审计（kube-bench）",
            "建立不可变基础设施模式",
        ],
    },
    {
        "scenario": "账号失陷/凭证窃取",
        "indicators": "异常登录时间/地点；多次登录失败后成功；新设备/MFA变更；异常数据访问模式；第三方账号绑定异常",
        "immediate_actions": [
            "立即重置用户密码并撤销会话Token",
            "检查并移除异常的MFA配置",
            "检查账号关联的OWA/邮箱规则（用于隐藏邮件）",
            "审查最近7天的所有登录活动和敏感操作",
            "通知用户确认账号活动",
        ],
        "medium_term": [
            "启用自适应MFA（基于风险条件触发）",
            "配置异常登录告警（地理位置/设备指纹/时间）",
            "实施最小权限原则，定期审查权限",
            "部署UEBA（用户实体行为分析）",
        ],
        "long_term": [
            "部署密码less认证（FIDO2/Passkeys）",
            "实施零信任网络访问（ZTNA）",
            "建立身份治理和管理（IGA）体系",
        ],
    },
    {
        "scenario": "挖矿木马感染",
        "indicators": "CPU使用率持续100%；网络连接矿池地址；主机响应缓慢；发现挖矿进程（xmrig等）；电力消耗异常",
        "immediate_actions": [
            "终止挖矿进程",
            "查找并删除挖矿程序文件和相关脚本",
            "检查计划任务/cron和自启动项",
            "封禁矿池域名和IP",
            "如果是容器环境，立即重建镜像",
        ],
        "medium_term": [
            "检查漏洞来源：未授权访问/弱口令/未修复漏洞",
            "扫描所有主机和容器镜像",
            "修复发现的安全漏洞",
            "配置资源监控和告警",
        ],
        "long_term": [
            "配置HIDS/HIPS监控异常进程",
            "实施应用白名单（如CIS基准）",
            "定期安全加固基线检查",
        ],
    },
    {
        "scenario": "供应链攻击",
        "indicators": "软件更新包含异常代码；构建环境被篡改；依赖库存在后门；第三方服务商数据泄露；意外软件行为",
        "immediate_actions": [
            "识别受影响的环境和系统",
            "确认攻击范围和影响深度",
            "隔离受影响系统",
            "检查是否有数据外传迹象",
            "联系软件供应商获取修复方案",
        ],
        "medium_term": [
            "验证软件包哈希和签名",
            "审查构建管道安全性",
            "使用SBOM（软件物料清单）管理资产",
            "检查所有第三方依赖的安全性",
        ],
        "long_term": [
            "建立供应链安全风险管理流程",
            "实施最小权限的CI/CD管道",
            "使用镜像代理仓库缓存可信映像",
            "定期审计供应商安全态势",
        ],
    },
]

# ──────────────────────────────────────────────
# 新增应急场景（阶段二：扩充至30+场景）
# ──────────────────────────────────────────────
ADDITIONAL_PLAYBOOKS_V2 = [
    {
        "scenario": "AD域控制器沦陷（黄金票据/白银票据）",
        "indicators": "异常Kerberos TGT请求；DCSync事件（Event ID 4662）；服务账号异常登录；KRBTGT密码被修改；异常的服务票据",
        "immediate_actions": [
            "隔离域控制器网络连接",
            "重置KRBTGT账号密码（两次，间隔至少10小时）",
            "重置所有域管理员密码",
            "禁用可疑账号并检查其活动",
            "检查Golden/Silver Ticket攻击迹象（异常TGT/服务票据）",
        ],
        "medium_term": [
            "部署AD安全监控（Microsoft Defender for Identity）",
            "实施Protected Users安全组",
            "限制DCSync权限（删除不必要的Replicating Directory Changes权限）",
            "启用高级审计策略（Kerberos服务票据操作审计）",
        ],
        "long_term": [
            "实施红林/蓝林AD架构分离",
            "建立AD安全基线（CIS Benchmark）",
            "定期进行AD安全评估和渗透测试",
        ],
    },
    {
        "scenario": "供应链攻击（第三方库投毒）",
        "indicators": "依赖包版本异常更新；构建时异常网络连接；代码仓库异常commit；包哈希与官方不匹配；CVE扫描检出供应链相关漏洞",
        "immediate_actions": [
            "锁定受影响的构建版本，阻止发布流程",
            "回滚到已知安全的依赖版本",
            "审计依赖完整性校验（checksum/签名）",
            "检查代码仓库是否被植入后门",
            "通知上游供应商和安全团队",
        ],
        "medium_term": [
            "实施依赖锁定策略（lockfile/Pipfile.lock）",
            "启用软件物料清单（SBOM）自动生成",
            "部署依赖漏洞扫描（Dependabot/Snyk）",
            "使用私有镜像仓库+签名校验机制",
        ],
        "long_term": [
            "建立软件供应链安全策略",
            "实施SLSA安全框架",
            "定期进行供应商安全审查",
            "建立软件物料清单管理流程",
        ],
    },
    {
        "scenario": "API密钥泄露/凭证泄露",
        "indicators": "API调用来自异常地域；短时间内大量401错误；非工作时间高频调用；云平台账单异常增长；Github仓库发现硬编码密钥",
        "immediate_actions": [
            "立即轮换泄露的API密钥",
            "审计所有使用泄露密钥的API调用记录（过去30天）",
            "确认数据泄露范围和受影响的数据/资源",
            "检查是否使用了泄露密钥创建了其他资源",
            "通知相关利益方（客户/监管/管理层）",
        ],
        "medium_term": [
            "实施短暂临时凭证（STS）替代永久AK/SK",
            "设置API密钥IP白名单/地域限制",
            "部署密钥泄露扫描（GitGuardian）",
            "启用密钥自动轮转策略（30/90天）",
        ],
        "long_term": [
            "使用Secrets Manager统一管理凭证",
            "实施Git提交前密钥检测pre-commit hook",
            "移除代码仓库中所有硬编码凭证",
            "建立密码less认证体系（OIDC/FIDO2）",
        ],
    },
    {
        "scenario": "IaaS云基础设施入侵（AWS/Azure/GCP）",
        "indicators": "CloudTrail日志中异常API调用；IAM角色异常AssumeRole；S3存储桶公开访问异常；EC2实例在未知地域启动；控制台登录异常",
        "immediate_actions": [
            "确认云平台告警事件",
            "立即撤销泄露的Access Key/登录凭证",
            "隔离受影响的EC2实例（更换安全组/快照取证）",
            "启用S3 Block Public Access（如适用）",
            "审计CloudTrail/Azure Monitor完整事件链",
        ],
        "medium_term": [
            "实施服务控制策略（SCP）进行权限边界控制",
            "启用GuardDuty/Security Hub实时监控",
            "配置AWS Config合规规则监控资源变更",
            "删除未使用的IAM用户和角色",
            "实施基础设施即代码（Terraform/Pulumi）",
        ],
        "long_term": [
            "实施云安全态势管理（CSPM）",
            "部署云工作负载保护平台（CWPP）",
            "建立多云安全统一管理策略",
            "定期进行云渗透测试",
        ],
    },
    {
        "scenario": "Active Directory证书服务滥用（ADCS）",
        "indicators": "异常证书请求模板；CA服务器上Event ID 4886/4887异常；新注册的AD计算机账号；Kerberos PKINIT异常请求；非域管用户请求域管证书",
        "immediate_actions": [
            "禁用ADCS证书颁发服务（暂停新证书颁发）",
            "吊销已知被滥用的证书",
            "检查并修复ESC1-ESC8漏洞配置",
            "审计所有近期颁发的可疑证书",
            "检查域控上是否有新创建的管理员账户",
        ],
        "medium_term": [
            "修复ADCS配置（启用CA角色分离、审核）",
            "配置证书模板安全设置（CA证书管理器审批）",
            "启用ADCS事件审计日志",
            "部署PKI健康检查工具（PSPKIAudit）",
        ],
        "long_term": [
            "实施ADCS堡垒机架构",
            "定期AD安全评估（包括ADCS）",
            "迁移到云端CA（Azure AD Certificate Services）",
        ],
    },
    {
        "scenario": "内部钓鱼攻击（横向钓鱼）",
        "indicators": "内部账号发送钓鱼邮件；异常邮件规则（转发/自动回复）；邮件流的SPF/DKIM验证失败；内部邮件服务器异常登录",
        "immediate_actions": [
            "确认失陷邮箱账号并立即重置密码",
            "撤销所有邮件应用的授权Token",
            "检查并删除异常的邮箱规则（转发/自动回复）",
            "审计失陷邮件的发件记录",
            "通知所有可能受影响的收件人",
        ],
        "medium_term": [
            "启用邮箱登录和多因子认证（MFA）",
            "部署邮件安全网关（反钓鱼+URL检测）",
            "配置邮箱活动告警（异常登录/规则修改）",
            "培训用户识别高级钓鱼攻击",
        ],
        "long_term": [
            "实施DMARC拒绝策略（p=reject）",
            "部署内部邮件安全监控",
            "建立反钓鱼演练常态化机制",
        ],
    },
    {
        "scenario": "物联网/OT设备入侵",
        "indicators": "IoT设备异常网络流量；Mirai/Gafgyt等IoT僵尸网络特征；设备频繁重启；ICS/SCADA系统异常行为；PLC控制逻辑异常修改",
        "immediate_actions": [
            "隔离受感染的IoT设备（网络切断/VLAN隔离）",
            "修改设备默认密码（所有IoT设备）",
            "检查设备是否有未修复的已知漏洞",
            "审计设备日志（如有）",
            "关闭不必要的远程访问端口",
        ],
        "medium_term": [
            "建立IoT/OT资产清单",
            "实施网络分段（OT网络与IT网络隔离）",
            "部署OT安全监控（流量基线异常检测）",
            "升级/替换无法更新的不安全设备",
        ],
        "long_term": [
            "建立OT安全运营中心（SOC-OT）",
            "实施零信任架构扩展到OT环境",
            "制定OT安全应急响应专项预案",
        ],
    },
    {
        "scenario": "零日漏洞大规模利用（爆发期）",
        "indicators": "安全厂商发布零日漏洞通告；WAF/IDS产生相关告警；网络扫描发现新攻击活动；内部资产扫描发现受影响组件",
        "immediate_actions": [
            "确认受影响资产清单（软件版本/暴露面）",
            "部署WAF/IPS虚拟补丁（如支持）",
            "对受影响系统实施临时缓解措施（禁用功能、端口隔离）",
            "检查是否存在被利用迹象（日志审查/IOC匹配）",
            "将受影响系统列入优先修复清单",
        ],
        "medium_term": [
            "跟踪厂商修复补丁发布进度",
            "安排停机窗口进行补丁部署",
            "增强对受影响系统的监控",
            "检查供应链是否受影响",
        ],
        "long_term": [
            "建立零日漏洞应急响应预案",
            "加强漏洞管理流程的时效性",
            "评估并减少攻击面（最小化安装）",
            "建立威胁情报预警机制",
        ],
    },
    {
        "scenario": "内部人员数据泄露",
        "indicators": "员工非工作时间大量下载数据；异常的数据导出量；USB设备大量拷贝；打印大量敏感文件；向外部邮箱发送公司数据",
        "immediate_actions": [
            "立即暂停涉事人员账号",
            "物理隔离涉事设备",
            "保全日志和数据取证",
            "确认数据泄露类型和范围",
            "通知法务/合规/HR部门",
        ],
        "medium_term": [
            "实施DLP策略（数据防泄漏）",
            "部署UEBA检测异常用户行为",
            "配置敏感数据访问告警",
            "实施前提离职安全流程",
        ],
        "long_term": [
            "建立数据分类分级制度",
            "实施最小权限原则和Just-In-Time访问",
            "部署数据访问审计和异常行为检测",
            "定期安全意识培训",
        ],
    },
    {
        "scenario": "配置错误导致的数据暴露（S3/Azure Blob/K8s）",
        "indicators": "安全扫描发现公开存储桶；Shodan/Censys上发现暴露数据；外部研究人员报告数据泄露；云平台合规告警",
        "immediate_actions": [
            "立即关闭公开访问权限",
            "评估暴露的数据内容和影响范围",
            "对暴露的数据进行hash取证",
            "通知受影响的数据主体（如涉及个人信息）",
            "检查访问日志确认是否已被未授权访问",
        ],
        "medium_term": [
            "配置云安全基线规则（AWS Config/合规策略）",
            "实施基础设施即代码（IaC）确保配置一致性",
            "部署CSPM工具持续监控配置合规",
            "设置公开存储桶告警机制",
        ],
        "long_term": [
            "建立云安全配置基线",
            "实施自动化合规检查（CI/CD安全门禁）",
            "定期进行云安全架构评审",
        ],
    },
]


def generate_remediation():
    """生成完整应急响应指南"""
    output_dir = os.path.dirname(OUTPUT_FILE)
    os.makedirs(output_dir, exist_ok=True)

    # 加载已有数据
    existing = {"remediation_playbooks": []}
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    existing_playbooks = existing.get("remediation_playbooks", [])
    existing_scenarios = {p.get("scenario", "").lower() for p in existing_playbooks}

    # 添加 document_text 到已有和新增的剧本
    added = 0
    all_playbooks = list(existing_playbooks)

    for pb in ADDITIONAL_PLAYBOOKS:
        scenario_lower = pb["scenario"].lower()
        if scenario_lower not in existing_scenarios:
            pb["document_text"] = _build_remediation_text(pb)
            all_playbooks.append(pb)
            existing_scenarios.add(scenario_lower)
            added += 1
            logger.info(f"新增剧本: {pb['scenario']}")
        else:
            logger.info(f"已存在: {pb['scenario']}")

    # V2 补充场景
    try:
        for pb in ADDITIONAL_PLAYBOOKS_V2:
            scenario_lower = pb["scenario"].lower()
            if scenario_lower not in existing_scenarios:
                pb["document_text"] = _build_remediation_text(pb)
                all_playbooks.append(pb)
                existing_scenarios.add(scenario_lower)
                added += 1
                logger.info(f"新增剧本V2: {pb['scenario']}")
            else:
                logger.info(f"已存在V2: {pb['scenario']}")
    except NameError:
        logger.warning("ADDITIONAL_PLAYBOOKS_V2 未定义，跳过")

    # 为已有剧本补充 document_text
    for pb in all_playbooks:
        if "document_text" not in pb:
            pb["document_text"] = _build_remediation_text(pb)

    output = {
        "remediation_playbooks": all_playbooks,
        "meta": {
            "total": len(all_playbooks),
            "scenarios": [p["scenario"] for p in all_playbooks],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "NIST SP 800-61 Rev 2, CISA ICS-CERT 指南, 行业最佳实践",
        },
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    logger.info(f"应急响应指南: {len(all_playbooks)} 个场景 (新增 {added} 个)")
    return len(all_playbooks)


def _build_remediation_text(pb: dict) -> str:
    """为嵌入构建文档文本"""
    parts = [
        f"应急响应剧本: {pb['scenario']}",
        f"识别指标: {pb.get('indicators', '')}",
    ]
    if pb.get("immediate_actions"):
        parts.append("立即处置:\n" + "\n".join(f"- {a}" for a in pb["immediate_actions"]))
    if pb.get("medium_term"):
        parts.append("中期措施:\n" + "\n".join(f"- {a}" for a in pb["medium_term"]))
    if pb.get("long_term"):
        parts.append("长期方案:\n" + "\n".join(f"- {a}" for a in pb["long_term"]))
    return "\n\n".join(parts)


if __name__ == "__main__":
    count = generate_remediation()
    print(f"应急响应指南已生成: {count} 个场景")
    sys.exit(0)

