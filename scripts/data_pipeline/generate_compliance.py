"""
合规知识库生成器
生成国际主流安全合规法规的结构化数据（补充现有中国法规）
"""
import os
import sys
import json
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.utils.logger import setup_logger
logger = setup_logger("pipeline.compliance")

OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data", "compliance"
)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "regulations.json")


def _load_existing() -> dict:
    """加载现有合规数据"""
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            pass
    return {"regulations": []}


# 国际安全合规法规（补充到现有中国法规基础上）
INTERNATIONAL_REGULATIONS = [
    {
        "name": "General Data Protection Regulation",
        "abbr": "GDPR",
        "standard_id": "EU 2016/679",
        "jurisdiction": "欧盟",
        "category": "数据保护",
        "description": "欧盟通用数据保护条例，对个人数据处理和跨境流动进行规范，是当前全球最严格的数据保护法规之一",
        "key_requirements": [
            "个人数据处理需获得明确同意（Article 7）",
            "数据泄露需在72小时内通知监管机构（Article 33）",
            "数据可携带权（Article 20）",
            "被遗忘权/删除权（Article 17）",
            "数据保护影响评估（Article 35）",
            "指定数据保护官（Article 37）",
            "充分性认定或标准合同条款用于跨境传输（Article 45-46）",
        ],
        "penalties": "最高 2000 万欧元或全球年营业额的 4%（取高者）",
        "applicable_to": "处理欧盟居民个人数据的任何组织（无论所在地）",
        "security_requirements": [
            "实施适当的技术和组织措施（Article 32）",
            "数据最小化原则",
            "隐私默认设计（Article 25）",
            "处理活动记录（Article 30）",
            "定期安全测试和评估",
        ],
    },
    {
        "name": "Payment Card Industry Data Security Standard",
        "abbr": "PCI DSS",
        "standard_id": "PCI DSS v4.0",
        "jurisdiction": "全球",
        "category": "支付安全",
        "description": "支付卡行业数据安全标准，适用于所有处理、存储或传输持卡人数据的组织",
        "key_requirements": [
            "安装和维护防火墙配置（Requirement 1）",
            "不使用供应商提供的默认密码（Requirement 2）",
            "保护存储的持卡人数据（Requirement 3）",
            "加密持卡人数据的传输（Requirement 4）",
            "使用并定期更新防病毒软件（Requirement 5）",
            "开发并维护安全系统和应用程序（Requirement 6）",
            "根据业务需要限制数据访问（Requirement 7）",
            "对系统组件进行唯一身份标识（Requirement 8）",
            "限制对持卡人数据的物理访问（Requirement 9）",
            "跟踪和监控对网络资源和持卡人数据的访问（Requirement 10）",
            "定期测试安全系统和流程（Requirement 11）",
            "维护信息安全策略（Requirement 12）",
        ],
        "penalties": "每月 $5,000-$100,000 罚款，或取消卡片受理资格",
        "applicable_to": "所有处理持卡人数据的商户、服务提供商和金融机构",
        "security_requirements": [
            "持卡人数据加密存储",
            "传输加密（TLS 1.2+）",
            "多因素认证",
            "季度漏洞扫描",
            "年度渗透测试",
            "安全日志保留至少12个月",
        ],
    },
    {
        "name": "Health Insurance Portability and Accountability Act",
        "abbr": "HIPAA",
        "standard_id": "45 CFR 160, 164",
        "jurisdiction": "美国",
        "category": "医疗健康",
        "description": "美国健康保险流通与责任法案，规定受保护健康信息的隐私和安全标准",
        "key_requirements": [
            "隐私规则：保护个人健康信息（45 CFR 164.500-534）",
            "安全规则：管理、物理和技术安全措施（45 CFR 164.302-318）",
            "违规通知规则：数据泄露通知义务（45 CFR 164.400-414）",
            "实施访问控制（用户认证和授权）",
            "审计控制（记录系统活动日志）",
            "完整性控制（防止数据被非法修改）",
            "传输安全（加密数据传输）",
            "应急预案和恢复计划",
        ],
        "penalties": "每年最高 $1,919,173（故意违规），民事罚款 $100-$50,000/条",
        "applicable_to": "医疗服务提供者、健康计划、医疗信息处理中心及其业务伙伴",
        "security_requirements": [
            "行政保障：风险评估、培训、应急计划",
            "物理保障：设施控制、工作站安全",
            "技术保障：访问控制、审计控制、完整性",
            "组织保障：业务伙伴协议",
            "政策和程序文档化",
        ],
    },
    {
        "name": "ISO/IEC 27001",
        "abbr": "ISO 27001",
        "standard_id": "ISO/IEC 27001:2022",
        "jurisdiction": "全球",
        "category": "信息安全管理",
        "description": "国际信息安全管理体系标准，规定了建立、实施、维护和持续改进信息安全管理体系的要求",
        "key_requirements": [
            "组织环境分析（Clause 4）",
            "领导力和承诺（Clause 5）",
            "信息安全风险评估和处置计划（Clause 6.1）",
            "资源支持（Clause 7）",
            "运行计划和控制（Clause 8）",
            "绩效评估和内部审计（Clause 9）",
            "管理评审和持续改进（Clause 10）",
            "附件A：93项控制措施（A.5-A.8）",
        ],
        "penalties": "认证失效/暂停，商业信誉损失",
        "applicable_to": "任何建立信息安全管理系统并寻求认证的组织",
        "security_requirements": [
            "信息安全策略",
            "组织信息安全",
            "人力资源安全",
            "资产管理",
            "访问控制",
            "密码技术",
            "物理和环境安全",
            "操作安全",
            "通信安全",
            "系统获取、开发和维护",
            "供应商关系",
            "信息安全事件管理",
            "业务连续性管理",
            "合规性",
        ],
    },
    {
        "name": "SOC 2",
        "abbr": "SOC 2",
        "standard_id": "AICPA SOC 2",
        "jurisdiction": "美国/全球",
        "category": "服务组织控制",
        "description": "美国注册会计师协会（AICPA）制定的服务组织控制报告标准，评估服务商的安全、可用性、处理完整性、保密性和隐私控制",
        "key_requirements": [
            "安全：保护系统资源免受未授权访问（Common Criteria）",
            "可用性：确保系统按照承诺可用和运行",
            "处理完整性：系统处理完成、准确、及时且经授权",
            "保密性：机密信息受到保护",
            "隐私：个人信息按照隐私声明收集、使用、保留和处置",
            "CC1.0: 控制环境",
            "CC2.0: 沟通和信息",
            "CC3.0: 风险评估",
            "CC4.0: 监控活动",
            "CC5.0: 控制活动",
        ],
        "penalties": "审计失败/不合格报告，客户流失",
        "applicable_to": "SaaS/云服务提供商、数据处理中心、托管服务商等",
        "security_requirements": [
            "逻辑和物理访问控制",
            "系统监控和日志管理",
            "变更管理流程",
            "风险评估和管理",
            "供应商管理",
            "事件响应计划",
            "数据备份和恢复",
            "安全培训",
        ],
    },
    {
        "name": "NIST Cybersecurity Framework",
        "abbr": "NIST CSF",
        "standard_id": "NIST CSF v2.0",
        "jurisdiction": "美国/全球",
        "category": "网络安全框架",
        "description": "美国国家标准技术研究院发布的网络安全框架，提供基于风险的方法管理网络安全风险",
        "key_requirements": [
            "识别（Identify）：资产管理、业务环境、治理、风险评估、风险管理策略",
            "保护（Protect）：访问控制、意识培训、数据安全、信息保护流程、维护、保护技术",
            "检测（Detect）：异常和事件、连续安全监控、检测流程",
            "响应（Respond）：响应计划、沟通、分析、缓解、改进",
            "恢复（Recover）：恢复计划、改进、沟通",
            "治理（Govern）：企业风险管理策略、供应链风险管理",
        ],
        "penalties": "无法定罚款（自愿框架），但合规要求可获监管认可",
        "applicable_to": "关键基础设施组织及寻求提升网络安全的各类组织",
        "security_requirements": [
            "资产管理（ID.AM）",
            "风险评估（ID.RA）",
            "访问控制（PR.AC）",
            "数据安全（PR.DS）",
            "信息保护流程（PR.IP）",
            "维护（PR.MA）",
            "保护技术（PR.PT）",
            "异常和事件检测（DE.AE）",
            "安全连续监控（DE.CM）",
            "事件响应管理（RS.MA）",
        ],
    },
    {
        "name": "Personal Information Protection and Electronic Documents Act",
        "abbr": "PIPEDA",
        "standard_id": "SC 2000, c. 5",
        "jurisdiction": "加拿大",
        "category": "数据保护",
        "description": "加拿大个人信息保护和电子文档法案，规范私营机构在商业活动中收集、使用和披露个人信息的行为",
        "key_requirements": [
            "责任原则：组织对个人信息负责",
            "目的说明：收集前说明目的",
            "同意：需知情同意",
            "限制收集：只收集必要信息",
            "限制使用和披露：仅用于收集目的",
            "准确性：保持信息准确",
            "安全措施：适当的安全保护",
            "开放性：信息管理政策透明",
            "个人访问：允许个人访问自己的信息",
            "合规挑战：接受投诉和调查",
        ],
        "penalties": "最高 $100,000 CAD 罚款",
        "applicable_to": "在商业活动中收集个人信息的加拿大私营组织",
        "security_requirements": [
            "个人信息保护措施",
            "数据加密",
            "访问控制",
            "员工培训",
            "数据泄露通知",
            "信息保留和销毁政策",
        ],
    },
    {
        "name": "California Consumer Privacy Act",
        "abbr": "CCPA",
        "standard_id": "Cal. Civ. Code § 1798.100",
        "jurisdiction": "美国（加州）",
        "category": "数据保护",
        "description": "加州消费者隐私法案，赋予加州居民对其个人信息的更多控制权，是美国最严格的州级数据隐私法",
        "key_requirements": [
            "知情权：企业必须告知收集的个人信息类别和目的",
            "删除权：消费者可要求删除其个人信息",
            "选择退出权：消费者可选择不出售其个人信息",
            "非歧视：行使权利不会受到价格或服务歧视",
            "访问权：消费者可请求访问收集的特定信息",
            "数据可携带权：以可移植格式获取数据",
        ],
        "penalties": "每次故意违规 $7,500，非故意 $2,500；私人诉讼 $100-$750/人/次",
        "applicable_to": "年收入 >$2500万 或处理 >10万 人信息的在加州运营企业",
        "security_requirements": [
            "个人信息分类和映射",
            "隐私政策更新",
            "消费者权利响应机制",
            "与第三方数据共享协议管理",
            "数据安全措施",
        ],
    },
]


def generate_compliance():
    """生成完整的合规知识库（保留现有数据 + 新增国际法规）"""
    existing = _load_existing()
    existing_regs = existing.get("regulations", [])

    # 检查已存在的法规（按缩写或名称去重）
    existing_abbrs = {r.get("abbr", "").lower() for r in existing_regs}

    added = 0
    for reg in INTERNATIONAL_REGULATIONS:
        abbr = reg.get("abbr", "").lower()
        if abbr not in existing_abbrs:
            # 为嵌入准备 document_text
            reg["document_text"] = _build_compliance_text(reg)
            existing_regs.append(reg)
            existing_abbrs.add(abbr)
            added += 1
            logger.info(f"新增合规: {reg['abbr']} - {reg['name']}")
        else:
            logger.info(f"已存在: {reg['abbr']}")

    # 为旧的法规也补充 document_text
    for reg in existing_regs:
        if "document_text" not in reg:
            reg["document_text"] = _build_compliance_text(reg)

    output = {
        "regulations": existing_regs,
        "meta": {
            "total": len(existing_regs),
            "jurisdictions": list(set(r.get("jurisdiction", "") for r in existing_regs if r.get("jurisdiction"))),
            "categories": list(set(r.get("category", "") for r in existing_regs if r.get("category"))),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    logger.info(f"合规知识库: {len(existing_regs)} 条法规 (新增 {added} 条)")
    return len(existing_regs)


def _build_compliance_text(reg: dict) -> str:
    """为嵌入构建合规文档文本"""
    parts = [
        f"合规法规: {reg.get('name', '')} ({reg.get('abbr', '')})",
        f"标准编号: {reg.get('standard_id', '')}",
        f"管辖区域: {reg.get('jurisdiction', '')}",
        f"类别: {reg.get('category', '')}",
        f"描述: {reg.get('description', '')}",
    ]
    if reg.get("applicable_to"):
        parts.append(f"适用范围: {reg['applicable_to']}")
    if reg.get("penalties"):
        parts.append(f"违规处罚: {reg['penalties']}")
    reqs = reg.get("key_requirements", [])
    if reqs:
        parts.append("核心要求:\n" + "\n".join(f"- {r}" for r in reqs))
    sec_reqs = reg.get("security_requirements", [])
    if sec_reqs:
        parts.append("安全要求:\n" + "\n".join(f"- {r}" for r in sec_reqs))
    return "\n\n".join(parts)


if __name__ == "__main__":
    count = generate_compliance()
    print(f"合规知识库已生成: {count} 条法规")
    sys.exit(0)

