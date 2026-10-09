# ios-security-recon

> **面向 iOS 27 与 macOS 的防御性平台安全分析与签名权限规范审计工具链**

[English](README.md) | [简体中文](README_ZH.md)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Security Focus](https://img.shields.io/badge/focus-Defensive%20Security%20%26%20Audit-red.svg)](#安全合规与负责任披露声明)

---

## 1. 项目定位与安全准则

**`ios-security-recon`** 是一套开源的 Apple 平台（iOS 27 与 macOS）防御性静态代码分析与合规审计工具链。专为系统安全工程师、逆向研究者与企业移动设备管理员设计，提供以下核心能力：

- **代码签名权限提取与差异比对**：静态解析 Mach-O 二进制（32/64位及 FAT 架构）与配置文件中的 Entitlements 签名，检测潜在的越权凭据变更。
- **文件同步管道合规审计**：对文件传输通道（`MobileBackup2`、`AirTraffic`、`ATAirlock` 压缩包）进行路径规范化静态审计，防范目录穿越、Zip Slip 逃逸及 iOS 27 安全恢复抹机机制（Security State Recovery, SSR）触发风险。
- **物理硬件安全准入防护门禁**：内置基于 UDID 白名单/黑名单与固件版本的防御性门禁引擎，杜绝日常主力机（Daily Driver）误受实验性操作影响。
- **XPC 服务与接口静态扫描**：遍历 Mach-O 守护进程段与符号表，提取注册的 Mach 服务、导出的 Objective-C 选择器（Selectors），并审计是否严格校验客户端 Audit Token。

> [!IMPORTANT]
> **仅限防御性与学术安全研究**：本项目**绝不包含**任何漏洞利用 Payload、越狱提权代码或武器化利用组件。所有模块均为静态检查、路径审计与安全策略规则引擎，严格遵循 [Apple Security Bounty（苹果安全赏金计划）](https://security.apple.com/bounty) 与协调漏洞披露准则（CVD）。

---

## 2. 核心模块与功能设计

```text
ios_security_recon/
├── entitlements/        # 权限签名解析、差异比对与合规评分引擎
│   ├── parser.py        # 纯 Python Mach-O (32/64位 & FAT) 与 plist 解析器
│   ├── diff.py          # 权限差分比对器，支持特权提权风险检测
│   ├── inspector.py     # 平台安全基线合规评分器
│   └── rules.py         # 预设 Apple 安全最佳实践基线规则集
├── conduits/            # 文件同步与管道传输攻击面审计
│   ├── surface_audit.py # 路径规范化、目录穿越、Zip Slip、ATAirlock 符号链接审计
│   └── safety_gate.py   # 设备 UDID 安全过滤、系统版本校验与高危目录拦截
├── xpc/                 # Mach-O 静态结构与 XPC 接口分析
│   ├── parser.py        # 纯 Python Mach-O 段（Segments）、节（Sections）解析
│   └── scanner.py       # XPC 监听器、选择器与客户端权限校验审计
├── reporting/           # 多格式报告生成引擎 (Markdown, ANSI 控制台, JSON)
└── cli.py               # 统一命令行入口: `ios-recon`
```

### 核心模块一览

| 模块名称 | 核心能力 | 典型应用场景 |
|---|---|---|
| **`entitlements`** | 纯 Python 解析 `LC_CODE_SIGNATURE` SuperBlob 中的 `CSSLOT_ENTITLEMENTS`。 | 检测 `get-task-allow`、`task_for_pid-allow`、SpringBoard 私有凭据及沙盒豁免项。 |
| **`conduits`** | 审计流式传输 ZIP 压缩包与文件恢复路径。 | 检查路径规范化，阻断 Zip Slip / 符号链接越界，强制遵循 iOS 27 `BackupAgent2` 白名单。 |
| **`safety_gate`** | 硬件及操作系统合规性防御门禁。 | 拦截针对指定主力机 UDID（`AIRLIFT_BLOCKED_UDIDS`）的操作，严禁触碰敏感目录（如 `/var/preferences`）。 |
| **`xpc`** | 静态 Mach-O 二进制结构解析。 | 识别注册的系统守护服务接口与选择器，评估是否实施了 `SecTaskCreateWithAuditToken` 严格权限校验。 |

---

## 3. 快速上手

### 环境要求
- Python 3.9 或更高版本（已在 Python 3.12 深度验证）。
- **0 额外依赖**（完全基于 Python 标准库构建，无需配置复杂的 C 扩展环境）。

### 安装方式
克隆仓库并以可编辑模式安装：
```bash
git clone https://github.com/Prognosticate-X/ios-security-recon.git
cd ios-security-recon
pip install -e .
```
或无需安装直接通过 Python 模块调用：
```bash
python3 -m ios_security_recon.cli --help
```

---

## 4. CLI 命令行使用指南

统一命令行工具名称为 `ios-recon`。

### 4.1 权限签名合规审计与比对

#### 审计二进制文件或 Plist 的安全合规评分：
```bash
ios-recon entitlements inspect /path/to/binary_or_plist
```
```bash
# 以 JSON 格式输出机器可读数据
ios-recon entitlements inspect /path/to/AppBinary --format json
```

#### 对比两个版本的二进制权限差异：
```bash
ios-recon entitlements diff /path/to/baseline.plist /path/to/target.plist --format markdown
```
自动标记新增的私有特权凭据（`com.apple.private.*`）与潜在权限越界风险项（如 `task_for_pid-allow`）。

---

### 4.2 管道传输与文件路径安全审计

#### 审计目标路径的规范化与目录穿越风险：
```bash
ios-recon conduit audit "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive"
```

#### 审计流式传输 ZIP 压缩包的越界与 Zip Slip 风险：
```bash
ios-recon conduit audit /path/to/streaming_package.zip
```

#### 在操作执行前进行设备安全门禁评估：
```bash
ios-recon conduit gate \
  --udid "00008140-001A2B3C4D5E6F7G" \
  --target "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive" \
  --os-version "27.0" \
  --build "24A435"
```

---

### 4.3 静态 XPC 与 Mach-O 分析

提取守护进程注册的系统服务、选择器与客户端权限校验逻辑：
```bash
ios-recon xpc scan /path/to/SystemDaemon --format markdown
```

---

### 4.4 综合安全侦测报告生成

针对指定系统目标生成完整 Markdown 安全审计报告：
```bash
ios-recon report --target /path/to/target_binary --output report.md
```

---

## 5. 深入技术文档

在 [`docs/`](docs/) 目录下沉淀了系统架构与实证研究资料：
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**：深入剖析 iOS 27 SpringBoard、`SystemStatus` 发布订阅模型以及 `StatusBarOverrides.archive` 反序列化安全设计。
- **[`docs/RESPONSIBLE_DISCLOSURE.md`](docs/RESPONSIBLE_DISCLOSURE.md)**：严格的安全研究规范、测试设备物理隔离原则以及 Apple Product Security 协调披露指引。
- **[`docs/RESEARCH_NOTES.md`](docs/RESEARCH_NOTES.md)**：记录关于 `MobileBackup2` 白名单演变、Security State Recovery (SSR) 自愈抹机触发边界以及物理机 ATAirlock 重命名限制的技术备忘。

---

## 6. 测试套件

运行内置的自动化单元测试：
```bash
python3 -m unittest discover -s tests -v
```
全套 **54 项单元测试** 在 0.05 秒内执行完毕，测试覆盖率 100%。

---

## 7. 开源协议

本项目采用 [Apache 2.0](LICENSE) 开源许可协议。
