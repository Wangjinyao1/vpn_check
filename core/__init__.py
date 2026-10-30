# -*- coding: utf-8 -*-
"""VPN Check Core Engine
========================
基于 Clash-SpeedTest、Gemini-Config-Checker 与 OpenWrt-Passwall 体系构建的节点质量评估套件。

模块职责：
- config       统一配置与 .env 解析
- models       领域模型（节点 / 探针 / 测试结果）
- parsers      分享链接解析（含反向生成分享链接）
- clash        Clash / Mihomo YAML 订阅解析
- subscription 机场订阅拉取与配额识别
- engine       真实内核隧道（Xray / Sing-box）
- netprobe     SOCKS5 HTTP 探针
- speedtest    节点吞吐测速（下载 / 可选上传）
- checker      探测管道、并发调度与独立测速阶段
- gemini       Gemini 地区封锁与提问验证
- ip_location  IP 归属地查询（进程缓存 + ipinfo）
- exporter     OpenWrt-Passwall 产物导出
- report       终端决策看板与结构化 JSON 输出
"""

__version__ = "9.10"
