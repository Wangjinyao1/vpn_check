# -*- coding: utf-8 -*-
"""VPN Check Core Engine
========================
基于 Clash-SpeedTest、Gemini-Config-Checker 与 OpenWrt-Passwall 体系构建的节点质量评估套件。

模块职责：
- config       统一配置与 .env 解析
- models       领域模型（节点 / 探针 / 测试结果）
- parsers      分享链接解析
- subscription 机场订阅拉取与配额识别
- engine       真实内核隧道（Xray / Sing-box）
- netprobe     SOCKS5 HTTP 探针
- checker      探测管道与并发调度
- gemini       Gemini 地区封锁与提问验证
- ip_location  IP 归属地缓存与回源
- database     MySQL 持久化
- exporter     OpenWrt-Passwall 产物导出
- report       终端决策看板
"""

__version__ = "8.03"
