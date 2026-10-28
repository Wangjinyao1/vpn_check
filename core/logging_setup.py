# -*- coding: utf-8 -*-
"""core/logging_setup.py — 日志初始化（规范第 8 条）
=================================================
单文件运行日志 `run_log.log`，单文件上限 3MB（轮转后覆盖自身，不产生备份文件）。
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from core import config

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
MAX_BYTES = 3 * 1024 * 1024


def setup_logging(level: int = logging.INFO) -> None:
    """初始化全局日志（重复调用不会叠加 handler）"""
    root = logging.getLogger()
    if getattr(root, "_vpn_check_configured", False):
        return

    handler = RotatingFileHandler(
        config.LOG_FILE, maxBytes=MAX_BYTES, backupCount=0, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    root.addHandler(handler)
    root.setLevel(level)
    root._vpn_check_configured = True  # type: ignore[attr-defined]

    # 第三方库降噪
    for noisy in ("urllib3", "curl_cffi", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
