# -*- coding: utf-8 -*-
"""net_check.py — 兼容入口
==========================
保留旧入口名称，内部转发至 `main.main()`。
"""

import sys

from main import main

if __name__ == "__main__":
    sys.exit(main())
