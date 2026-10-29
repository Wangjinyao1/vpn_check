# 项目开发记忆（vpn_check）

本文件用于让 AI / 协作者快速了解项目必须遵守的约定，对应团队《AI 编程规范》。

## 项目定位

- 面向中国大陆网络环境的机场节点评估工具，最终产物用于 OpenWrt Passwall。
- 一切协议解析、探针规则、UCI 字段必须与 `Openwrt-Passwall/subscribe.lua` 保持一致。
- Gemini 判定必须区分「网页可访问」「地区封锁」「真实提问可用」三态。

## 必须遵守的规范

1. **文档**：每次改代码同步更新 `README.md`，并在「版本迭代」中递增版本（小改 +0.01 / 中改 +0.1 / 大改 +1）。
2. **敏感信息**：只放 `.env`，不得硬编码；`.env` 必须被 `.gitignore` 忽略；仓库只保留脱敏的 `.env.example`。
3. **临时文件**：统一放 `.temp/`，文件名以 `temp_` 开头，运行结束即清理。
4. **无数据库**：项目不引入 MySQL / Redis / SQLite 等外部存储，结果只写本地报告与 `export/`。
5. **日志**：单文件 `run_log.log`，上限 3MB。
6. **配置**：所有可调参数集中在 `core/config.py`，禁止散落魔法值。
7. **IP 归属地**：进程内缓存 + ipinfo 回源，不再依赖任何本地数据库。
8. **保密性**：禁止提交 `Project_Require.md`、`export/`、`bin/`、`run_log.log`、`test_results.txt`、`.vscode/`；提交前执行 README 中的保密性自查命令。

## 代码结构约定

- 解析 → `core/parsers.py`；订阅拉取 → `core/subscription.py`；网络探测 → `core/netprobe.py`。
- 内核配置与生命周期只在 `core/engine.py`，不要在 checker 中直接拼 JSON。
- 领域模型集中在 `core/models.py`，模块间只传模型对象，避免裸 dict。
- 纯函数（解析、判定、配置生成）必须可单元测试，测试放 `tests/`。

## 验证要求

```bash
python -m unittest discover -s tests -v
python main.py --limit 2 --skip-gemini-chat --no-export
```

提交前确保：内核配置能被 `xray run -test` / `sing-box check` 验证通过，且工作区无敏感文件。
