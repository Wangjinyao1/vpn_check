# -*- coding: utf-8 -*-
"""core/database.py — MySQL 持久化层
====================================
遵循《AI 编程规范》第 6、7、12 条：

- 表名统一使用项目前缀 `vpn_check_`，主键自增，含 `created_at` / `updated_at`
- 所有字段带中文注释
- 节点按连接指纹唯一索引自动去重，测试记录按 (node_id, tested_at) 去重
- IP 归属地复用通用表 `ip_address_location`（跨项目共享）
- 数据库异常只降级不阻塞主流程
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import contextmanager
from typing import Dict, Iterator, List, Tuple

import pymysql

from core import config
from core.models import NodeResult, ProxyNode

logger = logging.getLogger("vpn_check.database")

PREFIX = config.DB_TABLE_PREFIX


@contextmanager
def connection() -> Iterator[pymysql.connections.Connection]:
    """获取数据库连接（自动关闭）"""
    conn = pymysql.connect(**config.DB_CONFIG)
    try:
        yield conn
    finally:
        conn.close()


def _execute_ignore(cursor, sql: str) -> None:
    """执行可选 DDL（旧表升级），失败仅记录调试日志"""
    try:
        cursor.execute(sql)
    except Exception as exc:  # noqa: BLE001
        logger.debug("可选 DDL 跳过: %s (%s)", sql.split("(")[0].strip(), exc)


def _ddl_statements() -> List[str]:
    p = PREFIX
    return [
        # 1. 节点元数据表：保存订阅解析出的节点与配额信息
        f"""
        CREATE TABLE IF NOT EXISTS `{p}_node` (
            `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '自增主键',
            `fingerprint` VARCHAR(64) NOT NULL COMMENT '节点连接指纹(SHA256)，用于去重',
            `name` VARCHAR(255) NOT NULL COMMENT '节点显示名称',
            `protocol` VARCHAR(32) NOT NULL COMMENT '协议类型(vless/vmess/trojan/shadowsocks/hysteria2/anytls)',
            `address` VARCHAR(255) NOT NULL COMMENT '服务器地址',
            `port` INT NOT NULL COMMENT '服务端口',
            `uuid` VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'UUID或密码',
            `sni` VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'TLS SNI',
            `security` VARCHAR(32) NOT NULL DEFAULT '' COMMENT '安全层(tls/reality/空)',
            `params_json` TEXT COMMENT '归一化后的传输与协议参数JSON',
            `sub_name` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '归属订阅名称',
            `sub_url` VARCHAR(512) NOT NULL DEFAULT '' COMMENT '归属订阅地址',
            `raw_link` TEXT COMMENT '原始分享链接',
            `remaining_traffic` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '机场节余流量快照',
            `expire_time` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '套餐到期时间',
            `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
            `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_fingerprint` (`fingerprint`),
            KEY `idx_addr_port` (`address`, `port`),
            KEY `idx_protocol` (`protocol`),
            KEY `idx_sub_name` (`sub_name`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='VPN节点元数据表';
        """,
        # 2. 单节点测试记录表：每次巡检写入一条，按节点+测试时间去重
        f"""
        CREATE TABLE IF NOT EXISTS `{p}_test_record` (
            `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '自增主键',
            `node_id` BIGINT UNSIGNED NOT NULL COMMENT '关联节点ID',
            `level` TINYINT NOT NULL COMMENT '连通分级:0代理通/1仅直连/2无网络',
            `latency_ms` FLOAT NOT NULL DEFAULT 0 COMMENT '主探针延迟(毫秒)',
            `kernel` VARCHAR(16) NOT NULL DEFAULT '' COMMENT '实际使用的内核(xray/sing-box)',
            `core_fallback` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否使用备用内核',
            `google_ok` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Google网页是否可达',
            `gemini_ok` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Gemini网页是否可用',
            `grok_ok` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Grok网页是否可达',
            `gemini_blocked` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Gemini是否被地区封锁',
            `gemini_status` VARCHAR(24) NOT NULL DEFAULT '' COMMENT 'Gemini页面判定状态',
            `gemini_studio_status` VARCHAR(24) NOT NULL DEFAULT '' COMMENT 'AI Studio判定状态',
            `gemini_api_ok` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'GenerativeLanguageAPI是否连通',
            `gemini_chat_ok` TINYINT NULL COMMENT 'Gemini提问:1成功/0失败/NULL未测',
            `gemini_reply` VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'Gemini回复摘要',
            `gemini_region` VARCHAR(16) NOT NULL DEFAULT '' COMMENT 'Google识别地区码(USA/JPN等)',
            `chat_ms` FLOAT NOT NULL DEFAULT 0 COMMENT '提问接口耗时(毫秒)',
            `outbound_ip` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '出海落地真实IP',
            `outbound_location` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '落地IP归属地',
            `fail_code` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '失败分类代码',
            `fail_reason` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '失败原因描述',
            `tested_at` DATETIME NOT NULL COMMENT '测试时间',
            `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
            `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_node_tested` (`node_id`, `tested_at`),
            KEY `idx_level` (`level`),
            KEY `idx_tested_at` (`tested_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='VPN节点测试记录表';
        """,
        # 3. 批次汇总表：每次巡检一行
        f"""
        CREATE TABLE IF NOT EXISTS `{p}_run_batch` (
            `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '自增主键',
            `batch_time` DATETIME NOT NULL COMMENT '批次执行时间',
            `total_nodes` INT NOT NULL DEFAULT 0 COMMENT '测试节点总数',
            `level0_count` INT NOT NULL DEFAULT 0 COMMENT '代理通节点数',
            `level1_count` INT NOT NULL DEFAULT 0 COMMENT '仅直连节点数',
            `level2_count` INT NOT NULL DEFAULT 0 COMMENT '无网络节点数',
            `gemini_available_count` INT NOT NULL DEFAULT 0 COMMENT 'Gemini可用节点数',
            `gemini_chat_ok_count` INT NOT NULL DEFAULT 0 COMMENT 'Gemini提问成功节点数',
            `elapsed_seconds` FLOAT NOT NULL DEFAULT 0 COMMENT '批次总耗时(秒)',
            `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
            `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_batch_time` (`batch_time`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='VPN测试批次汇总表';
        """,
        # 4. 通用 IP 归属地缓存表（规范第 12 条，跨项目共享）
        f"""
        CREATE TABLE IF NOT EXISTS `{config.IP_LOCATION_TABLE}` (
            `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '自增主键',
            `ip` VARCHAR(64) NOT NULL COMMENT 'IP地址',
            `country` VARCHAR(32) NOT NULL DEFAULT '' COMMENT '国家/地区代码',
            `region` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '省份/州',
            `city` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '城市',
            `location` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '组合归属地文本',
            `org` VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'ISP/ASN组织',
            `loc` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '经纬度',
            `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
            `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_ip` (`ip`),
            KEY `idx_country` (`country`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='IP地址归属地字典缓存表';
        """,
    ]


def _migration_statements() -> List[str]:
    p = PREFIX
    return [
        f"ALTER TABLE `{p}_node` ADD COLUMN `remaining_traffic` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '机场节余流量快照'",
        f"ALTER TABLE `{p}_node` ADD COLUMN `expire_time` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '套餐到期时间'",
        f"ALTER TABLE `{p}_test_record` ADD COLUMN `kernel` VARCHAR(16) NOT NULL DEFAULT '' COMMENT '实际使用的内核'",
        f"ALTER TABLE `{p}_test_record` ADD COLUMN `core_fallback` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否使用备用内核'",
        f"ALTER TABLE `{p}_test_record` ADD COLUMN `gemini_status` VARCHAR(24) NOT NULL DEFAULT '' COMMENT 'Gemini页面判定状态'",
        f"ALTER TABLE `{p}_test_record` ADD COLUMN `gemini_studio_status` VARCHAR(24) NOT NULL DEFAULT '' COMMENT 'AI Studio判定状态'",
        f"ALTER TABLE `{p}_test_record` ADD COLUMN `gemini_api_ok` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'GenerativeLanguageAPI是否连通'",
        f"ALTER TABLE `{p}_test_record` ADD COLUMN `chat_ms` FLOAT NOT NULL DEFAULT 0 COMMENT '提问接口耗时'",
        f"ALTER TABLE `{p}_test_record` ADD COLUMN `fail_code` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '失败分类代码'",
        f"ALTER TABLE `{p}_test_record` ADD COLUMN `outbound_ip` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '出海落地真实IP'",
        f"ALTER TABLE `{p}_test_record` MODIFY COLUMN `outbound_location` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '落地IP归属地'",
        f"ALTER TABLE `{p}_run_batch` ADD COLUMN `gemini_chat_ok_count` INT NOT NULL DEFAULT 0 COMMENT 'Gemini提问成功节点数'",
        f"ALTER TABLE `{p}_run_batch` ADD COLUMN `elapsed_seconds` FLOAT NOT NULL DEFAULT 0 COMMENT '批次总耗时'",
    ]


def _dedupe_and_add_indexes(cursor) -> None:
    """为历史表补齐去重约束：先清理同键重复行，再创建唯一索引"""
    p = PREFIX
    _execute_ignore(
        cursor,
        f"DELETE t1 FROM `{p}_test_record` t1 JOIN `{p}_test_record` t2 "
        "ON t1.`node_id` = t2.`node_id` AND t1.`tested_at` = t2.`tested_at` AND t1.`id` < t2.`id`",
    )
    _execute_ignore(
        cursor,
        f"ALTER TABLE `{p}_test_record` ADD UNIQUE KEY `uniq_node_tested` (`node_id`, `tested_at`)",
    )
    _execute_ignore(
        cursor,
        f"DELETE t1 FROM `{p}_run_batch` t1 JOIN `{p}_run_batch` t2 "
        "ON t1.`batch_time` = t2.`batch_time` AND t1.`id` < t2.`id`",
    )
    _execute_ignore(
        cursor,
        f"ALTER TABLE `{p}_run_batch` ADD UNIQUE KEY `uniq_batch_time` (`batch_time`)",
    )


def init_database() -> bool:
    """初始化数据表（幂等执行）"""
    try:
        with connection() as conn:
            with conn.cursor() as cursor:
                for statement in _ddl_statements():
                    cursor.execute(statement)
                for statement in _migration_statements():
                    _execute_ignore(cursor, statement)
                _dedupe_and_add_indexes(cursor)
            conn.commit()
        logger.info("数据库初始化成功，业务表前缀: %s_", PREFIX)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("数据库初始化失败，本次跳过持久化: %s", exc)
        return False


def _clip(value: object, limit: int) -> str:
    return str(value or "")[:limit]


def _chunks(items: List[object], size: int = 500):
    for index in range(0, len(items), size):
        yield items[index:index + size]


def _upsert_nodes(cursor, nodes: List[ProxyNode]) -> Dict[str, int]:
    """批量写入节点并返回 指纹 -> 主键ID 映射"""
    if not nodes:
        return {}
    sql = f"""
    INSERT INTO `{PREFIX}_node`
    (`fingerprint`, `name`, `protocol`, `address`, `port`, `uuid`, `sni`, `security`,
     `params_json`, `sub_name`, `sub_url`, `raw_link`, `remaining_traffic`, `expire_time`)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        `name`=VALUES(`name`),
        `protocol`=VALUES(`protocol`),
        `address`=VALUES(`address`),
        `port`=VALUES(`port`),
        `uuid`=VALUES(`uuid`),
        `sni`=VALUES(`sni`),
        `security`=VALUES(`security`),
        `params_json`=VALUES(`params_json`),
        `sub_name`=VALUES(`sub_name`),
        `sub_url`=VALUES(`sub_url`),
        `raw_link`=VALUES(`raw_link`),
        `remaining_traffic`=IF(VALUES(`remaining_traffic`) <> '', VALUES(`remaining_traffic`), `remaining_traffic`),
        `expire_time`=IF(VALUES(`expire_time`) <> '', VALUES(`expire_time`), `expire_time`),
        `updated_at`=NOW()
    """
    rows = [
        (
            node.fingerprint,
            _clip(node.name, 255),
            _clip(node.protocol, 32),
            _clip(node.address, 255),
            node.port,
            _clip(node.uuid, 255),
            _clip(node.sni, 255),
            _clip(node.security, 32),
            json.dumps(node.params, ensure_ascii=False),
            _clip(node.sub_name, 64),
            _clip(node.sub_url, 512),
            node.raw,
            _clip(node.remaining_traffic, 64),
            _clip(node.expire_time, 64),
        )
        for node in nodes
    ]
    cursor.executemany(sql, rows)

    fingerprint_to_id: Dict[str, int] = {}
    fingerprints = [node.fingerprint for node in nodes]
    for chunk in _chunks(fingerprints):
        placeholders = ",".join(["%s"] * len(chunk))
        cursor.execute(
            f"SELECT `fingerprint`, `id` FROM `{PREFIX}_node` WHERE `fingerprint` IN ({placeholders})",
            tuple(chunk),
        )
        for fingerprint, node_id in cursor.fetchall():
            fingerprint_to_id[fingerprint] = int(node_id)
    return fingerprint_to_id


def _record_row(node_id: int, result: NodeResult, tested_at: str) -> tuple:
    gemini = result.gemini
    return (
        node_id,
        result.level,
        result.latency_ms,
        _clip(result.core, 16),
        int(result.fallback_used),
        int(result.site_ok("Google")),
        int(result.site_ok("Gemini")),
        int(result.site_ok("Grok")),
        int(bool(gemini and gemini.region_blocked)),
        _clip(gemini.gemini_status if gemini else "", 24),
        _clip(gemini.studio_status if gemini else "", 24),
        int(bool(gemini and gemini.api_reach_ok)),
        None if not gemini or gemini.chat_ok is None else int(gemini.chat_ok),
        _clip(gemini.reply_snippet if gemini else "", 255),
        _clip(gemini.region_code if gemini else "", 16),
        gemini.chat_ms if gemini else 0.0,
        _clip(result.egress_ip, 64),
        _clip(result.egress_location, 255),
        _clip(result.fail_code, 64),
        _clip(result.fail_reason, 255),
        tested_at,
    )


def persist_test_batch(
    nodes: List[ProxyNode], results: List[NodeResult], elapsed_seconds: float = 0.0
) -> bool:
    """单事务写入节点、测试记录与批次汇总"""
    if not results:
        return False
    tested_at = time.strftime("%Y-%m-%d %H:%M:%S")
    record_sql = f"""
    INSERT INTO `{PREFIX}_test_record`
    (`node_id`, `level`, `latency_ms`, `kernel`, `core_fallback`, `google_ok`, `gemini_ok`,
     `grok_ok`, `gemini_blocked`, `gemini_status`, `gemini_studio_status`, `gemini_api_ok`,
     `gemini_chat_ok`, `gemini_reply`, `gemini_region`, `chat_ms`, `outbound_ip`,
     `outbound_location`, `fail_code`, `fail_reason`, `tested_at`)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        `level`=VALUES(`level`),
        `latency_ms`=VALUES(`latency_ms`),
        `kernel`=VALUES(`kernel`),
        `core_fallback`=VALUES(`core_fallback`),
        `google_ok`=VALUES(`google_ok`),
        `gemini_ok`=VALUES(`gemini_ok`),
        `grok_ok`=VALUES(`grok_ok`),
        `gemini_blocked`=VALUES(`gemini_blocked`),
        `gemini_status`=VALUES(`gemini_status`),
        `gemini_studio_status`=VALUES(`gemini_studio_status`),
        `gemini_api_ok`=VALUES(`gemini_api_ok`),
        `gemini_chat_ok`=VALUES(`gemini_chat_ok`),
        `gemini_reply`=VALUES(`gemini_reply`),
        `gemini_region`=VALUES(`gemini_region`),
        `chat_ms`=VALUES(`chat_ms`),
        `outbound_ip`=VALUES(`outbound_ip`),
        `outbound_location`=VALUES(`outbound_location`),
        `fail_code`=VALUES(`fail_code`),
        `fail_reason`=VALUES(`fail_reason`),
        `updated_at`=NOW()
    """
    batch_sql = f"""
    INSERT INTO `{PREFIX}_run_batch`
    (`batch_time`, `total_nodes`, `level0_count`, `level1_count`, `level2_count`,
     `gemini_available_count`, `gemini_chat_ok_count`, `elapsed_seconds`)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        `total_nodes`=VALUES(`total_nodes`),
        `level0_count`=VALUES(`level0_count`),
        `level1_count`=VALUES(`level1_count`),
        `level2_count`=VALUES(`level2_count`),
        `gemini_available_count`=VALUES(`gemini_available_count`),
        `gemini_chat_ok_count`=VALUES(`gemini_chat_ok_count`),
        `elapsed_seconds`=VALUES(`elapsed_seconds`),
        `updated_at`=NOW()
    """

    try:
        with connection() as conn:
            with conn.cursor() as cursor:
                fingerprint_to_id = _upsert_nodes(cursor, nodes)
                rows = [
                    _record_row(fingerprint_to_id[result.node.fingerprint], result, tested_at)
                    for result in results
                    if result.node.fingerprint in fingerprint_to_id
                ]
                if rows:
                    cursor.executemany(record_sql, rows)

                level_counts = {
                    level: sum(1 for r in results if r.level == level) for level in (0, 1, 2)
                }
                gemini_available = sum(1 for r in results if r.gemini_available)
                chat_ok = sum(1 for r in results if r.gemini and r.gemini.chat_ok is True)
                cursor.execute(
                    batch_sql,
                    (
                        tested_at,
                        len(results),
                        level_counts[0],
                        level_counts[1],
                        level_counts[2],
                        gemini_available,
                        chat_ok,
                        round(elapsed_seconds, 2),
                    ),
                )
            conn.commit()
        logger.info("测试数据持久化成功（%d 个节点）", len(results))
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("数据库持久化失败: %s", exc)
        return False


def lookup_subscription_quota(sub_name: str) -> Tuple[str, str]:
    """查询订阅最近一次可用的配额快照，返回 (节余流量, 到期时间)"""
    try:
        with connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    f"SELECT `remaining_traffic`, `expire_time` FROM `{PREFIX}_node` "
                    "WHERE `sub_name` = %s AND `remaining_traffic` <> '' "
                    "ORDER BY `updated_at` DESC LIMIT 1",
                    (sub_name,),
                )
                row = cursor.fetchone()
        if row:
            return str(row[0] or ""), str(row[1] or "")
    except Exception as exc:  # noqa: BLE001
        logger.debug("查询订阅配额失败 (%s): %s", sub_name, exc)
    return "", ""


def lookup_ip_location(ip: str) -> Dict[str, str]:
    """从通用缓存表查询 IP 归属地"""
    try:
        with connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    f"SELECT `ip`, `country`, `region`, `city`, `location`, `org`, `loc` "
                    f"FROM `{config.IP_LOCATION_TABLE}` WHERE `ip` = %s LIMIT 1",
                    (ip,),
                )
                row = cursor.fetchone()
        if row and row[4]:
            return {
                "ip": row[0],
                "country": row[1],
                "region": row[2],
                "city": row[3],
                "location": row[4],
                "org": row[5],
                "loc": row[6],
                "source": "db",
            }
    except Exception as exc:  # noqa: BLE001
        logger.debug("查询 IP 归属地缓存失败 (%s): %s", ip, exc)
    return {}


def upsert_ip_location(info: Dict[str, str]) -> bool:
    """写入 / 更新 IP 归属地缓存（按 ip 唯一键去重）"""
    if not info.get("ip"):
        return False
    sql = f"""
    INSERT INTO `{config.IP_LOCATION_TABLE}`
    (`ip`, `country`, `region`, `city`, `location`, `org`, `loc`)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        `country`=VALUES(`country`),
        `region`=VALUES(`region`),
        `city`=VALUES(`city`),
        `location`=VALUES(`location`),
        `org`=VALUES(`org`),
        `loc`=VALUES(`loc`),
        `updated_at`=NOW()
    """
    try:
        with connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql,
                    (
                        info.get("ip", ""),
                        _clip(info.get("country"), 32),
                        _clip(info.get("region"), 64),
                        _clip(info.get("city"), 64),
                        _clip(info.get("location"), 255),
                        _clip(info.get("org"), 255),
                        _clip(info.get("loc"), 64),
                    ),
                )
            conn.commit()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.debug("写入 IP 归属地缓存失败 (%s): %s", info.get("ip"), exc)
        return False
