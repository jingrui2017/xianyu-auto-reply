"""
首次管理员口令。

不在代码中放置可用口令。环境变量提供一次性口令，或在本地文件生成随机口令。
日志只记录文件路径。
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from loguru import logger


def initial_admin_password_path(settings: Any) -> Path:
    """本地口令文件路径。显式配置优先，否则放在备份目录或 data 目录。"""
    configured = (getattr(settings, "admin_initial_password_file", "") or "").strip()
    if configured:
        return Path(configured)
    backup = Path(getattr(settings, "backup_dir", "backups") or "backups")
    if backup.is_absolute():
        return backup / "admin-initial-password.txt"
    return Path("data") / "admin-initial-password.txt"


def _write_private_file(path: Path, password: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, f"{password}\n".encode("utf-8"))
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def resolve_initial_admin_password(settings: Any) -> tuple[str, str | None]:
    """
    返回 (口令, 文件路径或 None)。

    文件路径只在本次生成随机口令时返回。调用方负责哈希后保存，不得记录口令本身。
    """
    configured = getattr(settings, "admin_initial_password", "") or ""
    if configured:
        logger.info("初始管理员口令取自 ADMIN_INITIAL_PASSWORD，请登录后立即修改并清除该变量")
        return configured, None

    password = secrets.token_urlsafe(24)
    path = initial_admin_password_path(settings)
    _write_private_file(path, password)
    logger.info(
        "初始管理员口令已写入本地文件，请在本机读取后立即修改密码并删除该文件: "
        f"{path}"
    )
    return password, str(path)
