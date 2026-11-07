"""
MySQL 与 Redis 的可信 CA TLS。

默认不启用 TLS，现有内网明文部署保持原样。一旦开启校验，或公网配置要求 TLS，
连接只使用调用方提供的 CA，并校验证书与主机名。缺 CA、无效 CA、私钥文件、
不受支持的校验模式都会在建连前失败，不会退回明文，也不会关闭证书校验。
"""
from __future__ import annotations

import inspect
import re
import socket
import ssl
from pathlib import Path
from typing import Any, Callable

from common.db.redis_pool import HealthyRedisConnection, HealthyRedisConnectionPool

_URL_USERINFO = re.compile(r"://[^\s/@]*:[^\s/@]*@")
_PRIVATE_KEY_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
)
_DISABLE_MODES = {"", "disable", "off", "false", "0"}
_VERIFY_MODES = {"verify_identity", "verify_full"}
_MAX_CA_BYTES = 1024 * 1024

_pin_state: tuple[str, str] | None = None
_original_getaddrinfo: Callable[..., Any] | None = None


class TLSConfigError(RuntimeError):
    """TLS 配置不完整或不安全，调用方不得继续连接。"""


def redact_secrets(text: str, *secrets: str) -> str:
    """去掉异常和诊断文本中的连接口令，避免写入日志。"""
    redacted = _URL_USERINFO.sub("://***@", text)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def normalize_host(host: str) -> str:
    """去掉 URL 里的 IPv6 方括号，驱动和证书校验使用裸主机名或 IP。"""
    value = (host or "").strip()
    if len(value) >= 2 and value[0] == "[" and value[-1] == "]":
        return value[1:-1]
    return value


def normalize_mysql_ssl_mode(value: str) -> str:
    """只接受关闭或严格身份校验，其他模式直接拒绝。"""
    mode = (value or "").strip().lower().replace("-", "_")
    if mode in _DISABLE_MODES:
        return "disable"
    if mode in _VERIFY_MODES:
        return "verify_identity"
    raise TLSConfigError(
        f"MYSQL_SSL_MODE={value!r} 不是受支持的严格模式，已拒绝连接"
    )


def mysql_tls_active(settings: Any) -> bool:
    """MySQL 是否必须走严格 TLS。公网配置不允许退回明文。"""
    mode = normalize_mysql_ssl_mode(getattr(settings, "mysql_ssl_mode", "disable"))
    if getattr(settings, "db_tls_required", False) and mode != "verify_identity":
        raise TLSConfigError(
            "DB_TLS_REQUIRED 要求 MYSQL_SSL_MODE=VERIFY_IDENTITY，已拒绝明文连接"
        )
    return mode == "verify_identity"


def redis_tls_active(settings: Any) -> bool:
    """Redis 是否必须走严格 TLS。"""
    enabled = bool(getattr(settings, "redis_ssl", False))
    if getattr(settings, "db_tls_required", False) and not enabled:
        raise TLSConfigError(
            "DB_TLS_REQUIRED 要求 REDIS_SSL=true，已拒绝明文连接"
        )
    return enabled


def mysql_tls_identity(settings: Any) -> str:
    """证书必须匹配的主机名或 IP。未单独指定时使用拨号地址。"""
    override = normalize_host(getattr(settings, "mysql_ssl_server_hostname", ""))
    return override or normalize_host(getattr(settings, "mysql_host", ""))


def redis_tls_identity(settings: Any) -> str:
    """Redis 证书必须匹配的主机名或 IP。"""
    override = normalize_host(getattr(settings, "redis_ssl_server_hostname", ""))
    return override or normalize_host(getattr(settings, "redis_host", ""))


def _read_ca_text(path: Path, label: str) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise TLSConfigError(f"{label} 无法读取") from exc
    if len(data) > _MAX_CA_BYTES:
        raise TLSConfigError(f"{label} 超出 CA 证书文件大小限制")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise TLSConfigError(f"{label} 不是 PEM 证书") from exc
    upper = text.upper()
    if any(marker in upper for marker in _PRIVATE_KEY_MARKERS):
        raise TLSConfigError(f"{label} 含有私钥，连接只接受 CA 证书")
    if "BEGIN CERTIFICATE" not in upper:
        raise TLSConfigError(f"{label} 不含 CA 证书")
    return text


def validate_ca_file(ca_path: str, label: str) -> Path:
    """确认 CA 是可读的证书文件，不接受目录、空路径或私钥。"""
    raw = (ca_path or "").strip()
    if not raw:
        raise TLSConfigError(f"{label} 未设置，已拒绝连接")
    path = Path(raw)
    if not path.is_file():
        raise TLSConfigError(f"{label} 不是可读的 CA 证书文件")
    _read_ca_text(path, label)
    return path


def build_client_ssl_context(ca_path: str, label: str) -> ssl.SSLContext:
    """构造只信任指定 CA、且必须校验主机名的客户端上下文。"""
    path = validate_ca_file(ca_path, label)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cafile=str(path))
    except (ssl.SSLError, OSError) as exc:
        raise TLSConfigError(f"{label} 不是有效的 CA 证书") from exc
    if context.cert_store_stats().get("x509_ca", 0) < 1:
        raise TLSConfigError(f"{label} 未载入任何 CA 证书")
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise TLSConfigError(f"{label} 证书校验未保持开启，已拒绝连接")
    return context


def enforce_tls_policy(settings: Any) -> None:
    """在配置对象创建时失败关闭。明文默认配置不会访问 CA 文件。"""
    mysql_on = mysql_tls_active(settings)
    redis_on = redis_tls_active(settings)
    if mysql_on:
        if not str(getattr(settings, "sync_driver", "")).startswith("mysql+pymysql"):
            raise TLSConfigError("MySQL TLS 仅支持 mysql+pymysql 同步驱动")
        if not str(getattr(settings, "async_driver", "")).startswith("mysql+asyncmy"):
            raise TLSConfigError("MySQL TLS 仅支持 mysql+asyncmy 异步驱动")
        if not mysql_tls_identity(settings):
            raise TLSConfigError("MySQL TLS 主机名为空，已拒绝连接")
        build_client_ssl_context(getattr(settings, "mysql_ssl_ca", ""), "MYSQL_SSL_CA")
    if redis_on:
        if not redis_tls_identity(settings):
            raise TLSConfigError("Redis TLS 主机名为空，已拒绝连接")
        build_client_ssl_context(getattr(settings, "redis_ssl_ca", ""), "REDIS_SSL_CA")


def reset_mysql_resolution_pin() -> None:
    """测试隔离用：撤掉进程内的 MySQL 拨号固定。"""
    global _pin_state, _original_getaddrinfo
    if _original_getaddrinfo is not None:
        socket.getaddrinfo = _original_getaddrinfo
    _original_getaddrinfo = None
    _pin_state = None


def ensure_mysql_resolution_pin(identity: str, dial_host: str) -> None:
    """
    拨号地址和证书身份不同时，只把证书身份解析到配置的地址。

    驱动仍用证书身份做 SNI 和主机名校验。解析结果被固定到 MYSQL_HOST，
    不关闭校验，也不影响其他主机名。
    """
    global _pin_state, _original_getaddrinfo
    identity = normalize_host(identity)
    dial_host = normalize_host(dial_host)
    if not identity or identity == dial_host:
        return
    if _pin_state == (identity, dial_host):
        return
    if _pin_state is not None:
        raise TLSConfigError("MySQL TLS 拨号固定已绑定到其他地址，已拒绝连接")
    original = socket.getaddrinfo

    def pinned(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        if host == identity:
            host = dial_host
        return original(host, port, *args, **kwargs)

    socket.getaddrinfo = pinned
    _original_getaddrinfo = original
    _pin_state = (identity, dial_host)


def _mysql_timeouts(
    settings: Any,
    read_timeout: int | None,
    write_timeout: int | None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "connect_timeout": int(settings.db_connect_timeout),
    }
    if read_timeout is not None:
        kwargs["read_timeout"] = int(read_timeout)
    if write_timeout is not None:
        kwargs["write_timeout"] = int(write_timeout)
    return kwargs


def connect_mysql_sync(
    settings: Any,
    *,
    charset: str | None = None,
    read_timeout: int | None = None,
    write_timeout: int | None = None,
) -> Any:
    """建立同步 PyMySQL 连接。口令只进入驱动参数，不进入 URL。"""
    import pymysql

    enforce_tls_policy(settings)
    dial_host = normalize_host(settings.mysql_host)
    identity = mysql_tls_identity(settings) if mysql_tls_active(settings) else dial_host
    if mysql_tls_active(settings):
        ensure_mysql_resolution_pin(identity, dial_host)
    kwargs: dict[str, Any] = {
        "host": identity,
        "port": int(settings.mysql_port),
        "user": settings.mysql_user,
        "password": settings.mysql_password,
        "database": settings.mysql_database,
        **_mysql_timeouts(settings, read_timeout, write_timeout),
    }
    if charset:
        kwargs["charset"] = charset
    if mysql_tls_active(settings):
        kwargs["ssl"] = build_client_ssl_context(settings.mysql_ssl_ca, "MYSQL_SSL_CA")
    return pymysql.connect(**kwargs)


async def connect_mysql_async(
    settings: Any,
    *,
    read_timeout: int | None = None,
    write_timeout: int | None = None,
) -> Any:
    """建立异步 asyncmy 连接。口令只进入驱动参数。"""
    import asyncmy

    enforce_tls_policy(settings)
    dial_host = normalize_host(settings.mysql_host)
    identity = mysql_tls_identity(settings) if mysql_tls_active(settings) else dial_host
    if mysql_tls_active(settings):
        ensure_mysql_resolution_pin(identity, dial_host)
    kwargs: dict[str, Any] = {
        "host": identity,
        "port": int(settings.mysql_port),
        "user": settings.mysql_user,
        "password": settings.mysql_password,
        "database": settings.mysql_database,
        "connect_timeout": int(settings.db_connect_timeout),
    }
    if read_timeout is not None:
        kwargs["read_timeout"] = int(read_timeout)
    try:
        accepted = inspect.signature(asyncmy.connect).parameters
    except (TypeError, ValueError):
        accepted = {}
    if write_timeout is not None and "write_timeout" in accepted:
        kwargs["write_timeout"] = int(write_timeout)
    if mysql_tls_active(settings):
        kwargs["ssl"] = build_client_ssl_context(settings.mysql_ssl_ca, "MYSQL_SSL_CA")
    return await asyncmy.connect(**kwargs)


def create_sync_mysql_engine(settings: Any, **engine_kwargs: Any) -> Any:
    """同步引擎。creator 持有口令和 SSLContext，URL 不包含口令。"""
    from sqlalchemy import create_engine

    read_timeout = engine_kwargs.pop("read_timeout", None)
    write_timeout = engine_kwargs.pop("write_timeout", None)
    charset = engine_kwargs.pop("charset", None)

    def creator() -> Any:
        return connect_mysql_sync(
            settings,
            charset=charset,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
        )

    return create_engine(settings.database_url, creator=creator, **engine_kwargs)


def create_async_mysql_engine(settings: Any, **engine_kwargs: Any) -> Any:
    """异步引擎。async_creator 持有口令和 SSLContext，URL 不包含口令。"""
    from sqlalchemy.ext.asyncio import create_async_engine

    read_timeout = engine_kwargs.pop("read_timeout", None)
    write_timeout = engine_kwargs.pop("write_timeout", None)

    async def creator() -> Any:
        return await connect_mysql_async(
            settings,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
        )

    return create_async_engine(
        settings.async_database_url,
        async_creator=creator,
        **engine_kwargs,
    )


def _redis_keepalive_options(settings: Any) -> dict[int, int] | None:
    if not settings.redis_socket_keepalive:
        return None
    options: dict[int, int] = {}
    if hasattr(socket, "TCP_KEEPIDLE"):
        options[socket.TCP_KEEPIDLE] = settings.redis_socket_keepalive_idle
    if hasattr(socket, "TCP_KEEPINTVL"):
        options[socket.TCP_KEEPINTVL] = settings.redis_socket_keepalive_interval
    if hasattr(socket, "TCP_KEEPCNT"):
        options[socket.TCP_KEEPCNT] = settings.redis_socket_keepalive_count
    return options or None


class HealthyStrictRedisConnection(HealthyRedisConnection):
    """异步 Redis 连接：健康检查保持不变，TLS 只信任指定 CA 并校验主机名。"""

    def __init__(
        self,
        *,
        strict_ssl_context: ssl.SSLContext,
        tls_server_hostname: str,
        **kwargs: Any,
    ) -> None:
        if (
            strict_ssl_context.verify_mode != ssl.CERT_REQUIRED
            or not strict_ssl_context.check_hostname
        ):
            raise TLSConfigError("Redis TLS 证书校验未保持开启，已拒绝连接")
        self._strict_ssl_context = strict_ssl_context
        self._tls_server_hostname = normalize_host(tls_server_hostname)
        if not self._tls_server_hostname:
            raise TLSConfigError("Redis TLS 主机名为空，已拒绝连接")
        for insecure in ("ssl_cert_reqs", "ssl_check_hostname", "ssl_ca_certs", "ssl_ca_data"):
            kwargs.pop(insecure, None)
        super().__init__(**kwargs)

    def _connection_arguments(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "ssl": self._strict_ssl_context,
            "server_hostname": self._tls_server_hostname,
        }


def _strict_sync_redis_class() -> type:
    import redis.connection as sync_connection

    class _Connection(sync_connection.SSLConnection):
        def __init__(
            self,
            *,
            strict_ssl_context: ssl.SSLContext,
            tls_server_hostname: str,
            **kwargs: Any,
        ) -> None:
            if (
                strict_ssl_context.verify_mode != ssl.CERT_REQUIRED
                or not strict_ssl_context.check_hostname
            ):
                raise TLSConfigError("Redis TLS 证书校验未保持开启，已拒绝连接")
            self._strict_ssl_context = strict_ssl_context
            self._tls_server_hostname = normalize_host(tls_server_hostname)
            kwargs["ssl_cert_reqs"] = "required"
            kwargs["ssl_check_hostname"] = True
            super().__init__(**kwargs)

        def _wrap_socket_with_ssl(self, sock: socket.socket) -> ssl.SSLSocket:
            return self._strict_ssl_context.wrap_socket(
                sock,
                server_hostname=self._tls_server_hostname or self.host,
            )

    return _Connection


def redis_connection_kwargs(settings: Any, *, socket_connect_timeout: float | None = None) -> dict[str, Any]:
    """构造不含 URL 的 Redis 连接参数。TLS 开启时强制 CA 与主机名校验。"""
    from redis.backoff import ExponentialWithJitterBackoff
    from redis.retry import Retry

    timeout = (
        float(socket_connect_timeout)
        if socket_connect_timeout is not None
        else float(settings.redis_socket_connect_timeout)
    )
    kwargs: dict[str, Any] = {
        "host": normalize_host(settings.redis_host),
        "port": int(settings.redis_port),
        "password": settings.redis_password or None,
        "db": int(settings.redis_db),
        "decode_responses": True,
        "socket_timeout": float(settings.redis_socket_timeout),
        "socket_connect_timeout": timeout,
        "socket_keepalive": bool(settings.redis_socket_keepalive),
        "socket_keepalive_options": _redis_keepalive_options(settings),
        "health_check_interval": int(settings.redis_health_check_interval),
        "retry": Retry(ExponentialWithJitterBackoff(base=1, cap=10), retries=3),
        "protocol": int(settings.redis_protocol),
    }
    if not redis_tls_active(settings):
        return kwargs
    kwargs["connection_class"] = _strict_sync_redis_class()
    kwargs["strict_ssl_context"] = build_client_ssl_context(
        settings.redis_ssl_ca, "REDIS_SSL_CA"
    )
    kwargs["tls_server_hostname"] = redis_tls_identity(settings)
    kwargs["ssl_cert_reqs"] = "required"
    kwargs["ssl_check_hostname"] = True
    kwargs["ssl_ca_certs"] = str(validate_ca_file(settings.redis_ssl_ca, "REDIS_SSL_CA"))
    return kwargs


def build_redis_pool(settings: Any) -> HealthyRedisConnectionPool:
    """异步健康连接池。TLS 使用独立连接类，不把口令放进 URL。"""
    kwargs = redis_connection_kwargs(settings)
    kwargs.pop("connection_class", None)
    pool_kwargs: dict[str, Any] = {
        "max_connections": int(settings.redis_pool_size),
        "connection_class": HealthyRedisConnection,
    }
    if redis_tls_active(settings):
        pool_kwargs["connection_class"] = HealthyStrictRedisConnection
        kwargs["strict_ssl_context"] = build_client_ssl_context(
            settings.redis_ssl_ca, "REDIS_SSL_CA"
        )
        kwargs["tls_server_hostname"] = redis_tls_identity(settings)
        kwargs["ssl_cert_reqs"] = "required"
        kwargs["ssl_check_hostname"] = True
        kwargs["ssl_ca_certs"] = str(validate_ca_file(settings.redis_ssl_ca, "REDIS_SSL_CA"))
    return HealthyRedisConnectionPool(**pool_kwargs, **kwargs)


def connect_redis_sync(settings: Any, *, socket_connect_timeout: float | None = None) -> Any:
    """同步 Redis 连接，供启动前检查使用。"""
    import redis

    kwargs = redis_connection_kwargs(settings, socket_connect_timeout=socket_connect_timeout)
    connection_class = kwargs.pop("connection_class", redis.Connection)
    pool = redis.ConnectionPool(connection_class=connection_class, **kwargs)
    return redis.Redis(connection_pool=pool)


def safe_endpoint(settings: Any, kind: str) -> str:
    """可写入日志的端点描述，不包含口令。"""
    if kind == "mysql":
        tls = "verify_identity" if mysql_tls_active(settings) else "disable"
        identity = mysql_tls_identity(settings) if tls != "disable" else "-"
        return (
            f"mysql host={normalize_host(settings.mysql_host)} "
            f"port={settings.mysql_port} database={settings.mysql_database} "
            f"tls={tls} identity={identity}"
        )
    tls = "verify_identity" if redis_tls_active(settings) else "disable"
    return (
        f"redis host={normalize_host(settings.redis_host)} "
        f"port={settings.redis_port} db={settings.redis_db} tls={tls}"
    )
