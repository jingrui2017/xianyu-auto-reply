"""
数据库和Redis连接验证模块

功能：
1. 验证MySQL连接是否正常
2. 验证Redis连接是否正常
3. 供GUI界面调用，验证用户填写的连接信息
"""
import os
import socket


def _redact(message: str, *secrets: str) -> str:
    redacted = message
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def _env_requests_tls() -> bool:
    required = os.environ.get("DB_TLS_REQUIRED", "").strip().lower() in {"1", "true", "yes", "on"}
    redis_ssl = os.environ.get("REDIS_SSL", "").strip().lower() in {"1", "true", "yes", "on"}
    mysql_mode = os.environ.get("MYSQL_SSL_MODE", "disable").strip().lower().replace("-", "_")
    return required or redis_ssl or mysql_mode not in {"", "disable", "off", "false", "0"}


def _connection_settings():
    from common.core.config import get_settings

    return get_settings()


def check_mysql_connection(host: str, port: int, user: str, password: str, database: str) -> dict:
    """
    检查MySQL数据库连接
    
    先通过socket检测端口是否可达，再尝试用pymysql建立真实连接。
    TLS 开启时校验 CA 和主机名，失败后不退回明文。
    
    Args:
        host: MySQL主机地址
        port: MySQL端口
        user: 用户名
        password: 密码
        database: 数据库名
    Returns:
        字典包含:
        - success: bool 连接是否成功
        - message: str 结果说明
    """
    # 先检查端口可达性
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
    except socket.timeout:
        return {"success": False, "message": f"连接超时：无法连接到 {host}:{port}"}
    except socket.error as e:
        return {"success": False, "message": f"网络错误：{host}:{port} 不可达 - {e}"}

    use_tls = False
    settings = None
    try:
        from common.db.tls import TLSConfigError, mysql_tls_active

        settings = _connection_settings().model_copy(update={
            "mysql_host": host,
            "mysql_port": int(port),
            "mysql_user": user,
            "mysql_password": password,
            "mysql_database": database,
            "db_connect_timeout": 10,
        })
        use_tls = mysql_tls_active(settings)
    except Exception as exc:
        tls_error = exc.__class__.__name__ == "TLSConfigError" or _env_requests_tls()
        if tls_error:
            return {"success": False, "message": _redact(f"MySQL TLS配置拒绝连接: {exc}", password)}

    if use_tls:
        try:
            from common.db.tls import connect_mysql_sync

            conn = connect_mysql_sync(settings, charset="utf8mb4")
            conn.ping(reconnect=False)
            conn.close()
            return {"success": True, "message": "MySQL TLS连接成功"}
        except Exception as exc:
            return {"success": False, "message": _redact(f"MySQL TLS连接失败: {exc}", password)}

    try:
        import pymysql
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            connect_timeout=10,
            charset="utf8mb4",
        )
        conn.ping(reconnect=False)
        conn.close()
        return {"success": True, "message": "MySQL连接成功"}
    except ImportError:
        return {"success": False, "message": "缺少pymysql依赖，请检查安装"}
    except Exception as e:
        return {"success": False, "message": _redact(f"MySQL连接失败: {e}", password)}


def check_redis_connection(host: str, port: int, password: str, db: int) -> dict:
    """
    检查Redis连接
    
    尝试建立Redis连接并执行PING命令。
    TLS 开启时校验 CA 和主机名，失败后不退回明文。
    
    Args:
        host: Redis主机地址
        port: Redis端口
        password: Redis密码（可为空字符串）
        db: Redis数据库编号
    Returns:
        字典包含:
        - success: bool 连接是否成功
        - message: str 结果说明
    """
    # 先检查端口可达性
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
    except socket.timeout:
        return {"success": False, "message": f"连接超时：无法连接到 {host}:{port}"}
    except socket.error as e:
        return {"success": False, "message": f"网络错误：{host}:{port} 不可达 - {e}"}

    use_tls = False
    settings = None
    try:
        from common.db.tls import redis_tls_active

        settings = _connection_settings().model_copy(update={
            "redis_host": host,
            "redis_port": int(port),
            "redis_password": password,
            "redis_db": int(db),
        })
        use_tls = redis_tls_active(settings)
    except Exception as exc:
        tls_error = exc.__class__.__name__ == "TLSConfigError" or _env_requests_tls()
        if tls_error:
            return {"success": False, "message": _redact(f"Redis TLS配置拒绝连接: {exc}", password)}

    if use_tls:
        try:
            from common.db.tls import connect_redis_sync

            client = connect_redis_sync(settings, socket_connect_timeout=10)
            client.ping()
            client.close()
            return {"success": True, "message": "Redis TLS连接成功"}
        except Exception as exc:
            return {"success": False, "message": _redact(f"Redis TLS连接失败: {exc}", password)}

    try:
        import redis
        r = redis.Redis(
            host=host,
            port=port,
            password=password if password else None,
            db=db,
            socket_connect_timeout=10,
            decode_responses=True,
        )
        r.ping()
        r.close()
        return {"success": True, "message": "Redis连接成功"}
    except ImportError:
        return {"success": False, "message": "缺少redis依赖，请检查安装"}
    except Exception as e:
        return {"success": False, "message": _redact(f"Redis连接失败: {e}", password)}
