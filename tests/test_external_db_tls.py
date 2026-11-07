"""公网数据库 TLS 的本地测试。不访问外部服务器。"""
from __future__ import annotations

import asyncio
import socket
import ssl
import stat
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common.core.config import BaseConfig
from common.db.initial_admin import resolve_initial_admin_password
from common.db.tls import (
    TLSConfigError,
    build_client_ssl_context,
    build_redis_pool,
    connect_redis_sync,
    connect_mysql_async,
    connect_mysql_sync,
    create_async_mysql_engine,
    create_sync_mysql_engine,
    redact_secrets,
    reset_mysql_resolution_pin,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _reset_resolution_pin():
    reset_mysql_resolution_pin()
    yield
    reset_mysql_resolution_pin()


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_pem(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _certificate_pair(tmp_path: Path, dns_names: list[str], ips: list[str]) -> tuple[Path, Path, Path]:
    import ipaddress

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("xianyu-test-ca"))
        .issuer_name(_name("xianyu-test-ca"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alt_names: list[x509.GeneralName] = [x509.DNSName(item) for item in dns_names]
    alt_names.extend(x509.IPAddress(ipaddress.ip_address(item)) for item in ips)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(_name(dns_names[0]))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.crt"
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    _write_pem(ca_path, ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(cert_path, server_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(
        key_path,
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    return ca_path, cert_path, key_path


def _server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def _mysql_greeting() -> bytes:
    import struct

    version = b"8.4.5-local-test\x00"
    salt1 = b"abcdefgh"
    salt2 = b"ijklmnopqr12"
    plugin = b"mysql_native_password\x00"
    capability = 0xFFFF | (0xFFFF << 16)
    payload = bytearray()
    payload.append(10)
    payload.extend(version)
    payload.extend(struct.pack("<I", 11))
    payload.extend(salt1)
    payload.append(0)
    payload.extend(struct.pack("<H", capability & 0xFFFF))
    payload.append(255)
    payload.extend(struct.pack("<H", 2))
    payload.extend(struct.pack("<H", (capability >> 16) & 0xFFFF))
    payload.append(21)
    payload.extend(b"\x00" * 10)
    payload.extend(salt2)
    payload.append(0)
    payload.extend(plugin)
    header = struct.pack("<I", len(payload))[:3] + bytes([0])
    return header + bytes(payload)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = sock.recv(size - len(chunks))
        if not piece:
            break
        chunks.extend(piece)
    return bytes(chunks)


def _serve_mysql_tls(context: ssl.SSLContext, events: list[str]) -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]

    def accept_loop() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            events.append("accepted")
            try:
                connection.settimeout(5)
                connection.sendall(_mysql_greeting())
                header = _recv_exact(connection, 4)
                if len(header) < 4:
                    events.append("short-header")
                    continue
                length = int.from_bytes(header[:3], "little")
                payload = _recv_exact(connection, length)
                events.append(f"pre-tls:{payload[:1].hex()}")
                tls = context.wrap_socket(connection, server_side=True)
                events.append("tls_ok")
                tls.close()
            except ssl.SSLError as exc:
                events.append(f"tls_fail:{type(exc).__name__}")
            except OSError as exc:
                events.append(f"os_fail:{type(exc).__name__}")
            finally:
                try:
                    connection.close()
                except OSError:
                    pass

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    return listener, port


def _serve_redis_tls(context: ssl.SSLContext, events: list[str]) -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]

    def handle(connection: socket.socket) -> None:
        events.append("accepted")
        try:
            connection.settimeout(5)
            tls = context.wrap_socket(connection, server_side=True)
            events.append("tls_ok")
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                if b"PING" in chunk:
                    tls.sendall(b"+PONG\r\n")
                    break
                tls.sendall(b"+OK\r\n")
            tls.close()
        except ssl.SSLError as exc:
            events.append(f"tls_fail:{type(exc).__name__}")
        except OSError as exc:
            events.append(f"os_fail:{type(exc).__name__}")
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def accept_loop() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(connection,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return listener, port


def _close_listener(listener: socket.socket) -> None:
    try:
        listener.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    listener.close()


def _mysql_settings(ca_path: Path, port: int, **overrides: object) -> BaseConfig:
    values = {
        "mysql_host": "127.0.0.1",
        "mysql_port": port,
        "mysql_user": "app_user",
        "mysql_password": "db-plain-secret",
        "mysql_database": "xianyu_data",
        "mysql_ssl_mode": "VERIFY_IDENTITY",
        "mysql_ssl_ca": str(ca_path),
        "db_tls_required": False,
        "redis_ssl": False,
        "db_connect_timeout": 3,
        "db_pool_size": 20,
        "redis_pool_size": 20,
    }
    values.update(overrides)
    return BaseConfig(**values)


def _redis_settings(ca_path: Path, port: int, **overrides: object) -> BaseConfig:
    values = {
        "redis_host": "127.0.0.1",
        "redis_port": port,
        "redis_password": "redis-plain-secret",
        "redis_db": 0,
        "redis_ssl": True,
        "redis_ssl_ca": str(ca_path),
        "redis_ssl_server_hostname": "redis.internal",
        "mysql_ssl_mode": "disable",
        "db_tls_required": False,
        "db_pool_size": 20,
        "redis_pool_size": 20,
    }
    values.update(overrides)
    return BaseConfig(**values)


def _error_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _has_ssl_error(exc: BaseException) -> bool:
    return any(isinstance(item, ssl.SSLError) for item in _error_chain(exc))


def _is_certificate_rejection(exc: BaseException) -> bool:
    text = " ".join(str(item).lower() for item in _error_chain(exc))
    markers = (
        "certificate verify failed",
        "certificate_verify_failed",
        "hostname mismatch",
        "doesn't match",
        "does not match",
    )
    return any(marker in text for marker in markers)


def test_plaintext_urls_omit_passwords() -> None:
    settings = BaseConfig(
        mysql_password="db-plain-secret",
        redis_password="redis-plain-secret",
        db_pool_size=20,
        redis_pool_size=20,
    )
    rendered = " ".join(
        [
            settings.database_url,
            settings.async_database_url,
            settings.redis_url,
            repr(settings),
        ]
    )
    assert "db-plain-secret" not in rendered
    assert "redis-plain-secret" not in rendered
    assert settings.redis_url.startswith("redis://")
    assert settings.database_url.startswith("mysql+pymysql://")
    engine = create_sync_mysql_engine(settings, echo=False)
    async_engine = create_async_mysql_engine(settings, echo=False, pool_size=1, max_overflow=0)
    try:
        assert "db-plain-secret" not in engine.url.render_as_string(hide_password=False)
        assert "db-plain-secret" not in async_engine.url.render_as_string(hide_password=False)
    finally:
        engine.dispose()
        asyncio.run(async_engine.dispose())


def test_small_pool_is_allowed() -> None:
    settings = BaseConfig(db_pool_size=20, redis_pool_size=20)
    assert settings.db_pool_size == 20
    assert settings.redis_pool_size == 20


def test_missing_invalid_and_weak_tls_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(TLSConfigError):
        BaseConfig(
            mysql_ssl_mode="VERIFY_IDENTITY",
            mysql_ssl_ca="",
            db_pool_size=20,
            redis_pool_size=20,
        )
    with pytest.raises(TLSConfigError):
        BaseConfig(
            db_tls_required=True,
            mysql_ssl_mode="disable",
            redis_ssl=True,
            mysql_ssl_ca=str(tmp_path / "missing.crt"),
            redis_ssl_ca=str(tmp_path / "missing.crt"),
            db_pool_size=20,
            redis_pool_size=20,
        )
    invalid = tmp_path / "invalid.crt"
    invalid.write_text("-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n", encoding="utf-8")
    with pytest.raises(TLSConfigError):
        build_client_ssl_context(str(invalid), "MYSQL_SSL_CA")
    private_key = tmp_path / "both.pem"
    private_key.write_text(
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    with pytest.raises(TLSConfigError, match="私钥"):
        build_client_ssl_context(str(private_key), "MYSQL_SSL_CA")
    with pytest.raises(TLSConfigError):
        BaseConfig(
            mysql_ssl_mode="REQUIRED",
            db_pool_size=20,
            redis_pool_size=20,
        )
    with pytest.raises(TLSConfigError):
        BaseConfig(
            mysql_ssl_mode="VERIFY_CA",
            mysql_ssl_ca=str(invalid),
            db_pool_size=20,
            redis_pool_size=20,
        )


def test_context_trusts_only_the_provided_ca(tmp_path: Path) -> None:
    ca_path, _, _ = _certificate_pair(tmp_path, ["db.internal"], ["127.0.0.1"])
    context = build_client_ssl_context(str(ca_path), "MYSQL_SSL_CA")
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.cert_store_stats()["x509_ca"] == 1
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_sync_and_async_mysql_contexts_verify_hostname(tmp_path: Path) -> None:
    ca_path, cert_path, key_path = _certificate_pair(tmp_path, ["db.internal"], ["127.0.0.1"])
    events: list[str] = []
    listener, port = _serve_mysql_tls(_server_context(cert_path, key_path), events)
    try:
        settings = _mysql_settings(ca_path, port)
        with pytest.raises(Exception) as caught:
            connect_mysql_sync(settings)
        assert "tls_ok" in events
        assert not _is_certificate_rejection(caught.value)
        assert events.count("accepted") == 1

        reset_mysql_resolution_pin()
        named = _mysql_settings(ca_path, port, mysql_ssl_server_hostname="db.internal")
        before = len(events)
        with pytest.raises(Exception) as named_error:
            connect_mysql_sync(named)
        assert "tls_ok" in events[before:]
        assert not _is_certificate_rejection(named_error.value)

        reset_mysql_resolution_pin()
        wrong = _mysql_settings(ca_path, port, mysql_ssl_server_hostname="wrong.example")
        accepted_before = events.count("accepted")
        with pytest.raises(Exception) as wrong_error:
            connect_mysql_sync(wrong)
        assert _is_certificate_rejection(wrong_error.value)
        assert events.count("accepted") == accepted_before + 1

        async def _async_good() -> None:
            reset_mysql_resolution_pin()
            good = _mysql_settings(ca_path, port)
            with pytest.raises(Exception) as async_error:
                await connect_mysql_async(good)
            assert not _is_certificate_rejection(async_error.value)

        asyncio.run(_async_good())
        assert events.count("tls_ok") >= 3
    finally:
        _close_listener(listener)


def test_sqlalchemy_engines_use_strict_mysql_tls(tmp_path: Path) -> None:
    ca_path, cert_path, key_path = _certificate_pair(tmp_path, ["db.internal"], ["127.0.0.1"])
    events: list[str] = []
    listener, port = _serve_mysql_tls(_server_context(cert_path, key_path), events)
    try:
        settings = _mysql_settings(ca_path, port)
        engine = create_sync_mysql_engine(settings, echo=False, pool_pre_ping=False)
        try:
            with pytest.raises(Exception) as sync_error:
                with engine.connect():
                    pass
            assert "db-plain-secret" not in str(sync_error.value)
            assert "tls_ok" in events
        finally:
            engine.dispose()

        async def _run_async() -> None:
            async_engine = create_async_mysql_engine(
                settings,
                echo=False,
                pool_pre_ping=False,
                pool_size=1,
                max_overflow=0,
            )
            try:
                with pytest.raises(Exception) as async_error:
                    async with async_engine.connect():
                        pass
                assert "db-plain-secret" not in str(async_error.value)
            finally:
                await async_engine.dispose()

        asyncio.run(_run_async())
    finally:
        _close_listener(listener)


def test_redis_tls_verifies_hostname_and_ca(tmp_path: Path) -> None:
    ca_path, cert_path, key_path = _certificate_pair(tmp_path, ["redis.internal"], ["127.0.0.1"])
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_ca, _, _ = _certificate_pair(other_dir, ["redis.internal"], ["127.0.0.1"])
    events: list[str] = []
    listener, port = _serve_redis_tls(_server_context(cert_path, key_path), events)
    try:
        settings = _redis_settings(ca_path, port)
        pool = build_redis_pool(settings)
        connection = pool.connection_class(**pool.connection_kwargs)
        arguments = connection._connection_arguments()
        assert arguments["server_hostname"] == "redis.internal"
        assert arguments["host"] == "127.0.0.1"
        assert arguments["ssl"].verify_mode == ssl.CERT_REQUIRED
        assert arguments["ssl"].check_hostname is True
        assert "password" not in arguments
        assert settings.redis_url.startswith("rediss://")
        assert "redis-plain-secret" not in settings.redis_url

        async def _ping(active_settings: BaseConfig) -> None:
            import redis.asyncio as redis_asyncio

            active_pool = build_redis_pool(active_settings)
            client = redis_asyncio.Redis(connection_pool=active_pool)
            try:
                assert await client.ping() is True
            finally:
                await client.aclose(close_connection_pool=True)

        sync_client = connect_redis_sync(settings, socket_connect_timeout=3)
        try:
            assert sync_client.ping() is True
        finally:
            sync_client.close()

        asyncio.run(_ping(settings))
        assert "tls_ok" in events

        wrong = _redis_settings(ca_path, port, redis_ssl_server_hostname="wrong.example")
        with pytest.raises(Exception) as wrong_error:
            asyncio.run(_ping(wrong))
        assert _has_ssl_error(wrong_error.value)

        foreign = _redis_settings(other_ca, port)
        with pytest.raises(Exception) as foreign_error:
            asyncio.run(_ping(foreign))
        assert _has_ssl_error(foreign_error.value)
        assert "redis-plain-secret" not in redact_secrets(str(foreign_error.value), "redis-plain-secret")
    finally:
        _close_listener(listener)


def test_initial_admin_password_is_not_logged(tmp_path: Path) -> None:
    from loguru import logger

    messages: list[str] = []
    sink = logger.add(lambda message: messages.append(str(message)), format="{message}")
    try:
        settings = BaseConfig(
            admin_initial_password="",
            admin_initial_password_file=str(tmp_path / "admin-initial-password.txt"),
            mysql_password="db-plain-secret",
            db_pool_size=20,
            redis_pool_size=20,
        )
        password, path = resolve_initial_admin_password(settings)
        assert path is not None
        file_path = Path(path)
        assert file_path.read_text(encoding="utf-8").strip() == password
        assert stat.S_IMODE(file_path.stat().st_mode) == 0o600
        output = "\n".join(messages)
        assert password not in output
        assert "db-plain-secret" not in output

        provided = BaseConfig(
            admin_initial_password="one-time-local-secret",
            admin_initial_password_file=str(tmp_path / "unused.txt"),
            db_pool_size=20,
            redis_pool_size=20,
        )
        value, file_path_or_none = resolve_initial_admin_password(provided)
        assert value == "one-time-local-secret"
        assert file_path_or_none is None
        assert "one-time-local-secret" not in "\n".join(messages)
    finally:
        logger.remove(sink)


def test_compose_external_db_is_fail_closed_and_local_only() -> None:
    import yaml

    compose_path = ROOT / "docker-compose.external-db.yml"
    text = compose_path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    assert set(document["services"]) == {"frontend", "backend-web", "websocket", "scheduler"}
    assert "mysql" not in document["services"]
    assert "redis" not in document["services"]
    assert "xianyu@2026" not in text
    for name, service in document["services"].items():
        assert service["platform"] == "linux/arm64"
        assert service["volumes"][0]["target"] == "/etc/xianyu/ca/ca.crt"
        assert service["volumes"][0]["read_only"] is True
        published = " ".join(service["ports"])
        assert published.startswith("127.0.0.1:")
        environment = service["environment"]
        assert environment["DB_TLS_REQUIRED"] == "true"
        assert environment["MYSQL_SSL_MODE"] == "VERIFY_IDENTITY"
        assert environment["REDIS_SSL"] == "true"
        assert environment["MYSQL_SSL_CA"] == "/etc/xianyu/ca/ca.crt"
        depends = service.get("depends_on") or {}
        assert "mysql" not in depends
        assert "redis" not in depends
        if name == "frontend":
            assert "MYSQL_PASSWORD" not in environment
            assert "REDIS_PASSWORD" not in environment
            assert "9000" in published
        else:
            assert "MYSQL_PASSWORD" in environment
            assert ":?" in environment["MYSQL_PASSWORD"]
            assert service["user"] == "10001:10001"
    assert document["services"]["websocket"]["environment"]["AUTO_START_WEBSOCKET"] == "false"
    assert "ADMIN_INITIAL_PASSWORD" in document["services"]["backend-web"]["environment"]
    assert "ADMIN_INITIAL_PASSWORD" not in document["services"]["websocket"]["environment"]
    assert "ADMIN_INITIAL_PASSWORD" not in document["services"]["scheduler"]["environment"]
    assert "ADMIN_INITIAL_PASSWORD" not in document["services"]["frontend"]["environment"]
    assert document["services"]["websocket"]["depends_on"]["backend-web"]["condition"] == "service_healthy"
    assert "backend-web" in document["services"]["scheduler"]["depends_on"]
    assert "websocket" in document["services"]["scheduler"]["depends_on"]
    assert "browser_data" in text


def test_connection_call_sites_and_admin_password_path() -> None:
    session = (ROOT / "common/db/session.py").read_text(encoding="utf-8")
    compat = (ROOT / "common/db/compat.py").read_text(encoding="utf-8")
    password_login = (ROOT / "websocket/app/api/routes/password_login.py").read_text(encoding="utf-8")
    weighted = (ROOT / "common/services/captcha/weighted_scheduler.py").read_text(encoding="utf-8")
    concurrency = (ROOT / "common/services/captcha/concurrency.py").read_text(encoding="utf-8")
    redis_client = (ROOT / "common/db/redis_client.py").read_text(encoding="utf-8")
    checker = (ROOT / "launcher/db_checker.py").read_text(encoding="utf-8")
    init_database = (ROOT / "common/db/init_database.py").read_text(encoding="utf-8")
    login = (ROOT / "frontend/src/pages/auth/Login.tsx").read_text(encoding="utf-8")
    assert "create_async_mysql_engine" in session
    assert "create_async_mysql_engine" in compat
    assert "create_async_mysql_engine" in password_login
    assert "create_sync_mysql_engine" in weighted
    assert "create_sync_mysql_engine" in concurrency
    assert "build_redis_pool" in redis_client
    assert "from_url" not in redis_client
    assert "connect_mysql_sync" in checker
    assert "connect_redis_sync" in checker
    assert 'get_password_hash("admin123")' not in init_database
    assert "admin123" not in login
    assert "security.admin_password_change_required" in (
        ROOT / "backend-web/app/api/routes/users.py"
    ).read_text(encoding="utf-8")
