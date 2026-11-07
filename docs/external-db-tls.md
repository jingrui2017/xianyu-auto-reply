# 公网 MySQL / Redis TLS

这份配置只启动 frontend、backend-web、websocket、scheduler。云端 MySQL 8.4 和 Redis 7.4 由数据库侧单独提供，compose 不创建数据库容器，也不连接本机名为 `mysql` 或 `redis` 的容器。

不要执行仓库里的 `deploy.sh`、`deploy_remote.sh`、`update.sh`，也不要执行 `curl | sh`。那些脚本会拉取远程部署逻辑。正式启动由本机核对环境后再做。

## 架构

目标机器是 Apple M4，10 核、16GiB，Docker 使用 linux/arm64。`docker-compose.external-db.yml` 把四个服务的 `platform` 固定为 `linux/arm64`，避免悄悄走 amd64 模拟。

四个服务都用仓库里的 Dockerfile：

- Docker Hub 清单里，`python:3.11-slim`、`node:18-alpine`、`nginx:alpine` 都包含 `linux/arm64`。
- 本机构建的 `python:3.11-slim` 实际是 Debian 13，不是 Debian 12。Playwright 与 Patchright 对 `debian13-arm64` 提供 linux arm64 Chromium；这次 ARM64 浏览器构建已经通过，因此不更换基础镜像。
- backend-web 和 websocket 在镜像内安装 Playwright 与 Patchright 的 Chromium。scheduler 安装 Playwright Chromium。
- 不在 macOS 宿主安装 Google Chrome，也不把宿主 Chrome 挂进容器。

因此 compose 固定 `platform: linux/arm64`，不使用 amd64 模拟。如果以后某个浏览器包不再提供 arm64，构建会直接失败；那时应停在该服务，而不是改成模拟运行。

Python 服务以 uid/gid `10001` 运行。前端镜像沿用官方 Nginx：主进程需要绑定容器内 80 端口，worker 由镜像自己降权。前端不打开 MySQL 或 Redis 连接，因此不向它注入数据库口令；它仍然挂载同一份只读 CA，并带上 TLS 模式和地址，方便核对四个容器的配置是否一致。

如果以后发现某个浏览器构建没有 linux/arm64，停止在该服务上构建，不要改成 `--platform linux/amd64` 碰运气。可选做法是先只启动已经确认有 arm64 浏览器包的服务，或等对应浏览器发布 arm64 包后再构建。

## 证书

CA 文件放在本机，例如 `/Users/jerry/.config/xianyu-infra/ca.crt`。容器只读挂载这一个文件到 `/etc/xianyu/ca/ca.crt`，不要挂载 CA 私钥，也不要挂载整个配置目录。

证书文件需要让容器用户可读，建议 `0644`。Docker 在源文件不存在时可能把挂载点做成目录，所以要先放好真正的证书文件再启动。

`MYSQL_HOST` / `REDIS_HOST` 填写公网 IP 或证书上的域名。客户端使用该地址建立 TCP，并用它校验证书。证书的 SAN 必须包含这个 IP 或域名。

如果 TCP 地址是 IP，而证书签给另一个域名，再设置：

```text
MYSQL_SSL_SERVER_HOSTNAME=证书上的域名
REDIS_SSL_SERVER_HOSTNAME=证书上的域名
```

这时 TCP 仍连接到 `MYSQL_HOST` / `REDIS_HOST`，TLS 校验使用上面的名字。名字不匹配、CA 不匹配或 CA 缺失都会失败，不会改成明文，也不会关闭校验。

不支持 `REQUIRED`、`VERIFY_CA`、`PREFERRED` 这类会跳过主机名或不强制 TLS 的模式。只接受默认的 `disable`，以及公网使用的 `VERIFY_IDENTITY`。

## 变量

公网 compose 固定：

```text
DB_TLS_REQUIRED=true
MYSQL_SSL_MODE=VERIFY_IDENTITY
MYSQL_SSL_CA=/etc/xianyu/ca/ca.crt
REDIS_SSL=true
REDIS_SSL_CA=/etc/xianyu/ca/ca.crt
```

口令只通过环境变量进入 backend-web、websocket、scheduler 的驱动参数。诊断用的数据库 URL 和 Redis URL 不带口令，日志会去掉口令。示例见 `.env.external-db.example`，复制为 `.env.external-db` 后在本机填写，不要提交。

未设置这些 TLS 变量时，原有 `docker-compose.yml` 和本地明文连接保持不变。

16GiB 机器上的外部 profile 把连接池上限降到几十，避免四个进程按代码默认值向云数据库申请上千连接。连接仍是按需创建。云数据库的 `max_connections` 必须大于三个服务的池上限与溢出之和。

## 空库

在云数据库上自行创建空库和账号，并要求 TLS。应用不会替你连接去执行这些语句：

```sql
CREATE DATABASE xianyu_data CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

给应用账号授予该库权限，并把允许访问的来源限制到部署机的公网 IP。不要使用 root 作为应用账号。Redis 开启 `requireTLS` 和访问口令。应用启动后会自己建表；启动前不要往库里写入闲鱼账号。

## 不接入闲鱼账号的启动

```bash
cp .env.external-db.example .env.external-db
# 在本机编辑占位值。不要把文件发回仓库。
docker compose --env-file .env.external-db -f docker-compose.external-db.yml up -d --build
```

这个 profile 里：

- `AUTO_START_WEBSOCKET=false`，不会因为库里后来出现账号就自动连接闲鱼。
- `AUTO_START_CRAWL_JOBS=false`。
- 远程广告和公告合并是关闭的。
- 浏览器状态卷 `browser_data` 是空的。不要在界面添加闲鱼账号，也不要导入 Cookie。

访问入口是 `http://127.0.0.1:9000`。backend-web `8089`、websocket `8090`、scheduler `8091` 只绑定宿主的 `127.0.0.1`，不发布到局域网。容器内部仍监听 `0.0.0.0`，否则 Docker 网络里的服务名无法互访。

三个 Python 服务的启动顺序仍是 backend-web，然后 websocket，然后 scheduler。frontend 等待 backend-web 的 HTTP 健康检查。健康检查通过只说明 HTTP 已监听；数据库断开时接口会报告 database disconnected，而不会改走明文。

## 管理员口令

新库不再使用写死的初始口令。

- 设置 `ADMIN_INITIAL_PASSWORD` 时，只把它传给 backend-web，只在首次创建 `admin` 时使用，日志不打印它的值。登录后调用 `POST /api/v1/users/change-password`，然后从环境变量里删掉它。
- 留空时，随机口令写入 `backup-files` 卷里的 `/app/backups/admin-initial-password.txt`，权限 `0600`。日志只给路径。在本机读取、修改密码、删除文件。不要把口令发出来。

修改密码后，`security.admin_password_change_required` 会被清掉。旧库若仍是历史弱口令，账号管理仍会要求先改密码。

## 依赖

同步 MySQL 使用已有的 PyMySQL，异步使用 asyncmy，Redis 使用已固定的 redis-py 6.2。TLS 使用 Python `ssl`，只把指定 CA 放进 `SSLContext`，`CERT_REQUIRED` 和主机名校验保持开启。这次没有新增运行时依赖，也没有改自动发货或业务 API。
