# NodeTools Agent V1

NodeTools Agent V1 是一个可运行的 Linux/Go 原型，包含可插拔内核接口、Web 面板、登录鉴权、REST API、配置热重载、SQLite 初始化、节点管理、策略路由和日志系统。

## 运行

```bash
go mod tidy
go run ./cmd
```

本机 Go 没写入 `PATH` 时可以直接运行：

```bash
./run-agent.sh
```

启动后访问：

- Web 面板：http://127.0.0.1:8080
- 节点列表：`GET /api/nodes`
- 状态接口：`GET /api/status`
- 配置快照：`GET /api/config`
- 运行日志：`GET /api/logs`
- 内核检测：`GET /api/system/kernels`
- 服务状态：`GET /api/system/service`

默认登录：

- 用户名：`admin`
- 密码：`password123`

首次启动后，默认密码会迁移为 SQLite 中的 bcrypt 哈希；`config.yaml` 不再保存明文密码。

## 创建代理

```bash
curl -c /tmp/nodetools.cookie -X POST http://127.0.0.1:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password123"}'

curl -X POST http://127.0.0.1:8080/api/proxy/create \
  -b /tmp/nodetools.cookie \
  -H 'Content-Type: application/json' \
  -d '{"name":"Local-SOCKS","protocol":"socks","port":1080,"outbound":"HK"}'
```

## 创建转发

```bash
curl -X POST http://127.0.0.1:8080/api/forward/create \
  -b /tmp/nodetools.cookie \
  -H 'Content-Type: application/json' \
  -d '{"name":"Forward-SSH","protocol":"tcp","listen_port":2222,"target_host":"127.0.0.1","target_port":22}'
```

## Sing-box 替换点

默认使用占位内核，只生成 `kernel.generated.json`。如果本机已安装 Sing-box，可以在 `config.yaml` 中设置：

```yaml
kernel:
  type: "sing-box"
  executable: "/usr/local/bin/sing-box"
  config_path: "sing-box.generated.json"
```

Agent 会生成 sing-box JSON 配置，执行 `sing-box check -c`，然后用 `sing-box run -c` 启动子进程。面板上的“重载内核”会重新生成配置并重启内核进程。

## Mihomo 替换点

如果本机已安装 mihomo，可以在 `config.yaml` 中设置：

```yaml
kernel:
  type: "mihomo"
  executable: "/usr/local/bin/mihomo"
  config_path: "mihomo.generated.yaml"
```

Agent 会生成 mihomo YAML 配置，执行 `mihomo -t -f`，然后用 `mihomo -f` 启动子进程。

当前原型内置的协议映射：

- 本地入站会映射为 sing-box `mixed/socks/socks5/http/vless/vmess/trojan/anytls/shadowsocks` 或 mihomo `mixed-port`
- `socks/socks5/http/direct/vless/vmess/trojan/shadowsocks/ss/hysteria2/tuic/anytls/naive` 出站会生成 sing-box 节点
- `socks/socks5/http/vless/vmess/trojan/shadowsocks/ss/hysteria2/tuic/anytls` 出站会生成 mihomo 节点
- `socks/socks5/http` 入站和出站支持用户名、密码
- VLESS/VMess 需要 `uuid`
- Trojan 需要 `password`
- Shadowsocks/SS 需要 `method` 和 `password`
- TLS、Reality、SNI、跳过证书校验、WS/H2/gRPC path/host、TUIC 拥塞控制、Hysteria2 速率等字段已经进入节点模型
- VLESS 入站支持 Reality 服务端字段：private key、short id、server name、handshake server/port
- AnyTLS 入站支持密码和 TLS server name
- ShadowTLS、Naive 等复杂组合可以解析和保存，精确运行配置会继续细化

示例 VLESS 出站：

```yaml
outbounds:
  - name: HK
    protocol: vless
    address: hk.node.example.com
    port: 443
    uuid: bf000d23-0752-40b4-affe-68f7707a9661
    network: tcp
    tls: true
    server_name: hk.node.example.com
```

## Mihomo 订阅、代理组和规则

```yaml
mihomo:
  providers:
    - name: main
      type: http
      url: https://example.com/sub.yaml
      interval: 3600
      health_check_url: http://www.gstatic.com/generate_204
      health_check_lazy: true
  proxy_groups:
    - name: Auto
      type: url-test
      use:
        - main
      url: http://www.gstatic.com/generate_204
      interval: 300
  rules:
    - DOMAIN-SUFFIX,example.com,Auto
    - MATCH,Auto
```

面板支持输入订阅 URL 后预览解析结果，包括节点数、代理组数、规则数和 provider 数。接口：

```bash
curl -X POST http://127.0.0.1:8080/api/subscription/preview \
  -b /tmp/nodetools.cookie \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/sub.yaml"}'
```

订阅预览支持：

- Mihomo/Clash YAML 订阅
- Base64 编码的 URI 节点列表
- 常见 `ss://`、`vmess://`、`vless://`、`trojan://`、`hysteria2://` URI 行

## 导入节点

Web 面板的“导入节点”可以直接粘贴分享链接、订阅正文、Clash/Mihomo YAML 列表、sing-box JSON 配置或 v2rayN/X-UI 导出的节点。导入接口：

```bash
curl -X POST http://127.0.0.1:8080/api/outbounds/import \
  -b /tmp/nodetools.cookie \
  -H 'Content-Type: application/json' \
  -d '{"text":"vless://..."}'
```

当前解析支持：

- URI：`vless://`、`vmess://`、`ss://`、`trojan://`、`hysteria2://`、`hy2://`、`tuic://`、`anytls://`、`shadowtls://`、`naive+https://`、`naive+quic://`、`http2://`、`http3://`
- Base64：整段 base64 订阅、base64 authority、VMess JSON、v2rayN JSON
- YAML/JSON：Clash/Mihomo `proxies` 或代理列表、sing-box `outbounds`

## 内核抽象

内核统一通过 `core.Kernel` 接口接入：

- `placeholder`：默认占位内核，用于原型运行和配置生成
- `sing-box`：生成 JSON、校验配置、启动/重载/停止 sing-box 进程
- `mihomo`：生成 YAML、校验配置、启动/重载/停止 mihomo 进程

核心接口：

```go
type Kernel interface {
    Name() string
    GenerateConfig(RuntimeState) ([]byte, error)
    ValidateConfig(path string) error
    Start(path string) error
    Reload(path string) error
    Stop() error
    Status() KernelStatus
}
```

## 节点管理 API

- `GET /api/system/kernels`：检测 `sing-box` / `mihomo` 是否安装、路径和版本
- `GET /api/system/service`：查看 systemd 支持情况、服务模板和安装命令
- `POST /api/password/change`：修改当前管理员密码
- `POST /api/subscription/preview`：拉取并解析订阅预览
- `POST /api/subscriptions/update`：拉取已保存订阅并导入出站节点
- `PUT /api/inbounds`：新增或更新入站
- `PUT /api/outbounds`：新增或更新出站
- `POST /api/outbounds/import`：批量解析并导入出站节点
- `POST /api/nodes/{type}/{name}/test`：测试节点连通性和延迟
- `PATCH /api/nodes/{type}/{name}/enabled`：启用或停用节点
- `PUT /api/kernel/config`：保存内核类型、可执行文件路径和配置输出路径
- `PUT /api/mihomo/config`：保存 mihomo 订阅、代理组和规则
- `DELETE /api/nodes/{type}/{name}`：删除入站或出站
- `POST /api/kernel/reload`：重载当前内核
- `POST /api/kernel/stop`：停止当前内核
- `POST /api/proxy/create`：创建代理入站
- `POST /api/forward/create`：创建转发入站和目标出站

## Linux systemd 部署

模板文件位于 [deploy/nodetools-agent.service](/Users/apple/Documents/codexz/linuxproxy/deploy/nodetools-agent.service)。

推荐部署目录：

```bash
/opt/nodetools-agent
```

### 离线 zip 部署

推荐方式：先在本机生成完整离线包，再上传到 VPS。VPS 不需要访问 GitHub。

先把 Linux amd64 内核文件下载到项目的 `kernels/` 目录：

- sing-box：`https://github.com/SagerNet/sing-box/releases/download/v1.13.13/sing-box-1.13.13-linux-amd64.tar.gz`
- mihomo：`https://github.com/MetaCubeX/mihomo/releases/download/v1.19.27/mihomo-linux-amd64-v1.19.27.gz`

目录放好后应类似：

```bash
kernels/sing-box-1.13.13-linux-amd64.tar.gz
kernels/mihomo-linux-amd64-v1.19.27.gz
```

本机生成 Linux amd64 离线包。默认 VPS 面板端口是 `39080`，也可以自己指定：

```bash
DEPLOY_WEB_PORT=39080 GO_BIN=/Users/apple/Library/Go/sdk/go1.26.3/bin/go ARCH=amd64 ./deploy/package-offline.sh
```

默认 `Local-Mixed:1080` 会生成账号密码，避免 VPS 无防火墙时变成开放代理。也可以手动指定：

```bash
DEPLOY_PROXY_USER=nodetools DEPLOY_PROXY_PASS=强密码 DEPLOY_WEB_PORT=39080 GO_BIN=/Users/apple/Library/Go/sdk/go1.26.3/bin/go ARCH=amd64 ./deploy/package-offline.sh
```

输出文件：

```bash
dist/nodetools-agent-offline-linux-amd64.zip
```

上传 zip 到 VPS 后，在 VPS 上执行一条命令安装：

```bash
unzip nodetools-agent-offline-linux-amd64.zip && cd nodetools-agent-offline && sudo sh install-offline.sh
```

脚本会安装到：

- Agent：`/opt/nodetools-agent/nodetools-agent`
- systemd：`/etc/systemd/system/nodetools-agent.service`
- sing-box：`/usr/local/bin/sing-box`
- mihomo：`/usr/local/bin/mihomo`

离线包会自动从 `kernels/` 目录解析 `sing-box` / `mihomo` 发布文件。也可以显式指定 Linux 二进制或发布包路径：

```bash
SING_BOX_BIN=/path/to/sing-box MIHOMO_BIN=/path/to/mihomo GO_BIN=/Users/apple/Library/Go/sdk/go1.26.3/bin/go ARCH=amd64 ./deploy/package-offline.sh
```

这里的 `sing-box` / `mihomo` 必须是 Linux 对应架构的二进制文件，不能用 macOS 本机版。

默认必须同时带 `sing-box` 和 `mihomo` 才会生成 zip；缺内核时脚本会停止。临时调试纯 Agent 包才使用：

```bash
ALLOW_MISSING_KERNELS=1 GO_BIN=/Users/apple/Library/Go/sdk/go1.26.3/bin/go ARCH=amd64 ./deploy/package-offline.sh
```

安装脚本会检查服务是否真的启动，并访问 VPS 本机的 `127.0.0.1:39080/login`。如果外网仍打不开，需要在云厂商安全组放行 TCP `39080`，或你指定的 `DEPLOY_WEB_PORT`。

查看运行日志：

```bash
sudo journalctl -u nodetools-agent -f
```

### 联网安装内核

如果 VPS 可以访问 GitHub，也可以用联网脚本安装内核：

```bash
sudo sh deploy/install-kernels.sh
```

## 当前真实状态

- 在线状态来自 TCP 连通性探测，不再固定显示 online。
- 延迟来自节点测速接口。
- 停用节点不会进入生成的内核配置。
- 流量统计不再随机增长；未接入 sing-box/mihomo 统计 API 前只保留真实已有值。
- 订阅更新会拉取已保存 provider URL，并把解析到的节点导入出站节点池。

## 数据库

SQLite 数据库位置：`database/nodetools.db`

初始化表：

- `users`
- `nodes`
- `routing_rules`
- `traffic_stats`
- `config_history`

## 日志

日志同时输出到控制台和 `logs/agent.log`。
