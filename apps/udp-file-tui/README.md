# udp-file 使用说明

`udp-file` 是文件传输系统的客户端命令行程序，提供交互式 TUI 和适合脚本、Docker Compose、CI 的无交互模式。

它只负责配置、终端交互和状态展示；配对、可靠 UDP、网络路径选择、文件校验和文件写入由 `transfer-client` 及其底层 crate 完成。

## 构建与启动

在 workspace 根目录执行：

```bash
cargo build -p udp-file-tui
cargo run -p udp-file-tui -- --help
```

构建后的二进制位于：

```text
target/debug/udp-file
target/release/udp-file
```

客户端需要连接已经启动的 `transfer-server`。默认服务端地址是 `127.0.0.1:41000`。

## 交互式 TUI

不指定子命令时进入主页：

```bash
cargo run -p udp-file-tui -- --config client.toml
```

主页按键：

| 按键 | 操作 |
| --- | --- |
| `s` | 创建配对并发送文件或目录 |
| `r` | 输入配对码并接收文件 |
| `u` | 打开断点恢复页 |
| `q` / `Esc` | 退出 |

发送流程会在终端中输入一个文件或目录路径。需要发送多个路径时，建议使用 `send` 子命令。接收流程会依次询问配对码、下载目录，并要求确认 offer。

传输页面显示：

- 当前传输状态；
- durable offset 进度；
- 当前路径类型，例如 `Host`、`RoutedLan` 或 `Relay`；
- 路径选择和回退事件；
- 文件进度事件及累计字节数（以客户端实际发布的 durable checkpoint 为准）。

传输过程中按 `c`、`q` 或 `Esc` 会发送取消请求。

断点恢复页会读取下载目录下的 `.udp-transfer/sessions`，并显示 checkpoint、临时数据大小和 ticket 状态。使用上下键或 `j`/`k` 选择条目：

- 按 `Enter` 恢复未过期的 ticket；发送方需要重新输入原始源路径，接收方继续使用该断点状态所属的下载目录。
- 按 `d` 清理选中的断点状态；退出页面后还需要输入 `y` 确认。
- 按 `Esc` 或 `q` 返回主页。

传输启动后客户端会把恢复 ticket 原子保存到 `.udp-transfer/sessions/<transfer-id>/resume.resume`。发送方的 ticket 会在对端加入后保存；如果 ticket 缺失、损坏或已过期，页面只允许查看或清理该条目。

## 命令行模式

### 发送文件

创建配对并发送一个或多个文件、目录：

```bash
cargo run -p udp-file-tui -- \
  --config client.toml \
  --non-interactive \
  send ./report.pdf ./photos
```

创建配对后，程序会在标准输出显示配对码。接收方需要在配对有效期内使用该配对码加入。

覆盖本次配对 TTL：

```bash
udp-file --non-interactive send --pairing-ttl-seconds 300 ./report.pdf
```

`send` 也可以写成 `create`。

### 接收文件

无交互模式必须显式提供配对码：

```bash
cargo run -p udp-file-tui -- \
  --config client.toml \
  --non-interactive \
  receive \
  --code ABC23456 \
  --output ./downloads \
  --overwrite rename
```

无交互模式会自动接受收到的 offer。交互模式下可以省略 `--code`，程序会询问配对码；也可以使用 `--accept` 跳过 offer 确认：

```bash
udp-file receive --code ABC23456 --output ./downloads --accept
```

`receive` 也可以写成 `join`。

覆盖策略：

| 值 | 行为 |
| --- | --- |
| `ask` | 使用默认询问策略 |
| `no-replace` | 不覆盖已有文件 |
| `replace` | 使用替换策略 |
| `rename` | 为冲突文件生成带后缀的名称 |

### 检查配置

`doctor` 只解析配置并检查客户端参数，不连接服务端：

```bash
udp-file --config client.toml --non-interactive doctor
```

它会显示服务端地址、本地绑定地址、direct/relay 配置、下载目录和配对 TTL。

### 检查网络候选地址

`probe` 会连接服务端，并输出本地接口、路由和候选地址：

```bash
udp-file --config client.toml --non-interactive probe
```

### 查看和清理断点状态

列出下载目录中的未完成 session：

```bash
udp-file --config client.toml resume list
```

也可以指定目录：

```bash
udp-file resume list --root ./downloads
```

清理指定传输的临时状态：

```bash
udp-file resume clean \
  --root ./downloads \
  --transfer-id 00112233445566778899aabbccddeeff
```

`resume clean` 会删除该 transfer 在 `.udp-transfer/sessions` 和 `.udp-transfer/partial` 下的状态及临时数据。此操作不可恢复，请确认 transfer ID 后再执行。

## TOML 配置

示例 `client.toml`：

```toml
[server]
endpoint = "127.0.0.1:41000"
connect_timeout_ms = 5000
pairing_ttl_seconds = 600

[client]
bind = "0.0.0.0:0"
display_name = "my-laptop"

[network]
enable_direct = true
direct_only = false
probe_timeout_ms = 1500
probe_retries = 3
max_candidates = 16
keep_relay_warm = true

[transfer]
chunk_size = 1048576
max_parallel_files = 2
checkpoint_interval_bytes = 4194304
checkpoint_interval_seconds = 2
max_file_size = 1099511627776
max_total_size = 4398046511104
overwrite = "ask"

[storage]
download_root = "./downloads"
allow_symlink = false
sync_data = true
sync_all = true

[ui]
color = true
refresh_hz = 10
```

配置说明：

| 配置项 | 说明 |
| --- | --- |
| `server.endpoint` | 服务端控制地址 |
| `server.connect_timeout_ms` | 客户端连接服务端的超时时间 |
| `server.pairing_ttl_seconds` | 默认配对有效期 |
| `client.bind` | 本地 UDP 绑定地址；端口 `0` 表示由系统分配 |
| `client.display_name` | offer 中显示给对端的客户端名称 |
| `network.enable_direct` | 是否发送 direct candidate |
| `network.direct_only` | 只允许 direct，失败时不回退 relay |
| `network.probe_timeout_ms` | 网络探测单次超时时间 |
| `network.probe_retries` | 网络探测重试次数 |
| `network.max_candidates` | 最多发送的候选地址数量 |
| `transfer.chunk_size` | 单个数据块大小，最大为 1 MiB |
| `transfer.max_parallel_files` | 同时处理的文件数量上限 |
| `transfer.checkpoint_interval_bytes` | checkpoint 字节间隔配置 |
| `transfer.checkpoint_interval_seconds` | checkpoint 时间间隔配置 |
| `transfer.max_file_size` | 单文件大小上限 |
| `transfer.max_total_size` | 单次 manifest 总大小上限 |
| `transfer.overwrite` | 接收端默认覆盖策略 |
| `storage.download_root` | 默认接收目录 |
| `storage.allow_symlink` | 必须为 `false`；当前客户端拒绝启用符号链接 |
| `storage.sync_data` | 写入数据后是否同步文件数据 |
| `storage.sync_all` | 写入 checkpoint 时是否同步文件元数据 |
| `ui.color` | 是否使用终端颜色 |
| `ui.refresh_hz` | TUI 刷新频率 |

配置优先级为：

```text
命令行参数 > 环境变量 > TOML 文件 > 默认值
```

例如：

```bash
udp-file \
  --config client.toml \
  --server 192.0.2.10:41000 \
  --bind 0.0.0.0:42000 \
  --download-root ./incoming \
  --chunk-size 65536 \
  --max-parallel-files 1 \
  --non-interactive \
  receive --code ABC23456
```

## 环境变量

支持的环境变量包括：

```text
UDP_FILE_SERVER_ENDPOINT
UDP_FILE_SERVER_PAIRING_TTL_SECONDS
UDP_FILE_CLIENT_BIND
UDP_FILE_CLIENT_DISPLAY_NAME
UDP_FILE_NETWORK_ENABLE_DIRECT
UDP_FILE_NETWORK_DIRECT_ONLY
UDP_FILE_NETWORK_PROBE_TIMEOUT_MS
UDP_FILE_NETWORK_PROBE_RETRIES
UDP_FILE_NETWORK_MAX_CANDIDATES
UDP_FILE_TRANSFER_CHUNK_SIZE
UDP_FILE_TRANSFER_MAX_PARALLEL_FILES
UDP_FILE_TRANSFER_CHECKPOINT_INTERVAL_BYTES
UDP_FILE_TRANSFER_CHECKPOINT_INTERVAL_SECONDS
UDP_FILE_TRANSFER_MAX_FILE_SIZE
UDP_FILE_TRANSFER_MAX_TOTAL_SIZE
UDP_FILE_TRANSFER_OVERWRITE
UDP_FILE_STORAGE_DOWNLOAD_ROOT
UDP_FILE_STORAGE_SYNC_DATA
UDP_FILE_STORAGE_SYNC_ALL
UDP_FILE_UI_COLOR
UDP_FILE_UI_REFRESH_HZ
```

布尔值使用 `true` 或 `false`，数值字段使用十进制表示。例如：

```bash
UDP_FILE_SERVER_ENDPOINT=127.0.0.1:41000 \
UDP_FILE_STORAGE_DOWNLOAD_ROOT=/srv/downloads \
UDP_FILE_NETWORK_DIRECT_ONLY=true \
udp-file --non-interactive receive --code ABC23456
```

## 安全注意事项

- 配对码只显示在终端，不写入 TOML 配置和日志；不要把命令输出保存到公开日志中。
- session ticket、私钥和临时 token 不应写入配置文件。
- 当前配置拒绝 `storage.allow_symlink = true`，发送端也不允许发送符号链接。
- 接收文件会受到目标 root 和相对路径校验保护，不应通过修改 transfer ID 或路径绕过 root 限制。
- `--direct-only` 会禁用 relay fallback；公网或复杂 NAT 环境通常应保留默认的 relay fallback。

## 当前限制

- `network.keep_relay_warm` 当前仅用于配置展示，客户端始终保留 relay fallback。
- 当前 TUI 的交互式发送输入一个路径；发送多个路径请使用 `send` 子命令。
