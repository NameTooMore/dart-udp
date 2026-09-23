# udp-file-server

`udp-file-server` 负责启动文件传输服务端，提供配对、控制信令和中继能力。配对与中继协议由 `transfer-server` 实现，本应用只负责配置、日志和进程生命周期。

## 启动

```bash
cargo run -p udp-file-server -- --config server.toml
```

默认监听 `0.0.0.0:41000`。服务端收到 Ctrl-C 或 Unix SIGTERM 后会记录指标并优雅退出。

## 配置

```toml
[server]
bind = "0.0.0.0:41000"
pairing_ttl_seconds = 600
max_pairings = 1024
max_join_attempts = 8
max_pending_messages = 1024

[relay]
max_bytes_per_session = 4294967296
max_bytes_total = 0
max_streams_per_session = 2
buffer_size = 65536
```

配置优先级为：命令行参数 > 环境变量 > TOML > 默认值。可使用 `doctor` 检查配置而不绑定端口：

```bash
cargo run -p udp-file-server -- --config server.toml doctor
```

主要环境变量以 `UDP_FILE_SERVER_` 开头，例如 `UDP_FILE_SERVER_BIND`、`UDP_FILE_SERVER_MAX_PAIRINGS` 和 `UDP_FILE_SERVER_RELAY_BUFFER_SIZE`。中继字节配额为 0 时，单会话配额表示禁用中继，总配额表示不限制总量。
