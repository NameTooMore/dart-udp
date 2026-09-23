#!/usr/bin/env bash
set -Eeuo pipefail

role=${1:-}
artifact_dir=${ARTIFACT_DIR:-/artifacts}
resolve_endpoint() {
    local endpoint=${1:-transfer-server:41000}
    local host=${endpoint%:*}
    local port=${endpoint##*:}
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$host" == *:* ]]; then
        printf '%s\n' "$endpoint"
        return 0
    fi
    local ip
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')
    if [[ -z "$ip" ]]; then
        ip=$(getent hosts "$host" 2>/dev/null | awk '{print $1; exit}')
    fi
    if [[ -z "$ip" && "$host" == "server" ]]; then
        ip=$(getent ahostsv4 "transfer-server" 2>/dev/null | awk '{print $1; exit}')
        if [[ -z "$ip" ]]; then
            ip=$(getent hosts "transfer-server" 2>/dev/null | awk '{print $1; exit}')
        fi
    fi
    if [[ -n "$ip" ]]; then
        printf '%s:%s\n' "$ip" "$port"
        return 0
    fi
    printf '%s\n' "$endpoint"
}

server_endpoint=${SERVER_ENDPOINT:-transfer-server:41000}

log_status() {
    local name=$1
    local status=$2
    printf '%s\n' "$status" >"$artifact_dir/${name}.status"
}

apply_netem() {
    local specification=${NETEM_SPEC:-}
    [[ -n "$specification" ]] || return 0

    # 场景网络可能对应不同的 ethN，所有非回环接口都使用相同的可复现参数。
    for interface in /sys/class/net/eth*; do
        [[ -e "$interface" ]] || continue
        interface=${interface##*/}
        tc qdisc replace dev "$interface" root netem $specification
    done
}

configure_routes() {
    if [[ -n "${ROUTE_DESTINATION:-}" && -n "${ROUTE_GATEWAY:-}" ]]; then
        ip route replace "$ROUTE_DESTINATION" via "$ROUTE_GATEWAY"
    fi
}

configure_router() {
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    if [[ -n "${ROUTER_UPLINK:-}" ]]; then
        iptables -t nat -A POSTROUTING -o "$ROUTER_UPLINK" -j MASQUERADE
    fi
    exec sleep infinity
}

configure_symmetric_proxy() {
    # 该代理只提供可观测的 UDP 映射面，真正的端口映射策略由场景脚本控制。
    if [[ -n "${PROXY_LISTEN:-}" && -n "${PROXY_TARGET:-}" ]]; then
        exec socat "UDP4-LISTEN:${PROXY_LISTEN},reuseaddr,fork" "UDP4:${PROXY_TARGET}"
    fi
    exec sleep infinity
}

get_bind_addr() {
    local endpoint=${1:-$server_endpoint}
    local host=${endpoint%:*}
    local ip=""
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$(ip route get "$host" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
        if [[ -z "$ip" ]]; then
            local prefix=${host%.*}
            ip=$(ip -4 addr show 2>/dev/null | grep -F "inet $prefix." | awk '{print $2}' | cut -d/ -f1 | head -n 1)
        fi
    fi
    if [[ -n "$ip" ]]; then
        printf '%s:0\n' "$ip"
    else
        printf '0.0.0.0:0\n'
    fi
}

wait_for_server() {
    local max_retries=60
    local count=0
    local endpoint=${SERVER_ENDPOINT:-transfer-server:41000}
    while true; do
        server_endpoint=$(resolve_endpoint "$endpoint")
        if [[ "$server_endpoint" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ || "$server_endpoint" =~ ^\[.*\]:[0-9]+$ ]]; then
            local bind_addr
            bind_addr=$(get_bind_addr "$server_endpoint")
            local probe_out=""
            if probe_out=$(udp-file --non-interactive --bind "$bind_addr" --server "$server_endpoint" probe 2>&1); then
                printf '[%s] 成功连接服务端 %s (bind %s)\n' "${role:-client}" "$server_endpoint" "$bind_addr" >&2
                break
            else
                if (( count % 5 == 0 )); then
                    printf '[%s] 探测服务端 %s 失败 (bind %s): %s\n' "${role:-client}" "$server_endpoint" "$bind_addr" "$probe_out" >&2
                fi
            fi
        fi
        count=$((count + 1))
        if (( count >= max_retries )); then
            printf '等待服务端 %s 超时 (解析结果: %s)\n' "$endpoint" "$server_endpoint" >&2
            return 1
        fi
        sleep 0.5
    done
}

run_sender() {
    mkdir -p "$artifact_dir/input/transfer-fixture" "$artifact_dir/output"
    if [[ ! -f "$artifact_dir/input/transfer-fixture/empty.bin" ]]; then
        : >"$artifact_dir/input/transfer-fixture/empty.bin"
        printf '%s\n' 'Compose transfer fixture' \
            >"$artifact_dir/input/transfer-fixture/message.txt"
        dd if=/dev/zero of="$artifact_dir/input/transfer-fixture/payload.bin" \
            bs=64K count=16 status=none
    fi
    apply_netem
    configure_routes
    wait_for_server

    local bind_addr
    bind_addr=$(get_bind_addr "$server_endpoint")

    local -a options=(
        --server "$server_endpoint"
        --bind "$bind_addr"
        --download-root "$artifact_dir/output"
        --non-interactive
        --json
    )
    if [[ "${DISABLE_DIRECT:-0}" == 1 ]]; then
        options+=(--no-direct)
    fi

    local code_file="$artifact_dir/pairing-code"
    (
        for (( i=1; i<=480; i++ )); do
            if [[ -s "$artifact_dir/sender.log" ]]; then
                code=$(sed -n -E 's/.*配对码：([0-9a-zA-Z]+).*/\1/p' "$artifact_dir/sender.log" | head -n 1)
                if [[ -n "$code" ]]; then
                    printf '%s' "$code" >"$code_file"
                    printf '[sender] 已成功提取配对码: %s\n' "$code" >&2
                    break
                fi
            fi
            sleep 0.25
        done
    ) &
    local pairing_extractor_pid=$!

    printf '[sender] server_endpoint=%s bind_addr=%s\n' "$server_endpoint" "$bind_addr" >"$artifact_dir/sender.log"
    ip addr show >>"$artifact_dir/sender.log"
    ip route show >>"$artifact_dir/sender.log"
    options+=(--log-level trace)

    printf '[sender] 开始执行 udp-file send...\n' >&2
    set +e
    udp-file "${options[@]}" send "$artifact_dir/input/transfer-fixture" \
        >>"$artifact_dir/sender.log" 2>&1
    local status=$?
    set -e
    printf '[sender] udp-file send 结束，退出状态码: %d\n' "$status" >&2
    wait "$pairing_extractor_pid" 2>/dev/null || true
    log_status sender "$status"
}

run_receiver() {
    mkdir -p "$artifact_dir/output"
    apply_netem
    configure_routes
    wait_for_server
    local code_file="$artifact_dir/pairing-code"
    printf '[receiver] 等待发送方发布配对码...\n' >&2
    for (( i=1; i<=480; i++ )); do
        if [[ -s "$code_file" ]]; then
            break
        fi
        if (( i % 20 == 0 )); then
            printf '[receiver] 仍等待配对码中... (已等待 %d 秒)\n' "$((i / 4))" >&2
        fi
        sleep 0.25
    done
    if [[ ! -s "$code_file" ]]; then
        printf '%s\n' 'sender did not publish a pairing code' >&2
        log_status receiver 124
        return 0
    fi

    local bind_addr
    bind_addr=$(get_bind_addr "$server_endpoint")

    local code
    code=$(<"$code_file")
    local -a options=(
        --server "$server_endpoint"
        --bind "$bind_addr"
        --download-root "$artifact_dir/output"
        --non-interactive
        --json
    )
    if [[ "${DISABLE_DIRECT:-0}" == 1 ]]; then
        options+=(--no-direct)
    fi

    printf '[receiver] server_endpoint=%s bind_addr=%s\n' "$server_endpoint" "$bind_addr" >"$artifact_dir/receiver.log"
    ip addr show >>"$artifact_dir/receiver.log"
    ip route show >>"$artifact_dir/receiver.log"
    options+=(--log-level trace)

    set +e
    udp-file "${options[@]}" receive --code "$code" --output "$artifact_dir/output" \
        --overwrite replace >>"$artifact_dir/receiver.log" 2>&1
    local status=$?
    set -e
    log_status receiver "$status"
}

case "$role" in
    server)
        declare -a server_options=(--bind "${SERVER_BIND:-0.0.0.0:41000}" --log-level debug)
        if [[ -n "${SERVER_RELAY_MAX_BYTES_PER_SESSION:-}" ]]; then
            server_options+=(
                --relay-max-bytes-per-session "$SERVER_RELAY_MAX_BYTES_PER_SESSION"
            )
        fi
        if [[ -n "${SERVER_RELAY_MAX_BYTES_TOTAL:-}" ]]; then
            server_options+=(--relay-max-bytes-total "$SERVER_RELAY_MAX_BYTES_TOTAL")
        fi
        exec udp-file-server "${server_options[@]}"
        ;;
    sender)
        run_sender
        ;;
    receiver)
        run_receiver
        ;;
    router)
        configure_router
        ;;
    symmetric-proxy)
        configure_symmetric_proxy
        ;;
    runner)
        exec /usr/local/bin/transfer-scenario-runner
        ;;
    *)
        printf '未知网络测试角色：%s\n' "$role" >&2
        exit 64
        ;;
esac
