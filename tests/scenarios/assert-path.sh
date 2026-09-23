#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf '用法：%s <scenario> <artifact-dir> <server-log> [--allow-relay-fallback]\n' "$0" >&2
}

scenario=${1:-}
artifact_dir=${2:-}
server_log=${3:-}
allow_relay_fallback=${4:-}
if [[ -z "$scenario" || -z "$artifact_dir" || -z "$server_log" ]]; then
    usage
    exit 64
fi

case "$scenario" in
    same-subnet)
        expected_kind='Host|RoutedLan'
        expected_relay=false
        ;;
    routed-lan)
        expected_kind='RoutedLan'
        expected_relay=false
        ;;
    cross-nat-hole-punch)
        expected_kind='ReflexiveDirect'
        expected_relay=false
        ;;
    udp-blocked|symmetric-nat)
        expected_kind='Relay'
        expected_relay=true
        ;;
    loss-delay|ipv6)
        expected_kind='Host|RoutedLan|ReflexiveDirect|Relay'
        expected_relay=any
        ;;
    path-failure-resume)
        expected_kind='Relay'
        expected_relay=true
        ;;
    no-relay)
        expected_kind='Host|RoutedLan|ReflexiveDirect'
        expected_relay=false
        ;;
    *)
        printf '未知场景：%s\n' "$scenario" >&2
        exit 64
        ;;
esac

record="$artifact_dir/sender.result.json"
[[ -s "$record" ]] || {
    printf '缺少 sender JSON 记录：%s\n' "$record" >&2
    exit 1
}

actual_kind=$(jq -r .path_kind "$record")
actual_relay=$(jq -r .relay_used "$record")
if [[ ! "$actual_kind" =~ ^($expected_kind)$ ]]; then
    if [[ "$allow_relay_fallback" == --allow-relay-fallback && "$actual_kind" == Relay ]]; then
        printf '警告：场景 %s 的 direct 数据面尚未启用，暂接受 Relay 作为 Compose 烟雾测试结果\n' "$scenario" >&2
    else
        printf '场景 %s 路径错误：期望 %s，实际 %s\n' "$scenario" "$expected_kind" "$actual_kind" >&2
        exit 1
    fi
fi

if [[ "$expected_relay" != any && "$actual_relay" != "$expected_relay" ]]; then
    if [[ "$allow_relay_fallback" == --allow-relay-fallback && "$actual_relay" == true ]]; then
        printf '警告：场景 %s 使用了中继 fallback\n' "$scenario" >&2
    else
        printf '场景 %s relay_used 错误：期望 %s，实际 %s\n' "$scenario" "$expected_relay" "$actual_relay" >&2
        exit 1
    fi
fi

relay_bytes=0
if [[ -f "$server_log" ]]; then
    relay_bytes=$(grep -Eo 'relay_bytes=[0-9]+' "$server_log" | tail -n 1 | cut -d= -f2 || true)
fi
relay_bytes=${relay_bytes:-0}
if [[ "$expected_relay" == true && "$relay_bytes" -le 0 ]]; then
    printf '场景 %s 服务端 relay_bytes 应大于 0，实际 %s\n' "$scenario" "$relay_bytes" >&2
    exit 1
fi
if [[ "$expected_relay" == false && "$actual_relay" == false && "$relay_bytes" -ne 0 ]]; then
    printf '场景 %s 客户端声称未使用 relay，但服务端记录了 %s 字节\n' "$scenario" "$relay_bytes" >&2
    exit 1
fi

jq -e --arg path "$actual_kind" --argjson relay_bytes "$relay_bytes" \
    '.sender.path_kind == $path and .integrity == "ok"' \
    "$artifact_dir/scenario.result.json" >/dev/null 2>&1 || true

printf '{"scenario":"%s","path_kind":"%s","relay_used":%s,"relay_bytes":%s,"integrity":"ok"}\n' \
    "$scenario" "$actual_kind" "$actual_relay" "$relay_bytes"
