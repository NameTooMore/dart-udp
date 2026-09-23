#!/usr/bin/env bash
set -Eeuo pipefail

scenario=${SCENARIO:-}
artifact_dir=${ARTIFACT_DIR:-/artifacts}
timeout_seconds=${SCENARIO_TIMEOUT_SECONDS:-180}

if [[ -z "$scenario" ]]; then
    printf '%s\n' 'SCENARIO 未设置' >&2
    exit 64
fi

deadline=$((SECONDS + timeout_seconds))
wait_count=0
while (( SECONDS < deadline )); do
    if [[ -s "$artifact_dir/sender.status" && -s "$artifact_dir/receiver.status" ]]; then
        break
    fi
    wait_count=$((wait_count + 1))
    if (( wait_count % 5 == 0 )); then
        printf '[scenario-runner] 场景 %s 正在等待 sender/receiver 完成... (已等待 %d 秒)\n' "$scenario" "$wait_count"
    fi
    sleep 1
done

if [[ ! -s "$artifact_dir/sender.status" || ! -s "$artifact_dir/receiver.status" ]]; then
    printf '场景 %s 超时：sender/receiver 没有同时结束\n' "$scenario" >&2
    exit 124
fi

sender_status=$(<"$artifact_dir/sender.status")
receiver_status=$(<"$artifact_dir/receiver.status")
sender_record=$artifact_dir/sender.result.json
receiver_record=$artifact_dir/receiver.result.json

extract_record() {
    local log_file=$1
    local output_file=$2
    [[ -f "$log_file" ]] || return 0
    grep -Eo '\{"transfer_id"[^}]+\}' "$log_file" | tail -n 1 >"$output_file" || true
}

extract_record "$artifact_dir/sender.log" "$sender_record"
extract_record "$artifact_dir/receiver.log" "$receiver_record"

if [[ "$sender_status" == 0 && "$receiver_status" == 0 ]]; then
    source_root=$artifact_dir/input/transfer-fixture
    target_root=$artifact_dir/output/transfer-fixture
    if [[ ! -d "$target_root" ]]; then
        printf '场景 %s 未生成接收目录\n' "$scenario" >&2
        exit 1
    fi
    diff -qr "$source_root" "$target_root"
fi

if [[ ! -s "$sender_record" || ! -s "$receiver_record" ]]; then
    printf '场景 %s 缺少 JSON 结果记录\n' "$scenario" >&2
    exit 1
fi

jq -e '(.transfer_id | type == "string") and (.path_kind | type == "string") and (.relay_used | type == "boolean") and (.bytes | type == "number") and .integrity == "ok"' \
    "$sender_record" >/dev/null
jq -e '(.transfer_id | type == "string") and (.path_kind | type == "string") and (.relay_used | type == "boolean") and (.bytes | type == "number") and .integrity == "ok"' \
    "$receiver_record" >/dev/null

sender_transfer_id=$(jq -r .transfer_id "$sender_record")
receiver_transfer_id=$(jq -r .transfer_id "$receiver_record")
if [[ "$sender_transfer_id" != "$receiver_transfer_id" ]]; then
    printf '场景 %s 的两端 transfer_id 不一致\n' "$scenario" >&2
    exit 1
fi

jq -n \
    --arg scenario "$scenario" \
    --argjson sender_status "$sender_status" \
    --argjson receiver_status "$receiver_status" \
    --argjson sender "$(<"$sender_record")" \
    --argjson receiver "$(<"$receiver_record")" \
    '{scenario: $scenario, sender_status: $sender_status, receiver_status: $receiver_status, sender: $sender, receiver: $receiver, integrity: "ok"}' \
    >"$artifact_dir/scenario.result.json"

printf '场景 %s 完成：path_kind=%s relay_used=%s\n' \
    "$scenario" \
    "$(jq -r .path_kind "$sender_record")" \
    "$(jq -r .relay_used "$sender_record")"
