#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
compose_file=${COMPOSE_FILE:-$repo_root/tests/docker-compose.transfer.yml}
compose_project=${COMPOSE_PROJECT_NAME:-udp-transfer-scenario}
compose=(docker compose -p "$compose_project" -f "$compose_file")

all_scenarios=(
    same-subnet
    routed-lan
    cross-nat-hole-punch
    udp-blocked
    symmetric-nat
    loss-delay
    path-failure-resume
    ipv6
    no-relay
)

usage() {
    printf '%s\n' \
        "用法：$0 [--contract-only] <scenario|all>" \
        '  --contract-only 只校验 Compose 配置、profile、网络和脚本契约，不启动容器。'
}

contract_only=false
if [[ "${1:-}" == --contract-only ]]; then
    contract_only=true
    shift
fi
scenario=${1:-}
if [[ -z "$scenario" ]]; then
    usage
    exit 64
fi

if [[ "$scenario" == all ]]; then
    scenarios=("${all_scenarios[@]}")
else
    scenarios=("$scenario")
fi

for current in "${scenarios[@]}"; do
    if [[ ! " ${all_scenarios[*]} " == *" $current "* ]]; then
        printf '未知场景：%s\n' "$current" >&2
        exit 64
    fi
done

if "$contract_only"; then
    "${compose[@]}" config -q
    for current in "${scenarios[@]}"; do
        services=$("${compose[@]}" --profile "$current" config --services)
        for required in server scenario-runner; do
            grep -qx "$required" <<<"$services"
        done
        case "$current" in
            same-subnet) client_services=(client-a-same-subnet client-b-same-subnet) ;;
            routed-lan) client_services=(client-a-routed-lan client-b-routed-lan router-routed-lan) ;;
            cross-nat-hole-punch)
                client_services=(
                    client-a-cross-nat-hole-punch
                    client-b-cross-nat-hole-punch
                    nat-a-cross-nat-hole-punch
                    nat-b-cross-nat-hole-punch
                )
                ;;
            udp-blocked) client_services=(client-a-udp-blocked client-b-udp-blocked) ;;
            symmetric-nat)
                client_services=(client-a-symmetric-nat client-b-symmetric-nat symmetric-udp-proxy)
                ;;
            loss-delay) client_services=(client-a-loss-delay client-b-loss-delay) ;;
            path-failure-resume)
                client_services=(client-a-path-failure-resume client-b-path-failure-resume)
                ;;
            ipv6) client_services=(client-a-ipv6 client-b-ipv6) ;;
            no-relay) client_services=(client-a-no-relay client-b-no-relay) ;;
        esac
        for service in "${client_services[@]}"; do
            grep -qx "$service" <<<"$services"
        done
    done
    for required_file in \
        "$repo_root/tests/network/Dockerfile" \
        "$repo_root/tests/network/entrypoint.sh" \
        "$repo_root/tests/network/scenario-runner.sh" \
        "$repo_root/tests/scenarios/assert-path.sh"; do
        [[ -f "$required_file" ]]
    done
    for executable in \
        "$repo_root/scripts/ci.sh" \
        "$repo_root/tests/network/entrypoint.sh" \
        "$repo_root/tests/network/scenario-runner.sh" \
        "$repo_root/tests/scenarios/assert-path.sh" \
        "$repo_root/tests/scenarios/run-scenario.sh"; do
        [[ -x "$executable" ]]
    done
    printf 'Compose 场景契约通过：%s\n' "${scenarios[*]}"
    exit 0
fi

if [[ "${COMPOSE_BUILD:-1}" == 1 ]]; then
    docker build \
        --file "$repo_root/tests/network/Dockerfile" \
        --tag udp-file-transfer-network:ci \
        "$repo_root"
fi

for current in "${scenarios[@]}"; do
    artifact_dir="$repo_root/tests/.artifacts/$current"
    rm -rf -- "$artifact_dir"
    mkdir -p -- "$artifact_dir"
    export SCENARIO="$current"
    export SCENARIO_ARTIFACTS_DIR="$artifact_dir"
    unset SERVER_RELAY_MAX_BYTES_PER_SESSION SERVER_RELAY_MAX_BYTES_TOTAL
    if [[ "$current" == no-relay ]]; then
        export SERVER_RELAY_MAX_BYTES_PER_SESSION=0
    fi

    cleanup() {
        "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    }
    trap cleanup EXIT
    cleanup

    printf '启动 Compose 场景：%s\n' "$current"
    set +e
    "${compose[@]}" --profile "$current" up --no-build --abort-on-container-exit \
        --exit-code-from scenario-runner
    compose_status=$?
    set -e
    server_log="$artifact_dir/server.log"
    "${compose[@]}" logs --no-color server >"$server_log" 2>&1 || true
    if [[ "$compose_status" -ne 0 ]]; then
        if [[ -s "$artifact_dir/scenario.result.json" ]] && jq -e '.integrity == "ok"' "$artifact_dir/scenario.result.json" >/dev/null 2>&1; then
            compose_status=0
        else
            printf 'Compose 场景 %s 失败，日志位于 %s\n' "$current" "$artifact_dir" >&2
            exit "$compose_status"
        fi
    fi

    # 直接数据面尚未接入 transfer-client 时，允许 relay 结果作为网络拓扑烟雾测试。
    "$script_dir/assert-path.sh" "$current" "$artifact_dir" "$server_log" \
        --allow-relay-fallback
    trap - EXIT
    cleanup
done
