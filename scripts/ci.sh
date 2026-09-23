#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
scenario_runner="$repo_root/tests/scenarios/run-scenario.sh"

usage() {
    printf '%s\n' \
        "用法：$0 <check|compose-contract|compose|compose-all|all>" \
        '  check            运行格式化、workspace 测试和 Clippy。' \
        '  compose-contract 校验全部 Compose profile 和网络测试入口。' \
        '  compose          运行当前可靠中继实现支持的 Compose 烟雾场景。' \
        '  compose-all      启动全部场景；direct 数据面未启用时会按契约失败。' \
        '  all              运行 check 和 compose-contract。'
}

check_rust() {
    cd "$repo_root"
    cargo fmt --all -- --check
    cargo test --workspace
    cargo clippy --workspace --all-targets --all-features -- -D warnings
}

check_compose_contract() {
    "$scenario_runner" --contract-only all
}

run_compose_smoke() {
    "$scenario_runner" same-subnet
}

run_compose_all() {
    "$scenario_runner" all
}

command=${1:-}
case "$command" in
    check)
        check_rust
        ;;
    compose-contract)
        check_compose_contract
        ;;
    compose)
        run_compose_smoke
        ;;
    compose-all)
        run_compose_all
        ;;
    all)
        check_rust
        check_compose_contract
        ;;
    *)
        usage >&2
        exit 64
        ;;
esac
