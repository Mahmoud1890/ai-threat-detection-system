#!/usr/bin/env bash
# run.sh — launch all EDR sensors and stream telemetry to data/raw/events.jsonl
#
# Usage:
#   sudo ./run.sh              # all sensors
#   sudo ./run.sh exec         # process exec sensor only
#   sudo ./run.sh file         # file access sensor only
#   sudo ./run.sh net          # network sensor only
#
set -euo pipefail

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[!] eBPF requires root. Re-run with: sudo ./run.sh" >&2
    exit 1
fi

# ── Run from project root so relative paths (data/raw/) resolve correctly ─────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Sensor selection ──────────────────────────────────────────────────────────
RUN_EXEC=true
RUN_FILE=true
RUN_NET=true

if [[ $# -gt 0 ]]; then
    RUN_EXEC=false
    RUN_FILE=false
    RUN_NET=false
    for arg in "$@"; do
        case "$arg" in
            exec) RUN_EXEC=true ;;
            file) RUN_FILE=true ;;
            net)  RUN_NET=true  ;;
            *)
                echo "[!] Unknown sensor: $arg (valid: exec, file, net)" >&2
                exit 1
                ;;
        esac
    done
fi

# ── Ensure output directory exists ───────────────────────────────────────────
mkdir -p data/raw

echo "========================================"
echo "  AI Threat Detection System"
echo "  Output: $SCRIPT_DIR/data/raw/events.jsonl"
echo "========================================"
echo ""

PIDS=()

# ── Launch sensors ────────────────────────────────────────────────────────────
if $RUN_EXEC; then
    python3 ebpf/process_exec_logger.py &
    PIDS+=($!)
    echo "[+] process_exec_logger  PID ${PIDS[-1]}"
fi

if $RUN_FILE; then
    python3 ebpf/file_access_monitor.py &
    PIDS+=($!)
    echo "[+] file_access_monitor  PID ${PIDS[-1]}"
fi

if $RUN_NET; then
    python3 ebpf/network_monitor.py &
    PIDS+=($!)
    echo "[+] network_monitor      PID ${PIDS[-1]}"
fi

if [[ ${#PIDS[@]} -eq 0 ]]; then
    echo "[!] No sensors selected." >&2
    exit 1
fi

echo ""
echo "[+] All sensors running. Press Ctrl+C to stop."
echo ""

# ── Graceful shutdown ─────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "[+] Stopping sensors..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    echo "[+] All sensors stopped. Events written to data/raw/events.jsonl"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ── Monitor for unexpected sensor exit ───────────────────────────────────────
while true; do
    for pid in "${PIDS[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[!] Sensor PID $pid exited unexpectedly. Stopping all sensors."
            cleanup
        fi
    done
    sleep 2
done
