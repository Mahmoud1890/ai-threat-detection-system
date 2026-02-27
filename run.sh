#!/usr/bin/env bash
# =============================================================================
# run.sh — Launch all EDR sensors and stream telemetry to data/raw/events.jsonl
#
# WHAT THIS SCRIPT DOES:
#   Starts the three eBPF sensors as background processes, monitors them for
#   unexpected crashes, and shuts everything down cleanly on Ctrl+C or kill.
#
# WHY THIS EXISTS:
#   Each sensor needs root and must be started from the project root directory
#   so that the relative path "data/raw/events.jsonl" resolves correctly.
#   Doing this manually across three terminals every time is error-prone.
#   This script handles all of that in one command.
#
# USAGE:
#   sudo ./run.sh              — start all three sensors
#   sudo ./run.sh exec         — process execution sensor only
#   sudo ./run.sh file         — file access sensor only
#   sudo ./run.sh net          — network connection sensor only
#   sudo ./run.sh exec net     — any combination works
#
# OUTPUT:
#   All events from all sensors are written to data/raw/events.jsonl as
#   newline-delimited JSON (one event per line). The file is appended to,
#   never overwritten, so you accumulate a full history across runs.
# =============================================================================

# set -e  : exit immediately if any command returns a non-zero exit code
# set -u  : treat unset variables as errors (catches typos like $PIDS vs $PIDS)
# set -o pipefail : a pipeline fails if any command in it fails, not just the last
set -euo pipefail


# ── Root check ────────────────────────────────────────────────────────────────
# eBPF programs require root to load into the kernel. Without root, BCC will
# fail deep inside its compilation step with a cryptic permission error.
# We check upfront and give a clear message instead.
if [[ $EUID -ne 0 ]]; then
    echo "[!] eBPF requires root. Re-run with: sudo ./run.sh" >&2
    exit 1
fi


# ── Always run from the project root ─────────────────────────────────────────
# The sensors use relative paths like "data/raw/events.jsonl". If you run this
# script from a different directory (e.g. your home folder), those paths break.
# This block finds where run.sh lives and cd's there unconditionally.
#
# BASH_SOURCE[0] = path to this script file
# dirname        = strip the filename, keep the directory
# cd + pwd       = resolve to an absolute path (handles symlinks and "..")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"


# ── Sensor selection ──────────────────────────────────────────────────────────
# Default: run everything. If arguments are given, only run the named sensors.
RUN_EXEC=true
RUN_FILE=true
RUN_NET=true

if [[ $# -gt 0 ]]; then
    # Arguments were provided — reset all flags to false and enable only
    # the ones explicitly named.
    RUN_EXEC=false
    RUN_FILE=false
    RUN_NET=false
    for arg in "$@"; do
        case "$arg" in
            exec) RUN_EXEC=true ;;
            file) RUN_FILE=true ;;
            net)  RUN_NET=true  ;;
            *)
                echo "[!] Unknown sensor: '$arg'" >&2
                echo "    Valid options: exec, file, net" >&2
                exit 1
                ;;
        esac
    done
fi


# ── Ensure output directory exists ───────────────────────────────────────────
# The sensors call os.makedirs() themselves, but doing it here too means the
# directory exists before any sensor starts, avoiding a theoretical race where
# two sensors try to create it simultaneously.
mkdir -p data/raw

echo "========================================"
echo "  AI Threat Detection System"
echo "  Output: $SCRIPT_DIR/data/raw/events.jsonl"
echo "========================================"
echo ""


# ── Launch sensors ────────────────────────────────────────────────────────────
# PIDS is an array that will hold the process ID of each sensor we start.
# We need these IDs later to monitor them and to kill them on shutdown.
PIDS=()

if $RUN_EXEC; then
    # The & at the end launches the command in the background so this script
    # doesn't wait for it to finish before continuing.
    python3 ebpf/process_exec_logger.py &
    PIDS+=($!)   # $! = PID of the last background command launched
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

# If no sensors were selected (shouldn't happen given the defaults, but
# guard against it in case someone passes an empty argument list).
if [[ ${#PIDS[@]} -eq 0 ]]; then
    echo "[!] No sensors selected." >&2
    exit 1
fi

echo ""
echo "[+] All sensors running. Press Ctrl+C to stop."
echo ""


# ── Graceful shutdown ─────────────────────────────────────────────────────────
# This function is called when Ctrl+C is pressed or when the script receives
# a kill signal. It sends SIGTERM to every sensor PID, waits for them to
# finish flushing their buffers, then exits.
cleanup() {
    echo ""
    echo "[+] Stopping sensors..."
    for pid in "${PIDS[@]}"; do
        # Send SIGTERM. The sensors catch this in their signal handler and
        # set running=False, which breaks their poll loop cleanly.
        # "|| true" prevents set -e from exiting if a PID is already gone.
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]}"; do
        # Wait for each sensor process to actually exit before we return.
        # This ensures the JSONL file is fully flushed before the script ends.
        wait "$pid" 2>/dev/null || true
    done
    echo "[+] All sensors stopped."
    echo "[+] Events written to data/raw/events.jsonl"
    exit 0
}

# trap: register cleanup() to run when this script receives SIGINT (Ctrl+C)
# or SIGTERM (kill command). Without this, Ctrl+C would leave sensor
# processes running in the background as orphans.
trap cleanup SIGINT SIGTERM


# ── Monitor for unexpected sensor exit ───────────────────────────────────────
# We loop forever, checking every 2 seconds that all sensor PIDs are still
# alive. If any sensor crashes (e.g. because a kernel update changed a
# function signature), we detect it here and shut everything else down
# rather than silently running with incomplete telemetry.
#
# kill -0 <pid> doesn't send any signal — it just checks if the process
# exists and we have permission to signal it. Returns 0 if alive, 1 if dead.
while true; do
    for pid in "${PIDS[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[!] Sensor PID $pid exited unexpectedly. Stopping all sensors."
            cleanup
        fi
    done
    sleep 2   # check interval — short enough to detect crashes quickly
done
