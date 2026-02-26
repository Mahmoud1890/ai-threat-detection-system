#!/usr/bin/env python3
from bcc import BPF
import os
import signal

from events.builder import build_event, write_jsonl

OUT_JSONL = "data/raw/events.jsonl"

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    bpf_trace_printk("EXEC:%s\n", args->filename);
    return 0;
}
"""

running = True

def ensure_data_dir():
    os.makedirs("data/raw", exist_ok=True)

def stop(signum, frame):
    global running
    running = False

def safe_read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""

def get_ppid_uid(pid: int) -> tuple[int, int]:
    status = safe_read_text(f"/proc/{pid}/status")
    ppid = 0
    uid = 0
    for line in status.splitlines():
        if line.startswith("PPid:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                ppid = int(parts[1])
        elif line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                uid = int(parts[1])
    return ppid, uid

def get_exe_path(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""

def parse_exec_path(msg: str) -> str:
    # msg example: "EXEC:/usr/bin/ls"
    msg = msg.strip()
    if "EXEC:" in msg:
        return msg.split("EXEC:", 1)[1].strip()
    return msg

def main():
    ensure_data_dir()

    b = BPF(text=BPF_PROGRAM)

    print("[+] Logging process executions... Press Ctrl+C to stop.")
    print(f"[+] Writing JSONL to {OUT_JSONL}")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    while running:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
            # Sometimes trace_fields can throw if it reads an incomplete line
            continue

        exec_path = parse_exec_path(msg)

        ppid, uid = get_ppid_uid(pid)
        exe = get_exe_path(pid)

        process = {
            "pid": int(pid),
            "ppid": int(ppid),
            "uid": int(uid),
            "comm": str(task),
            "exe": exe if exe else exec_path,
        }

        evt = build_event(
            event_type="process_exec",
            process=process,
            data={
                "filename": exec_path,
            },
        )

        write_jsonl(OUT_JSONL, evt)

    print("[+] Stopped.")

if __name__ == "__main__":
    main()
