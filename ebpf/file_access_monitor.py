#!/usr/bin/env python3
from bcc import BPF
import os
import signal

from events.builder import build_event, write_jsonl

OUT_JSONL = "data/raw/events.jsonl"

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define FNAME_LEN 256

struct event_t {
    u64 ts_ns;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char fname[FNAME_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    struct event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), filename);
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

int trace_open(struct pt_regs *ctx, const char __user *filename, int flags, umode_t mode) {
    struct event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), filename);
    events.perf_submit(ctx, &ev, sizeof(ev));
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
    # Reads /proc/<pid>/status to extract PPid and Uid
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
    # /proc/<pid>/exe is a symlink to the actual executable path
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""

def main():
    ensure_data_dir()

    b = BPF(text=BPF_PROGRAM)

    # Attach to openat (primary)
    b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")

    # Attach to open (optional)
    try:
        b.attach_kprobe(event="__x64_sys_open", fn_name="trace_open")
    except Exception:
        pass

    def handle_event(cpu, data, size):
        ev = b["events"].event(data)

        pid = int(ev.pid)
        comm = ev.comm.decode(errors="replace")
        path = ev.fname.decode(errors="replace")

        ppid, uid = get_ppid_uid(pid)
        exe = get_exe_path(pid)

        process = {
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "comm": comm,
            "exe": exe,
        }

        evt = build_event(
            event_type="file_open",
            process=process,
            data={
                "path": path,
                "kernel_ts_ns": int(ev.ts_ns),
            },
        )

        write_jsonl(OUT_JSONL, evt)

    b["events"].open_perf_buffer(handle_event)

    print(f"[+] File Access Monitor running. Writing JSONL to {OUT_JSONL}")
    print("[+] Press Ctrl+C to stop.")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    while running:
        b.perf_buffer_poll(timeout=1000)

    print("[+] Stopped.")

if __name__ == "__main__":
    main()
