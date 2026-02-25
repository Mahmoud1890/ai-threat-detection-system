#!/usr/bin/env python3
from bcc import BPF
from datetime import datetime
import os
import signal

LOG_PATH = "data/file_events.log"

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
    os.makedirs("data", exist_ok=True)

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def stop(signum, frame):
    global running
    running = False

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

    with open(LOG_PATH, "a", buffering=1) as f:
        def handle_event(cpu, data, size):
            ev = b["events"].event(data)
            line = f"{now_iso()} pid={ev.pid} comm={ev.comm.decode(errors='replace')} file={ev.fname.decode(errors='replace')}\n"
            f.write(line)

        b["events"].open_perf_buffer(handle_event)

        print(f"[+] File Access Monitor running. Logging to {LOG_PATH}")
        print("[+] Press Ctrl+C to stop.")

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)

        while running:
            b.perf_buffer_poll(timeout=1000)

    print("[+] Stopped.")

if __name__ == "__main__":
    main()
