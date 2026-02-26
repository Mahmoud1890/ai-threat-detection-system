#!/usr/bin/env python3
from bcc import BPF
import os
import signal

from events.builder import build_event, write_jsonl, safe_read_text, get_ppid_uid, get_exe_path

OUT_JSONL = "data/raw/events.jsonl"

# Refactored: uses BPF_PERF_OUTPUT ring buffer instead of bpf_trace_printk.
# This avoids the global debug pipe, eliminates fragile string parsing,
# and matches the pattern used in file_access_monitor.py.
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define FNAME_LEN 256

struct exec_event_t {
    u64  ts_ns;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char filename[FNAME_LEN];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t ev = {};
    ev.ts_ns  = bpf_ktime_get_ns();
    ev.pid    = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), args->filename);
    exec_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

running = True


def ensure_data_dir():
    os.makedirs("data/raw", exist_ok=True)


def stop(signum, frame):
    global running
    running = False



def main():
    ensure_data_dir()  # creates data/raw/ if it doesn't exist yet

    b = BPF(text=BPF_PROGRAM)

    print("[+] Logging process executions... Press Ctrl+C to stop.")
    print(f"[+] Writing JSONL to {OUT_JSONL}")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    def handle_event(cpu, data, size):
        ev = b["exec_events"].event(data)

        pid       = int(ev.pid)
        comm      = ev.comm.decode(errors="replace")
        filename  = ev.filename.decode(errors="replace")

        ppid, uid = get_ppid_uid(pid)
        exe       = get_exe_path(pid) or filename  # fall back to execve arg if /proc race

        process = {
            "pid":  pid,
            "ppid": ppid,
            "uid":  uid,
            "comm": comm,
            "exe":  exe,
        }

        evt = build_event(
            event_type="process_exec",
            process=process,
            data={
                "filename": filename,
                "kernel_ts_ns": int(ev.ts_ns),
            },
        )

        write_jsonl(OUT_JSONL, evt)

    b["exec_events"].open_perf_buffer(handle_event)

    while running:
        b.perf_buffer_poll(timeout=1000)

    print("[+] Stopped.")


if __name__ == "__main__":
    main()
