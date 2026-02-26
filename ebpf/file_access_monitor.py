#!/usr/bin/env python3
from bcc import BPF
import os
import signal
from events.builder import build_event, write_jsonl, safe_read_text, get_ppid_uid, get_exe_path

OUT_JSONL = "data/raw/events.jsonl"

# ---------------------------------------------------------------------------
# Path prefix filter — drop events for paths that are near-certain noise.
# Filtering is done in Python userspace here for simplicity; if volume is
# still too high, move these into the BPF program as a prefix-trie check.
# ---------------------------------------------------------------------------
IGNORED_PATH_PREFIXES = (
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/tmp/.font",
    "/tmp/.X",
)


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
    ev.pid   = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), filename);
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

int trace_open(struct pt_regs *ctx, const char __user *filename, int flags, umode_t mode) {
    struct event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid   = bpf_get_current_pid_tgid() >> 32;
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



def is_noise(path: str) -> bool:
    """Return True for paths that are near-certain high-volume noise."""
    for prefix in IGNORED_PATH_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def main():
    ensure_data_dir()

    b = BPF(text=BPF_PROGRAM)

    b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")

    try:
        b.attach_kprobe(event="__x64_sys_open", fn_name="trace_open")
    except Exception:
        pass  # __x64_sys_open may not exist on newer kernels

    def handle_event(cpu, data, size):
        ev = b["events"].event(data)

        pid  = int(ev.pid)
        comm = ev.comm.decode(errors="replace")
        path = ev.fname.decode(errors="replace")

        # Drop noise early — before touching /proc at all
        if is_noise(path):
            return

        ppid, uid = get_ppid_uid(pid)
        exe       = get_exe_path(pid)

        process = {
            "pid":  pid,
            "ppid": ppid,
            "uid":  uid,
            "comm": comm,
            "exe":  exe,
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
