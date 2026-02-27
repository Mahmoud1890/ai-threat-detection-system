#!/usr/bin/env python3
"""
file_access_monitor.py — eBPF-based file access sensor.

WHAT THIS FILE DOES:
    Watches every file open() call made by any process on the system.
    Captures the file path, the process that opened it, and — crucially —
    the open flags (read-only? write? create? truncate?), then writes a
    structured event to the shared JSONL event stream.

WHY FLAGS MATTER FOR EDR:
    A process opening /etc/cron.d/job for reading is normal system behavior.
    A process opening /etc/cron.d/job with O_WRONLY|O_CREAT is installing
    a persistence mechanism. Without flags, those two events look identical.
    With flags, you can write precise detection rules that distinguish intent.

HOW IT WORKS:
    We attach kprobes to the openat() and open() syscall handler functions
    in the kernel. A kprobe fires our BPF code every time those functions
    are called, before the kernel does anything with the arguments. We read
    the filename and flags straight from the syscall arguments, then send
    them to userspace through a perf ring buffer.

NOISE FILTERING:
    File open events are the highest-volume syscall on a running system.
    /proc, /sys, /dev, and /run are virtual filesystems that generate
    thousands of events per second but contain almost no threat signal.
    We filter them in Python userspace before touching /proc to enrich
    the event — this is intentionally cheap.

REQUIRES: root privileges, BCC installed (sudo apt install python3-bcc).
"""

from bcc import BPF
import os
import signal

# Import the shared normalization layer.
# build_event()   — builds a schema-validated event dict
# write_jsonl()   — appends it to the JSONL file, thread-safely
# safe_read_text()— reads a file as text, returns "" on any error
# get_ppid_uid()  — reads parent PID and UID from /proc/<pid>/status
# get_exe_path()  — reads the full executable path from /proc/<pid>/exe
from events.builder import build_event, write_jsonl, safe_read_text, get_ppid_uid, get_exe_path

# All three sensors write to the same file so the detection engine gets
# one unified stream of process, file, and network events to correlate.
OUT_JSONL = "data/raw/events.jsonl"

# ---------------------------------------------------------------------------
# NOISE FILTER
# Paths under these prefixes are virtual kernel filesystems, not real files.
# They generate enormous event volume (thousands/sec) with zero threat signal.
# We check this BEFORE enriching with /proc data to keep hot-path cost minimal.
# ---------------------------------------------------------------------------
IGNORED_PATH_PREFIXES = (
    "/proc/",       # kernel process info — every process reads this constantly
    "/sys/",        # kernel hardware/driver interface — continuous background reads
    "/dev/",        # device files — terminals, random, null, etc.
    "/run/",        # runtime state files — PIDs, sockets, lock files
    "/tmp/.font",   # font cache — X11 reads these thousands of times at startup
    "/tmp/.X",      # X11 socket files — display server inter-process comms
)

# ---------------------------------------------------------------------------
# OPEN FLAGS DECODER
#
# When a process calls open(), it passes an integer 'flags' argument that
# is a bitmask telling the kernel what to do with the file. For example:
#
#   flags = 65  →  binary: 01000001  →  O_WRONLY (1) | O_CREAT (64)
#
# The lowest 2 bits encode the access mode (read/write/both).
# Higher bits are individual feature flags OR'd together.
#
# We decode this into a human-readable list for two reasons:
#   1. Detection rules can match on ["O_WRONLY", "O_CREAT"] directly
#   2. The LLM triage layer (Phase 3) can read plain English, not integers
#
# We also keep flags_raw (the original integer) so Phase 2 rules can do
# fast bitmask checks: (flags_raw & os.O_WRONLY) instead of list lookups.
# ---------------------------------------------------------------------------

# Access mode lives in the lowest 2 bits of flags.
# os.O_ACCMODE is the bitmask 0b11 that isolates just those 2 bits.
_ACCESS_MODE = {
    os.O_RDONLY: "O_RDONLY",   # 0 — open for reading only
    os.O_WRONLY: "O_WRONLY",   # 1 — open for writing only
    os.O_RDWR:   "O_RDWR",    # 2 — open for reading and writing
}

# These are individual bits in the flags integer. We check each one and
# include its name in the output list if the bit is set.
_FLAG_BITS = [
    (os.O_CREAT,     "O_CREAT"),     # create the file if it doesn't exist
    (os.O_EXCL,      "O_EXCL"),      # fail if file already exists (atomic create)
    (os.O_TRUNC,     "O_TRUNC"),     # wipe the file contents on open (destructive)
    (os.O_APPEND,    "O_APPEND"),    # all writes go to end of file (log-safe)
    (os.O_NONBLOCK,  "O_NONBLOCK"),  # don't block if data isn't ready
    (os.O_DSYNC,     "O_DSYNC"),     # wait for data to be written to disk
    (os.O_DIRECTORY, "O_DIRECTORY"), # fail if path is not a directory
    (os.O_NOFOLLOW,  "O_NOFOLLOW"),  # don't follow symbolic links
    (os.O_CLOEXEC,   "O_CLOEXEC"),   # close this fd automatically on exec()
]


def decode_open_flags(flags: int) -> list:
    """Convert a raw open() flags integer into a human-readable list of names.

    Example:
        decode_open_flags(577)  →  ["O_WRONLY", "O_CREAT", "O_TRUNC"]
        decode_open_flags(0)    →  ["O_RDONLY"]
    """
    # Extract access mode from lowest 2 bits. Default to O_RDONLY if unrecognised.
    result = [_ACCESS_MODE.get(flags & os.O_ACCMODE, "O_RDONLY")]
    # Check every known flag bit and add its name if it's set.
    for bit, name in _FLAG_BITS:
        if flags & bit:
            result.append(name)
    return result


# =============================================================================
# BPF PROGRAM (C code that runs inside the Linux kernel)
# =============================================================================
# Everything inside this string is C code compiled by BCC and loaded into
# the kernel's eBPF virtual machine. It runs with near-zero overhead on
# every openat() and open() syscall, system-wide, for every process.
# =============================================================================
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>   /* pt_regs: access to syscall arguments */
#include <linux/sched.h>         /* TASK_COMM_LEN: max process name length (16) */

#define FNAME_LEN 256   /* max file path length we'll capture from the syscall */

/* ── Event struct ───────────────────────────────────────────────────────────
   Defines the exact binary layout sent from kernel to userspace.
   Every field here becomes an attribute on the Python object we receive
   in handle_event() below.
   ────────────────────────────────────────────────────────────────────────── */
struct event_t {
    u64  ts_ns;              /* kernel timestamp — nanoseconds since boot */
    u32  pid;                /* process ID of the process calling open() */
    u32  flags;              /* raw open flags bitmask — decoded in Python */
    char comm[TASK_COMM_LEN]; /* process name, e.g. "vim", "nginx" (max 16 chars) */
    char fname[FNAME_LEN];   /* file path being opened, e.g. "/etc/passwd" */
};

/* Ring buffer that sends events from kernel to our Python userspace handler. */
BPF_PERF_OUTPUT(events);


/* ── trace_openat ───────────────────────────────────────────────────────────
   Attached to __x64_sys_openat — the main file-open syscall on x86-64 Linux.
   openat() is used by almost all modern programs (glibc wraps open() with it).

   Arguments mirror the openat(2) syscall:
     dfd      — directory file descriptor (base for relative paths, ignored here)
     filename — pointer to the file path string in the calling process's memory
     flags    — bitmask of O_RDONLY, O_WRONLY, O_CREAT, etc.
     mode     — file permission bits if creating (ignored here)
   ────────────────────────────────────────────────────────────────────────── */
int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    struct event_t ev = {};   /* zero-initialise to avoid garbage data in unused bytes */

    ev.ts_ns  = bpf_ktime_get_ns();             /* monotonic kernel clock */
    ev.pid    = bpf_get_current_pid_tgid() >> 32; /* high 32 bits = PID */
    ev.flags  = flags;                           /* capture the open flags bitmask */

    bpf_get_current_comm(&ev.comm, sizeof(ev.comm)); /* process name from task struct */

    /* bpf_probe_read_user_str: safely copies a string from user memory into
       the BPF stack. We cannot dereference user pointers directly in eBPF.
       Truncates to FNAME_LEN if the path is longer. */
    bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), filename);

    /* Push the event into the ring buffer — our Python handler receives it. */
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}


/* ── trace_open ─────────────────────────────────────────────────────────────
   Attached to __x64_sys_open — the older file-open syscall.
   Still used by some older binaries and statically linked programs.
   May not exist on very new kernels (6.x+) where open() was removed.
   We attach it in a try/except in Python so failure is not fatal.
   ────────────────────────────────────────────────────────────────────────── */
int trace_open(struct pt_regs *ctx, const char __user *filename, int flags, umode_t mode) {
    struct event_t ev = {};

    ev.ts_ns  = bpf_ktime_get_ns();
    ev.pid    = bpf_get_current_pid_tgid() >> 32;
    ev.flags  = flags;

    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), filename);

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""


# =============================================================================
# USERSPACE (normal Python — runs outside the kernel)
# =============================================================================

running = True  # set to False by the signal handler to exit the poll loop


def ensure_data_dir():
    """Create data/raw/ if it doesn't exist. Safe to call repeatedly."""
    os.makedirs("data/raw", exist_ok=True)


def stop(signum, frame):
    """Signal handler: sets running=False so the poll loop exits cleanly
    on Ctrl+C (SIGINT) or kill (SIGTERM)."""
    global running
    running = False


def is_noise(path: str) -> bool:
    """Return True if this path is near-certain high-volume noise.
    Called before any /proc enrichment to keep the hot path fast."""
    for prefix in IGNORED_PATH_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def main():
    ensure_data_dir()

    # Compile and load the BPF C program into the kernel via BCC.
    b = BPF(text=BPF_PROGRAM)

    # Attach our BPF function to the openat syscall entry point.
    # Every process on the system that calls openat() will now trigger trace_openat.
    b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")

    # Also attach to the older open() syscall. Wrapped in try/except because
    # __x64_sys_open was removed in some newer kernel versions.
    try:
        b.attach_kprobe(event="__x64_sys_open", fn_name="trace_open")
    except Exception:
        pass  # not fatal — openat() covers the vast majority of file opens

    # ── Event handler ────────────────────────────────────────────────────────
    # Called by BCC each time the kernel sends an event through the perf buffer.
    # 'data' is the raw binary blob matching struct event_t.
    def handle_event(cpu, data, size):
        # Parse the binary payload into a Python object with named attributes.
        ev = b["events"].event(data)

        pid  = int(ev.pid)
        comm = ev.comm.decode(errors="replace")  # bytes → str
        path = ev.fname.decode(errors="replace") # bytes → str

        # Drop noise before doing any expensive /proc reads.
        # is_noise() is just a string prefix check — very fast.
        if is_noise(path):
            return

        # Enrich with parent PID and UID from /proc/<pid>/status.
        # get_ppid_uid() handles the race condition where the process
        # exits before we read /proc, returning (0, 0) in that case.
        ppid, uid = get_ppid_uid(pid)

        # Read the full executable path from /proc/<pid>/exe (a symlink).
        # Returns "" if the process already exited.
        exe = get_exe_path(pid)

        # Standard process block required by events/schema.py.
        process = {
            "pid":  pid,
            "ppid": ppid,
            "uid":  uid,
            "comm": comm,
            "exe":  exe,
        }

        # Decode the raw flags integer into a readable list.
        # e.g. 65 → ["O_WRONLY", "O_CREAT"]
        flags_raw  = int(ev.flags)
        flags_list = decode_open_flags(flags_raw)

        # Build and validate the schema-compliant event, then write it.
        evt = build_event(
            event_type="file_open",
            process=process,
            data={
                "path":         path,
                "flags":        flags_list,  # human-readable for rules and LLM triage
                "flags_raw":    flags_raw,   # raw integer for fast bitmask checks in rules
                "kernel_ts_ns": int(ev.ts_ns),
            },
        )

        # Thread-safe append to the shared JSONL event stream.
        write_jsonl(OUT_JSONL, evt)

    # Register the Python handler with BCC's perf buffer system.
    b["events"].open_perf_buffer(handle_event)

    print(f"[+] File Access Monitor running. Writing JSONL to {OUT_JSONL}")
    print("[+] Press Ctrl+C to stop.")

    # Register signal handlers for clean shutdown.
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # Poll the perf ring buffer every 1000ms. BCC calls handle_event for
    # any events that arrived since the last poll. Exits when running = False.
    while running:
        b.perf_buffer_poll(timeout=1000)

    print("[+] Stopped.")


if __name__ == "__main__":
    main()
