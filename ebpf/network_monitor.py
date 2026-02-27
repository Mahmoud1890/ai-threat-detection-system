#!/usr/bin/env python3
"""
network_monitor.py — eBPF-based outbound TCP connection sensor.

WHAT THIS FILE DOES:
    Watches every outbound TCP connection made by any process on the system.
    When a process calls connect() to reach an external server, this sensor
    captures who did it (PID, process name, user), and where they connected
    (source IP/port → destination IP/port), then writes a structured event
    to the shared JSONL event stream.

WHY THIS MATTERS FOR EDR:
    Network events are what link everything together in threat detection.
    A process reading /etc/passwd is suspicious. That same process then
    opening a TCP connection to an external IP makes it a confirmed exfil.
    Without network telemetry, you can only see half the attack chain.

HOW IT WORKS (two-probe design):
    The challenge is timing. When connect() starts, the kernel hasn't
    assigned the source port or routed the packet yet — so we can't read
    the full connection details at entry. The solution is two probes:

    1. ENTRY PROBE  — fires when connect() is called. We grab a pointer to
                      the kernel's socket struct and save it in a BPF hash
                      table. That's all we do here.

    2. RETURN PROBE — fires after connect() finishes. Now the kernel has
                      filled in all the address fields. We look up our saved
                      pointer, read src/dst IP and port, and emit the event.
                      If connect() failed (ret != 0), we discard it — we
                      only care about successful connections.

    We do this separately for IPv4 (tcp_v4_connect) and IPv6 (tcp_v6_connect).

REQUIRES: root privileges, BCC installed (sudo apt install python3-bcc).
"""

import os
import signal
import socket
import struct

from bcc import BPF

# Import the shared normalization layer.
# build_event()   — builds a schema-validated event dict
# write_jsonl()   — appends it to the JSONL file, thread-safely
# get_ppid_uid()  — reads parent PID and UID from /proc/<pid>/status
# get_exe_path()  — reads the full executable path from /proc/<pid>/exe
from events.builder import build_event, write_jsonl, get_ppid_uid, get_exe_path

# All three sensors write to the same file so the detection engine
# gets a single unified stream of process, file, and network events.
OUT_JSONL = "data/raw/events.jsonl"

# Connections to 127.x.x.x (localhost) are extremely high volume and almost
# never relevant for threat detection — they're just inter-process comms on
# the same machine. Set this to False if you need to debug local traffic.
IGNORE_LOOPBACK = True


# =============================================================================
# BPF PROGRAM (C code that runs inside the Linux kernel)
# =============================================================================
# Everything inside this string is C code compiled by BCC and loaded directly
# into the kernel. It runs in a sandboxed eBPF virtual machine — it cannot
# crash the kernel and cannot access arbitrary memory. It can only do what
# the eBPF verifier approves.
#
# This C code runs on every connect() call system-wide, for every process,
# with near-zero overhead (no context switch, no user/kernel boundary crossing
# per event).
# =============================================================================
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>   /* pt_regs: access to CPU registers at probe point */
#include <net/sock.h>            /* struct sock: the kernel's universal socket struct */
#include <net/inet_sock.h>       /* struct inet_sock: extends sock with IP/port fields */
#include <linux/sched.h>         /* TASK_COMM_LEN: max length of a process name (16) */

/* Address family constants — tells us whether a socket is IPv4 or IPv6. */
#define AF_INET  2
#define AF_INET6 10

/* ── Event structs ──────────────────────────────────────────────────────────
   These define the exact binary layout of the data we send from kernel to
   userspace through the perf ring buffer. Each field maps to a Python
   attribute we'll read in handle_ipv4() / handle_ipv6() below.
   ────────────────────────────────────────────────────────────────────────── */

struct ipv4_event_t {
    u64  ts_ns;              /* kernel timestamp in nanoseconds (bpf_ktime_get_ns) */
    u32  pid;                /* process ID of the connecting process */
    u32  uid;                /* user ID — 0 means root */
    char comm[TASK_COMM_LEN]; /* process name, e.g. "curl", "python3" (max 16 chars) */
    u32  saddr;              /* source (local) IPv4 address — network byte order */
    u32  daddr;              /* destination (remote) IPv4 address — network byte order */
    u16  sport;              /* source (local) port — network byte order */
    u16  dport;              /* destination (remote) port — network byte order */
};

struct ipv6_event_t {
    u64  ts_ns;
    u32  pid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    u8   saddr[16];          /* IPv6 addresses are 128 bits = 16 bytes */
    u8   daddr[16];
    u16  sport;
    u16  dport;
};

/* ── BPF data structures ────────────────────────────────────────────────────
   BPF_HASH: a kernel-side hash table. We use it to pass the sock pointer
   from the entry probe to the return probe.

   Key:   u32 TID (thread ID, not PID).
          We use TID because multiple threads in the same process can call
          connect() simultaneously — if we keyed by PID they'd overwrite
          each other's saved pointer and we'd lose events.

   Value: struct sock* — a pointer to the kernel socket struct.

   BPF_PERF_OUTPUT: a high-performance ring buffer for sending events to
   userspace. Much faster than writing to files or pipes.
   ────────────────────────────────────────────────────────────────────────── */
BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(ipv4_events);
BPF_PERF_OUTPUT(ipv6_events);


/* ── Entry probes ───────────────────────────────────────────────────────────
   These fire the instant tcp_v4_connect / tcp_v6_connect is called.
   We only save the sock pointer here — we can't read addresses yet because
   the kernel hasn't filled them in.
   ────────────────────────────────────────────────────────────────────────── */

int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 tid = (u32)bpf_get_current_pid_tgid(); /* low 32 bits = thread ID */
    currsock.update(&tid, &sk);                 /* save: TID → sock pointer */
    return 0;
}

int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    currsock.update(&tid, &sk);
    return 0;
}


/* ── Return probe: IPv4 ─────────────────────────────────────────────────────
   Fires after tcp_v4_connect() returns. By now the kernel has:
     - routed the packet and assigned the local port (inet_sport)
     - set the destination IP (skc_daddr) and port (skc_dport)
     - returned 0 on success or a negative error code on failure
   ────────────────────────────────────────────────────────────────────────── */
int trace_connect_v4_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);                  /* return value of connect() */
    u32 tid = (u32)bpf_get_current_pid_tgid();

    /* Look up the sock pointer we saved at entry. */
    struct sock **skpp = currsock.lookup(&tid);
    if (!skpp) return 0;     /* no entry found — entry probe missed, skip */
    currsock.delete(&tid);   /* clean up the hash table entry either way */

    if (ret != 0) return 0;  /* connect() failed — not a real connection, skip */

    struct sock *sk = *skpp;

    /* Double-check this is actually an IPv4 socket before reading IPv4 fields.
       This matters because currsock is shared between v4 and v6 entry probes. */
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    /* Build the event. bpf_probe_read() safely copies kernel memory — we
       must use this instead of direct pointer dereference in eBPF. */
    struct ipv4_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid   = bpf_get_current_pid_tgid() >> 32; /* high 32 bits = process ID */
    ev.uid   = (u32)bpf_get_current_uid_gid();   /* low 32 bits = user ID */
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    /* skc_rcv_saddr = local (source) IPv4 address */
    bpf_probe_read(&ev.saddr, sizeof(ev.saddr), &sk->__sk_common.skc_rcv_saddr);
    /* skc_daddr = remote (destination) IPv4 address */
    bpf_probe_read(&ev.daddr, sizeof(ev.daddr), &sk->__sk_common.skc_daddr);

    /* Ports are in the inet_sock layer which extends sock. */
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read(&ev.sport, sizeof(ev.sport), &inet->inet_sport); /* local port */
    bpf_probe_read(&ev.dport, sizeof(ev.dport), &sk->__sk_common.skc_dport); /* remote port */
    /* Note: ports are in network byte order here. We convert them in Python
       with socket.ntohs() rather than doing it in BPF to keep this simple. */

    /* Send the event through the perf ring buffer to our Python handler. */
    ipv4_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}


/* ── Return probe: IPv6 ─────────────────────────────────────────────────────
   Same logic as the IPv4 return probe but reads 128-bit IPv6 addresses
   from the sock struct's IPv6-specific fields.
   ────────────────────────────────────────────────────────────────────────── */
int trace_connect_v6_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct sock **skpp = currsock.lookup(&tid);
    if (!skpp) return 0;
    currsock.delete(&tid);

    if (ret != 0) return 0;

    struct sock *sk = *skpp;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET6) return 0;

    struct ipv6_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid   = bpf_get_current_pid_tgid() >> 32;
    ev.uid   = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    /* IPv6 addresses live in skc_v6_rcv_saddr and skc_v6_daddr.
       u6_addr8 is the raw byte array form of the 128-bit address. */
    bpf_probe_read(ev.saddr, sizeof(ev.saddr),
                   sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    bpf_probe_read(ev.daddr, sizeof(ev.daddr),
                   sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);

    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read(&ev.sport, sizeof(ev.sport), &inet->inet_sport);
    bpf_probe_read(&ev.dport, sizeof(ev.dport), &sk->__sk_common.skc_dport);

    ipv6_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""


# =============================================================================
# USERSPACE (normal Python — runs outside the kernel)
# =============================================================================

running = True  # flipped to False by the signal handler to stop the poll loop


def ensure_data_dir():
    """Create data/raw/ if it doesn't exist yet. Safe to call repeatedly."""
    os.makedirs("data/raw", exist_ok=True)


def stop(signum, frame):
    """Signal handler for Ctrl+C (SIGINT) and kill (SIGTERM).
    Sets the flag that breaks the poll loop so we exit cleanly."""
    global running
    running = False


def is_loopback(ip: str) -> bool:
    """Return True if the IP is a loopback address.
    127.x.x.x covers all IPv4 loopback. ::1 is the IPv6 loopback address."""
    return ip.startswith("127.") or ip == "::1"


def main():
    ensure_data_dir()

    # Compile and load the BPF program into the kernel.
    # BCC compiles the C code above using the kernel headers on this machine.
    b = BPF(text=BPF_PROGRAM)

    # Attach entry and return probes to the IPv4 connect function.
    b.attach_kprobe(event="tcp_v4_connect",    fn_name="trace_connect_v4_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")

    # Attach the same probes for IPv6. This may fail on kernels where
    # IPv6 support is compiled out — we log a warning and continue IPv4-only.
    ipv6_enabled = True
    try:
        b.attach_kprobe(event="tcp_v6_connect",    fn_name="trace_connect_v6_entry")
        b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
    except Exception:
        ipv6_enabled = False
        print("[!] tcp_v6_connect unavailable — IPv6 monitoring disabled.")

    # ── IPv4 event handler ───────────────────────────────────────────────────
    # Called by BCC every time the kernel pushes an ipv4_event_t through the
    # perf ring buffer. 'data' is the raw binary payload, 'size' is its length.
    def handle_ipv4(cpu, data, size):
        # Parse the binary payload into a Python object matching ipv4_event_t.
        ev = b["ipv4_events"].event(data)

        pid  = int(ev.pid)
        uid  = int(ev.uid)
        comm = ev.comm.decode(errors="replace")  # bytes → str, replace bad chars

        # Convert raw 4-byte integers to dotted-decimal strings like "93.184.216.34".
        # struct.pack("I", n) turns an unsigned int into 4 bytes in native byte order.
        # socket.inet_ntop then converts those bytes to a human-readable IP string.
        src_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", ev.saddr))
        dst_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", ev.daddr))

        # Ports are stored in network byte order (big-endian) in the kernel struct.
        # socket.ntohs() swaps the bytes to host order so 0x1F90 becomes 8080.
        sport = socket.ntohs(ev.sport)
        dport = socket.ntohs(ev.dport)

        # Skip localhost connections — they're noise for threat detection.
        if IGNORE_LOOPBACK and is_loopback(dst_ip):
            return

        # Get PPID from /proc. We already have UID from the kernel (more reliable),
        # so we discard the uid returned by get_ppid_uid() with the _ convention.
        ppid, _ = get_ppid_uid(pid)
        exe     = get_exe_path(pid)  # full path, e.g. /usr/bin/curl

        # Build the standard process block required by the event schema.
        process = {
            "pid":  pid,
            "ppid": ppid,
            "uid":  uid,
            "comm": comm,
            "exe":  exe,
        }

        # build_event() assembles the full schema-compliant event dict,
        # adds version, event_id (UUID), timestamp, and host metadata,
        # then validates all required fields before returning.
        evt = build_event(
            event_type="net_connect",
            process=process,
            data={
                "direction":    "outbound",    # we only hook connect(), not accept()
                "protocol":     "tcp",
                "af":           "ipv4",
                "src_ip":       src_ip,
                "src_port":     sport,
                "dst_ip":       dst_ip,
                "dst_port":     dport,
                "kernel_ts_ns": int(ev.ts_ns), # raw kernel clock for precise ordering
            },
        )

        # Append the event as a single JSON line. Thread-safe via module lock.
        write_jsonl(OUT_JSONL, evt)

    # ── IPv6 event handler ───────────────────────────────────────────────────
    # Same as handle_ipv4 but reads 16-byte IPv6 addresses instead of 4-byte.
    def handle_ipv6(cpu, data, size):
        ev = b["ipv6_events"].event(data)

        pid  = int(ev.pid)
        uid  = int(ev.uid)
        comm = ev.comm.decode(errors="replace")

        # bytes(ev.saddr) converts the ctypes array to a Python bytes object.
        # inet_ntop with AF_INET6 turns 16 bytes into a string like "::1" or
        # "2001:db8::1".
        src_ip = socket.inet_ntop(socket.AF_INET6, bytes(ev.saddr))
        dst_ip = socket.inet_ntop(socket.AF_INET6, bytes(ev.daddr))
        sport  = socket.ntohs(ev.sport)
        dport  = socket.ntohs(ev.dport)

        if IGNORE_LOOPBACK and is_loopback(dst_ip):
            return

        ppid, _ = get_ppid_uid(pid)
        exe     = get_exe_path(pid)

        process = {
            "pid":  pid,
            "ppid": ppid,
            "uid":  uid,
            "comm": comm,
            "exe":  exe,
        }

        evt = build_event(
            event_type="net_connect",
            process=process,
            data={
                "direction":    "outbound",
                "protocol":     "tcp",
                "af":           "ipv6",
                "src_ip":       src_ip,
                "src_port":     sport,
                "dst_ip":       dst_ip,
                "dst_port":     dport,
                "kernel_ts_ns": int(ev.ts_ns),
            },
        )

        write_jsonl(OUT_JSONL, evt)

    # Register the Python handlers with BCC's perf buffer system.
    # From this point on, BCC will call handle_ipv4 / handle_ipv6 every time
    # the kernel submits an event through the ring buffer.
    b["ipv4_events"].open_perf_buffer(handle_ipv4)
    if ipv6_enabled:
        b["ipv6_events"].open_perf_buffer(handle_ipv6)

    print(f"[+] Network Monitor running. Writing JSONL to {OUT_JSONL}")
    print(f"[+] IPv6: {'enabled' if ipv6_enabled else 'disabled'}. "
          f"Loopback filter: {'on' if IGNORE_LOOPBACK else 'off'}.")
    print("[+] Press Ctrl+C to stop.")

    # Register our stop() function to handle Ctrl+C and kill signals gracefully.
    signal.signal(signal.SIGINT,  stop)
    signal.signal(signal.SIGTERM, stop)

    # Poll the perf ring buffer every 1000ms. BCC calls our handlers for any
    # events that arrived since the last poll. We loop until stop() sets
    # running = False, then exit cleanly.
    while running:
        b.perf_buffer_poll(timeout=1000)

    print("[+] Stopped.")


if __name__ == "__main__":
    main()
