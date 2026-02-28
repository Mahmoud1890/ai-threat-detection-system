#!/usr/bin/env python3

import os
import signal
import socket
import struct

from bcc import BPF
from events.builder import build_event, write_jsonl, get_ppid_uid, get_exe_path

OUT_JSONL = "data/raw/events.jsonl"
IGNORE_LOOPBACK = True

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/sched.h>

#define AF_INET  2
#define AF_INET6 10

struct ipv4_event_t {
    u64  ts_ns;
    u32  pid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    u32  saddr;
    u32  daddr;
    u16  sport;
    u16  dport;
};

struct ipv6_event_t {
    u64  ts_ns;
    u32  pid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    u8   saddr[16];
    u8   daddr[16];
    u16  sport;
    u16  dport;
};

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(ipv4_events);
BPF_PERF_OUTPUT(ipv6_events);

int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    currsock.update(&tid, &sk);
    return 0;
}

int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    currsock.update(&tid, &sk);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct sock **skpp = currsock.lookup(&tid);
    if (!skpp) return 0;
    currsock.delete(&tid);

    if (ret != 0) return 0;

    struct sock *sk = *skpp;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    struct ipv4_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid   = bpf_get_current_pid_tgid() >> 32;
    ev.uid   = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    bpf_probe_read(&ev.saddr, sizeof(ev.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&ev.daddr, sizeof(ev.daddr), &sk->__sk_common.skc_daddr);

    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read(&ev.sport, sizeof(ev.sport), &inet->inet_sport);
    bpf_probe_read(&ev.dport, sizeof(ev.dport), &sk->__sk_common.skc_dport);

    ipv4_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

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

running = True


def ensure_data_dir():
    os.makedirs("data/raw", exist_ok=True)


def stop(signum, frame):
    global running
    running = False


def is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "::1"


def main():
    ensure_data_dir()

    b = BPF(text=BPF_PROGRAM)

    b.attach_kprobe(event="tcp_v4_connect",    fn_name="trace_connect_v4_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")

    ipv6_enabled = True
    try:
        b.attach_kprobe(event="tcp_v6_connect",    fn_name="trace_connect_v6_entry")
        b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
    except Exception:
        ipv6_enabled = False
        print("[!] tcp_v6_connect unavailable — IPv6 monitoring disabled.")

    def handle_ipv4(cpu, data, size):
        ev = b["ipv4_events"].event(data)

        pid  = int(ev.pid)
        uid  = int(ev.uid)
        comm = ev.comm.decode(errors="replace")

        src_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", ev.saddr))
        dst_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", ev.daddr))

        sport = socket.ntohs(ev.sport)
        dport = socket.ntohs(ev.dport)

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
                "af":           "ipv4",
                "src_ip":       src_ip,
                "src_port":     sport,
                "dst_ip":       dst_ip,
                "dst_port":     dport,
                "kernel_ts_ns": int(ev.ts_ns),
            },
        )

        write_jsonl(OUT_JSONL, evt)

    def handle_ipv6(cpu, data, size):
        ev = b["ipv6_events"].event(data)

        pid  = int(ev.pid)
        uid  = int(ev.uid)
        comm = ev.comm.decode(errors="replace")

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

    b["ipv4_events"].open_perf_buffer(handle_ipv4)
    if ipv6_enabled:
        b["ipv6_events"].open_perf_buffer(handle_ipv6)

    print(f"[+] Network Monitor running. Writing JSONL to {OUT_JSONL}")
    print(f"[+] IPv6: {'enabled' if ipv6_enabled else 'disabled'}. "
          f"Loopback filter: {'on' if IGNORE_LOOPBACK else 'off'}.")
    print("[+] Press Ctrl+C to stop.")

    signal.signal(signal.SIGINT,  stop)
    signal.signal(signal.SIGTERM, stop)

    while running:
        b.perf_buffer_poll(timeout=1000)

    print("[+] Stopped.")


if __name__ == "__main__":
    main()
