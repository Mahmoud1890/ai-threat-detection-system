# AI-Augmented Endpoint Detection & Response (EDR)

A Linux threat detection system that operates at the kernel level — where attacks happen before any userspace tool can see them. eBPF sensors capture real-time kernel telemetry, an ML anomaly detection layer scores behavioral event clusters, and the Claude API acts as an automated triage engine that produces plain-English analyst reports with severity classification and concrete remediation steps.

---

## Overview

Most security tools sit in userspace and observe what the OS chooses to expose. This system hooks directly into the Linux kernel via eBPF, intercepting syscalls at the source. Every process execution, file access, and outbound TCP connection is captured, normalized, and streamed into a unified behavioral event log — with no agent overhead and no userspace blind spots.

The pipeline is fully automated. Raw kernel telemetry flows into an ML anomaly detector, flagged events are triaged by an LLM, and analysts receive finished intelligence surfaced as live tickets on a real-time dashboard. No manual log parsing. No alert fatigue from raw data.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Linux Kernel                       │
│  execve tracepoint · open/openat kprobes             │
│  tcp_v4_connect / tcp_v6_connect kretprobes          │
└────────────────────┬────────────────────────────────┘
                     │ eBPF perf buffer
┌────────────────────▼────────────────────────────────┐
│              Sensor Layer  (ebpf/)                   │
│  process_exec_logger.py                              │
│  file_access_monitor.py                              │
│  network_monitor.py                                  │
└────────────────────┬────────────────────────────────┘
                     │ build_event() · write_jsonl()
┌────────────────────▼────────────────────────────────┐
│            Event Pipeline  (events/)                 │
│  schema.py     — versioned schema + required keys    │
│  builder.py    — normalization, /proc enrichment,    │
│                  UUID + nanosecond timestamps,        │
│                  thread-safe JSONL append             │
└────────────────────┬────────────────────────────────┘
                     │ data/raw/events.jsonl
┌────────────────────▼────────────────────────────────┐
│          ML Anomaly Detection  (coming)              │
│  Scores behavioral event clusters                    │
│  Flags: privilege escalation · abnormal exec chains  │
│         unexpected outbound connections              │
└────────────────────┬────────────────────────────────┘
                     │ flagged events
┌────────────────────▼────────────────────────────────┐
│           Claude API Triage Engine  (coming)         │
│  Automated — no human prompt required                │
│  Output: severity · plain-English report             │
│          remediation (kill · firewall · code patch)  │
└────────────────────┬────────────────────────────────┘
                     │ structured alert
┌────────────────────▼────────────────────────────────┐
│         Analyst Dashboard  (coming)                  │
│  FastAPI · React · PostgreSQL · WebSockets           │
│  Per-anomaly tickets with 3 engineer actions:        │
│  [Integrate Fix]  [Fix Manually]  [Delete]           │
└─────────────────────────────────────────────────────┘
```

---

## What's Built

### Phase 1 — eBPF Sensor Layer + Event Pipeline ✅

**Three concurrent eBPF sensors:**

| Sensor | Hook Type | Syscall | Event Type |
|---|---|---|---|
| `process_exec_logger.py` | Tracepoint | `sys_enter_execve` | `process_exec` |
| `file_access_monitor.py` | kprobe | `open` / `openat` | `file_open` |
| `network_monitor.py` | kprobe + kretprobe | `tcp_v4_connect` / `tcp_v6_connect` | `net_connect` |

Each sensor captures kernel-side data via BCC perf buffers and hands it to the event pipeline for enrichment and persistence.

**Event pipeline (`events/`):**
- `schema.py` — defines `EVENT_VERSION` and required key sets for `top-level`, `process`, and `host` fields
- `builder.py` — `build_event()` constructs a fully validated event with UUID, nanosecond timestamp, and hostname/kernel metadata; `write_jsonl()` appends atomically to `data/raw/events.jsonl` via a module-level `threading.Lock` shared across all sensors; `get_ppid_uid()` reads PPID and UID from `/proc/<pid>/status`; `get_exe_path()` resolves the full executable path via `/proc/<pid>/exe`

**Signal quality:**
- Loopback traffic suppressed (`127.x`, `::1`)
- Virtual filesystem noise filtered (`/proc`, `/sys`, `/dev`, `/run`)
- `open` flags decoded to human-readable form (`O_RDONLY`, `O_WRONLY`, `O_CREAT`, `O_TRUNC`, `O_APPEND`, etc.)
- Race-condition-safe `/proc` reads — returns `(0, 0)` on process exit, treated as unknown rather than root

**Unified event schema (every event):**
```json
{
  "version": "1.0",
  "event_id": "<uuid4>",
  "event_type": "process_exec | file_open | net_connect",
  "ts_ns": 1700000000000000000,
  "host": { "hostname": "...", "kernel_release": "..." },
  "process": { "pid": 0, "ppid": 0, "uid": 0, "comm": "...", "exe": "..." },
  "data": { ... }
}
```

---

## Roadmap

### Phase 2 — ML Anomaly Detection
Score behavioral event clusters from `events.jsonl` to surface:
- Privilege escalation patterns
- Abnormal process execution chains
- Unexpected file access by unprivileged processes
- Anomalous outbound connections

### Phase 3 — Claude API Triage Engine
Pass flagged event clusters to the Claude API as structured context. Claude generates:
- Plain-English analyst report
- Severity classification
- Concrete remediation: process kill commands, `iptables` rules, or code-level patches — depending on threat type

Fully automated. No human prompt in the loop.

### Phase 4 — Real-Time Analyst Dashboard
FastAPI backend · React frontend · PostgreSQL · WebSockets

Every anomaly creates a ticket. Each ticket surfaces:
- LLM-generated explanation and severity
- Process, file, and network event details
- Three engineer actions:
  - **Integrate Fix** — auto-applies Claude's remediation
  - **Fix Manually** — marks in-progress for manual handling
  - **Delete** — dismiss as false positive

Tickets update in real time via WebSockets.

### Phase 5 — Cloud Deployment
Containerize all layers — instrumentation, detection, AI triage, dashboard — and deploy to cloud via Docker and CI/CD pipeline.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Kernel instrumentation | eBPF, BCC |
| Sensors + pipeline | Python |
| ML detection | Python (scikit-learn / PyTorch) |
| LLM triage | Claude API (Anthropic) |
| Backend | FastAPI |
| Frontend | React |
| Database | PostgreSQL |
| Real-time updates | WebSockets |
| Deployment | Docker, CI/CD |

---

## Project Structure

```
ai-threat-detection-system/
├── ebpf/
│   ├── process_exec_logger.py   # execve tracepoint sensor
│   ├── file_access_monitor.py   # open/openat kprobe sensor
│   └── network_monitor.py       # tcp connect kprobe sensor
├── events/
│   ├── schema.py                # event schema + required key constants
│   └── builder.py               # normalization, validation, JSONL write
└── data/
    └── raw/
        └── events.jsonl         # unified behavioral event log
```

---

## Requirements

- Linux kernel 4.9+ with BPF support
- Python 3.8+
- [BCC](https://github.com/iovisor/bcc) (`bcc-tools`, `python3-bpfcc`)
- Root privileges (required for eBPF kernel hooks)

---

## Running the Sensors

Each sensor is independent and can run concurrently. All three write to the same `data/raw/events.jsonl` using a shared thread-safe lock.

```bash
# Run all three sensors concurrently (each in its own terminal, as root)
sudo python3 -m ebpf.process_exec_logger
sudo python3 -m ebpf.file_access_monitor
sudo python3 -m ebpf.network_monitor
```

Events are appended to `data/raw/events.jsonl` in real time.

---

## Author

**Mahmoud Amin** — Computer Engineering, McGill University
[LinkedIn](https://www.linkedin.com/in/mahmoudamin1/) · [GitHub](https://github.com/Mahmoud1890)
