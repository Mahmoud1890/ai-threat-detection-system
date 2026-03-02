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

**Bugs found and fixed during Phase 1:**

**1. Infinite feedback loop — `file_access_monitor.py`**
The file monitor hooks every `openat` syscall system-wide. When it detected an event, it called `write_jsonl()` which internally called Python's `open()` on `data/raw/events.jsonl` — which is itself an `openat` syscall. The monitor intercepted that, called `write_jsonl()` again, which opened the file again, and so on indefinitely. This consumed all CPU and RAM until the machine crashed. Fixed by adding `"data/raw/"` to `IGNORED_PATH_PREFIXES`, so the monitor drops any `openat` on the output file before it ever reaches `write_jsonl()`.

**2. Cross-process write corruption — `events/builder.py`**
All three sensors write to the same `data/raw/events.jsonl`. The original locking mechanism used a `threading.Lock`, which only coordinates threads within a single process. Since each sensor runs as a separate process, each had its own independent lock instance with no awareness of the others — all three could write simultaneously, interleaving bytes and producing malformed JSON lines. Replaced with `fcntl.flock`, which is enforced by the OS at the filesystem level, guaranteeing sequential writes regardless of how many processes are involved.

**3. Redundant syscalls on every event — `events/builder.py`**
`_get_host_info()` called `socket.gethostname()` and `platform.release()` on every single event, even though hostname and kernel version never change during a run. Under the high event volume generated by the file monitor, this added thousands of unnecessary syscalls per second. Replaced with a module-level constant `_HOST_INFO` computed once at import time.

---

## Roadmap

### Phase 2 — ML Anomaly Detection
Score behavioral event clusters from `events.jsonl` to surface:
- Privilege escalation patterns
- Abnormal process execution chains
- Unexpected file access by unprivileged processes
- Anomalous outbound connections

**Dataset: BETH (Behaviour and Event Tracing for Hosts)**
Collected from a real AWS honeypot. 763k labeled training rows, 188k validation rows, 188k test rows.

| Column | Type | Description |
|---|---|---|
| `timestamp` | float | Seconds since reference point |
| `processId` | int | PID of the process |
| `threadId` | int | Thread ID |
| `parentProcessId` | int | PPID of the process |
| `userId` | int | UID of the process |
| `mountNamespace` | int | Linux mount namespace ID |
| `processName` | str | Process name (equivalent to `comm`) |
| `hostName` | str | Machine hostname |
| `eventId` | int | Numeric syscall ID |
| `eventName` | str | Syscall name (`close`, `openat`, `kill`, etc.) |
| `stackAddresses` | list | Memory addresses on the call stack |
| `argsNum` | int | Number of syscall arguments |
| `returnValue` | int | Syscall return value (negative = error) |
| `args` | str | Full syscall arguments |
| `sus` | int | Label: 1 = suspicious |
| `evil` | int | Label: 1 = malicious |

**Approach:** Supervised — train on BETH `sus` labels, evaluate on test set with `evil` labels. Model learns known attack patterns from real honeypot data. Engineer feedback stored in PostgreSQL and used for periodic retraining (active learning loop).

**Generating the model:**

The trained model artifact (`models/detector.joblib`) is not committed to the repository. To generate it locally:

1. Download the BETH dataset from Kaggle (`katehighnam/beth-dataset`) and place the CSV files in `data/raw/`
2. Activate the virtual environment: `source .venv/bin/activate`
3. Run the training script: `python ml/train.py`

The trained model will be saved to `models/detector.joblib`.

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
├── ml/
│   └── train.py                 # trains anomaly detector on BETH dataset
├── models/
│   └── detector.joblib          # trained model (not committed — run ml/train.py)
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

## Virtual Environment

The project uses a `.venv` to isolate Python packages from the system. Without it, installing packages globally risks conflicting with dependencies that Ubuntu itself relies on — which can break the OS. The venv acts as a sandbox: packages installed inside it are completely separate from system packages and can't interfere with anything else on the machine.

**Two separate Python environments are in use:**

| What | Python | Why |
|------|--------|-----|
| eBPF sensors | System `python3` | Requires `python3-bcc` installed via `apt` — not available inside the venv |
| Everything else (ML, kaggle, pytest, Claude API) | `.venv` | All project packages live here |

The venv must be activated once per terminal session before running any non-sensor code:

```bash
source .venv/bin/activate
```

Packages stay installed permanently — activation just tells the shell to use `.venv/bin/` instead of the system Python.

**Why `source` and not `cd` or `./`?**

`cd` only changes your working directory — it has nothing to do with running scripts. `./venv/bin/activate` would run `activate` as a child process, which exits immediately, and any environment changes it makes (like updating `PATH`) die with it. `source` (or equivalently `. file`) runs the script directly in your current shell session, so its changes — pointing `PATH` to `.venv/bin/`, updating the prompt — actually stick. This is why `activate` must always be sourced and never just executed.

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
