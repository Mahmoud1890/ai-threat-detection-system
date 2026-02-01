from bcc import BPF
import time

program = """
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    bpf_trace_printk("EXEC:%s\\n", args->filename);
    return 0;
}
"""

b = BPF(text=program)

print("Logging process executions... Press Ctrl+C to stop.")

log_file = open("../data/events.log", "a")


try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        event = f"{time.time()} | PID {pid} | {msg}"
        print(event)
        log_file.write(event + "\n")
        log_file.flush()
except KeyboardInterrupt:
    print("\nStopped.")
    log_file.close()
