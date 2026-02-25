EVENT_VERSION = "1.0"

REQUIRED_TOP_LEVEL_KEYS = {
    "version",
    "event_id",
    "event_type",
    "ts_ns",
    "host",
    "process",
    "data",
}

REQUIRED_PROCESS_KEYS = {
    "pid",
    "ppid",
    "uid",
    "comm",
    "exe",
}

REQUIRED_HOST_KEYS = {
    "hostname",
    "kernel_release",
}
