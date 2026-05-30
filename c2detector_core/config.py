"""Generic analyzer configuration and constants."""

from dataclasses import dataclass


VERSION = "0.2.0"

HTTP_METHODS = {
    b"GET",
    b"POST",
    b"PUT",
    b"HEAD",
    b"DELETE",
    b"OPTIONS",
    b"PATCH",
}

SUSPICIOUS_USER_AGENT_TOKENS = (
    "curl",
    "wget",
    "python-requests",
    "go-http-client",
    "libwww-perl",
    "powershell",
    "winhttp",
    "java/",
    "okhttp",
    "axios",
    "node-fetch",
)

DEFAULT_ATTACK_MAP = [
    "T1071.001 Web Protocols",
    "T1105 Ingress Tool Transfer",
    "T1041 Exfiltration Over C2 Channel",
]


@dataclass
class AnalysisConfig:
    min_beacon_count: int = 4
    max_jitter_ratio: float = 0.25
    min_sleep_seconds: float = 2.0
    max_sleep_seconds: float = 900.0
    extract_http_objects: bool = True
