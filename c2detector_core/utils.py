"""Small formatting and parsing helpers."""

import statistics
from datetime import datetime, timezone

from c2detector_core.config import SUSPICIOUS_USER_AGENT_TOKENS


def iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def format_seconds(seconds: float) -> str:
    if seconds >= 60:
        return f"{seconds / 60:.1f}m"
    if seconds >= 10:
        return f"{seconds:.0f}s"
    return f"{seconds:.1f}s"


def confidence_from_score(score: int) -> str:
    if score >= 80:
        return "High"
    if score >= 55:
        return "Medium"
    return "Low"


def median_interval(timestamps: list[float]) -> tuple[float, float]:
    if len(timestamps) < 2:
        return (0.0, 0.0)
    intervals = [
        round(timestamps[i] - timestamps[i - 1], 6)
        for i in range(1, len(timestamps))
        if timestamps[i] >= timestamps[i - 1]
    ]
    if not intervals:
        return (0.0, 0.0)
    median = statistics.median(intervals)
    if len(intervals) == 1:
        return (median, 0.0)
    mad = statistics.median(abs(value - median) for value in intervals)
    jitter_ratio = mad / median if median else 1.0
    return (median, jitter_ratio)


def is_suspicious_user_agent(user_agent: str) -> bool:
    normalized = user_agent.strip().lower()
    if not normalized:
        return True
    return any(token in normalized for token in SUSPICIOUS_USER_AGENT_TOKENS)


def normalize_header_name(name: str) -> str:
    return name.strip().lower()


def parse_headers(header_lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    current_name = ""
    for raw_line in header_lines:
        if not raw_line:
            continue
        if raw_line[0] in " \t" and current_name:
            headers[current_name] = f"{headers[current_name]} {raw_line.strip()}"
            continue
        if ":" not in raw_line:
            continue
        name, value = raw_line.split(":", 1)
        current_name = normalize_header_name(name)
        headers[current_name] = value.strip()
    return headers


def format_headers_for_timeline(headers: dict[str, str]) -> str:
    interesting = []
    for name in ("host", "user-agent", "content-type", "content-length"):
        if name in headers:
            interesting.append(f"{name}={headers[name]}")
    return "; ".join(interesting)


def guess_extension(content_type: str) -> str:
    lowered = content_type.lower()
    if "json" in lowered:
        return ".json"
    if "html" in lowered:
        return ".html"
    if "text" in lowered:
        return ".txt"
    if "javascript" in lowered:
        return ".js"
    if "xml" in lowered:
        return ".xml"
    return ".bin"
