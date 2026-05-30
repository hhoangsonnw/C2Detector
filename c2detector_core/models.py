"""Normalized artifacts shared by parsers, detectors, and report writers."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PacketEvent:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    wire_len: int
    payload_len: int
    tcp_flags: str = ""
    tcp_seq: int = 0
    tcp_ack: int = 0
    payload: bytes = b""

    @property
    def flow_id(self) -> str:
        return f"{self.src}:{self.sport}->{self.dst}:{self.dport}/{self.protocol}"


@dataclass(frozen=True)
class HTTPMessage:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    message_type: str
    start_line: str
    headers: dict[str, str]
    body: bytes

    @property
    def host(self) -> str:
        return self.headers.get("host", "")

    @property
    def user_agent(self) -> str:
        return self.headers.get("user-agent", "")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


@dataclass(frozen=True)
class HTTPRequest:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    method: str
    uri: str
    version: str
    headers: dict[str, str]
    body_len: int
    body: bytes = b""

    @property
    def host(self) -> str:
        return self.headers.get("host", "")

    @property
    def user_agent(self) -> str:
        return self.headers.get("user-agent", "")

    @property
    def endpoint_key(self) -> tuple[str, str, int, str, str, str]:
        return (self.src, self.dst, self.dport, self.host, self.method, self.uri)


@dataclass(frozen=True)
class TLSClientHello:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    tls_version: int
    sni: str
    alpn: tuple[str, ...]
    ja3: str
    ja3_hash: str

    @property
    def endpoint_key(self) -> tuple[str, str, int, str, str]:
        return (self.src, self.dst, self.dport, self.sni, self.ja3_hash)


@dataclass
class HTTPObject:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    object_type: str
    content_type: str
    body: bytes
    source_line: str
    filename: str = ""
    sha256: str = ""

    @property
    def size(self) -> int:
        return len(self.body)


@dataclass
class FlowSummary:
    src: str
    sport: int
    dst: str
    dport: int
    protocol: str
    packet_count: int = 0
    bytes_on_wire: int = 0
    payload_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


@dataclass
class TimelineEvent:
    timestamp: float
    event_type: str
    src: str = ""
    sport: str = ""
    dst: str = ""
    dport: str = ""
    protocol: str = ""
    summary: str = ""
    details: str = ""


@dataclass
class SuspiciousFlow:
    finding_id: str
    host: str
    possible_c2: str
    confidence: str
    score: int
    src: str
    sport: str
    dst: str
    dport: str
    protocol: str
    first_seen: float
    last_seen: float
    request_count: int = 0
    median_interval: str = ""
    method: str = ""
    host_header: str = ""
    uri: str = ""
    ja3_hash: str = ""
    sni: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)


@dataclass
class Finding:
    finding_id: str
    suspicious_host: str
    possible_c2: str
    confidence: str
    score: int
    first_seen: float
    last_seen: float
    evidence: list[str]
    suspicious_flows: list[SuspiciousFlow]
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    pcap_path: Path
    output_dir: Path
    total_packets: int = 0
    parsed_packets: int = 0
    unsupported_packets: int = 0
    flows: dict[str, FlowSummary] = field(default_factory=dict)
    tcp_segments: list[PacketEvent] = field(default_factory=list)
    http_requests: list[HTTPRequest] = field(default_factory=list)
    http_messages: list[HTTPMessage] = field(default_factory=list)
    tls_client_hellos: list[TLSClientHello] = field(default_factory=list)
    http_objects: list[HTTPObject] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    plugin_artifacts: dict[str, list[object]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
