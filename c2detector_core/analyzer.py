"""Main analysis pipeline shared by all detector plugins."""

from c2detector_core.config import AnalysisConfig
from c2detector_core.engine import DetectionEngine
from c2detector_core.models import AnalysisResult, FlowSummary, HTTPObject, PacketEvent, TimelineEvent
from c2detector_core.pcap import PacketParser, PcapReader
from c2detector_core.protocols import HTTPStreamExtractor, ProtocolExtractor
from c2detector_core.utils import format_headers_for_timeline


class C2Analyzer:
    def __init__(self, config: AnalysisConfig, detection_engine: DetectionEngine):
        self.config = config
        self.detection_engine = detection_engine

    def analyze(self, pcap_path, output_dir) -> AnalysisResult:
        result = AnalysisResult(pcap_path=pcap_path, output_dir=output_dir)
        reader = PcapReader(pcap_path)

        for timestamp, raw_packet in reader:
            result.total_packets += 1
            event = PacketParser.parse(timestamp, raw_packet, reader.linktype)
            if event is None:
                result.unsupported_packets += 1
                continue
            result.parsed_packets += 1
            self._record_flow(result, event)
            self._record_transport_artifacts(result, event)

        self._record_http_streams(result)
        result.findings = self.detection_engine.evaluate(result, self.config)
        self._record_findings(result)
        result.timeline.sort(key=lambda item: item.timestamp)
        return result

    def _record_flow(self, result: AnalysisResult, event: PacketEvent) -> None:
        flow = result.flows.get(event.flow_id)
        if flow is None:
            flow = FlowSummary(
                src=event.src,
                sport=event.sport,
                dst=event.dst,
                dport=event.dport,
                protocol=event.protocol,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
            result.flows[event.flow_id] = flow
        flow.packet_count += 1
        flow.bytes_on_wire += event.wire_len
        flow.payload_bytes += event.payload_len
        flow.first_seen = min(flow.first_seen, event.timestamp)
        flow.last_seen = max(flow.last_seen, event.timestamp)

    def _record_transport_artifacts(self, result: AnalysisResult, event: PacketEvent) -> None:
        if event.protocol == "TCP" and event.payload:
            result.tcp_segments.append(event)

        tls_client_hello = ProtocolExtractor.extract_tls_client_hello(event)
        if tls_client_hello is not None:
            result.tls_client_hellos.append(tls_client_hello)
            result.timeline.append(
                TimelineEvent(
                    timestamp=tls_client_hello.timestamp,
                    event_type="tls_client_hello",
                    src=tls_client_hello.src,
                    sport=str(tls_client_hello.sport),
                    dst=tls_client_hello.dst,
                    dport=str(tls_client_hello.dport),
                    protocol="TLS",
                    summary=f"JA3 {tls_client_hello.ja3_hash}",
                    details=f"SNI={tls_client_hello.sni or '<missing>'} ALPN={','.join(tls_client_hello.alpn)}",
                )
            )

    def _record_http_streams(self, result: AnalysisResult) -> None:
        for http_message in HTTPStreamExtractor.extract(result.tcp_segments):
            result.http_messages.append(http_message)
            result.timeline.append(
                TimelineEvent(
                    timestamp=http_message.timestamp,
                    event_type=f"http_{http_message.message_type}",
                    src=http_message.src,
                    sport=str(http_message.sport),
                    dst=http_message.dst,
                    dport=str(http_message.dport),
                    protocol="HTTP",
                    summary=http_message.start_line,
                    details=format_headers_for_timeline(http_message.headers),
                )
            )

            if http_message.message_type == "request":
                request = ProtocolExtractor.http_request_from_message(http_message)
                if request is not None:
                    result.http_requests.append(request)

            if self.config.extract_http_objects and http_message.body:
                result.http_objects.append(
                    HTTPObject(
                        timestamp=http_message.timestamp,
                        src=http_message.src,
                        dst=http_message.dst,
                        sport=http_message.sport,
                        dport=http_message.dport,
                        object_type=f"http-{http_message.message_type}-body",
                        content_type=http_message.content_type,
                        body=http_message.body,
                        source_line=http_message.start_line,
                    )
                )

    def _record_findings(self, result: AnalysisResult) -> None:
        for finding in result.findings:
            result.timeline.append(
                TimelineEvent(
                    timestamp=finding.first_seen,
                    event_type="finding",
                    src=finding.suspicious_host,
                    protocol="C2",
                    summary=f"{finding.confidence} confidence: {finding.possible_c2}",
                    details="; ".join(finding.evidence[:3]),
                )
            )
