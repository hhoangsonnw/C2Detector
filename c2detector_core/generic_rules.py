"""Framework-neutral C2 behavior heuristics."""

from c2detector_core.config import AnalysisConfig
from c2detector_core.engine import DetectionRule
from c2detector_core.models import AnalysisResult, Finding, HTTPRequest, SuspiciousFlow, TLSClientHello
from c2detector_core.utils import (
    confidence_from_score,
    format_seconds,
    is_suspicious_user_agent,
    median_interval,
)


class GenericHTTPBeaconRule(DetectionRule):
    rule_id = "generic-http-beacon"
    name = "Generic HTTP beaconing"

    def evaluate(self, result: AnalysisResult, config: AnalysisConfig) -> list[Finding]:
        grouped: dict[tuple[str, str, int, str, str, str], list[HTTPRequest]] = {}
        for request in result.http_requests:
            grouped.setdefault(request.endpoint_key, []).append(request)

        findings: list[Finding] = []
        index = 1
        for key, requests in grouped.items():
            if len(requests) < config.min_beacon_count:
                continue
            requests = sorted(requests, key=lambda item: item.timestamp)
            timestamps = [request.timestamp for request in requests]
            sleep, jitter = median_interval(timestamps)
            if not (config.min_sleep_seconds <= sleep <= config.max_sleep_seconds):
                continue
            if jitter > config.max_jitter_ratio:
                continue

            src, dst, dport, host_header, method, uri = key
            user_agents = sorted({request.user_agent for request in requests})
            body_sizes = [request.body_len for request in requests]
            stable_body = len(set(body_sizes)) <= max(2, len(body_sizes) // 3)
            suspicious_ua = any(is_suspicious_user_agent(ua) for ua in user_agents)

            score = 35
            score += min(20, len(requests) * 3)
            score += 20
            if method == "POST":
                score += 10
            if suspicious_ua:
                score += 10
            if stable_body:
                score += 5
            score = min(score, 100)

            evidence = [
                f"{len(requests)} repeated {method} requests to the same endpoint",
                f"Fixed sleep interval: ~{format_seconds(sleep)} (jitter ratio {jitter:.2f})",
                f"Destination: {dst}:{dport} host={host_header or '<missing>'} uri={uri}",
            ]
            if method == "POST":
                evidence.append("Repeated POST requests can indicate tasking or check-in traffic")
            if suspicious_ua:
                evidence.append(
                    "User-Agent anomaly: "
                    + ", ".join(ua or "<missing>" for ua in user_agents[:4])
                )
            if stable_body:
                evidence.append("HTTP payload sizes are comparatively stable across check-ins")
            evidence.append("HTTP pattern match: periodic same-endpoint beaconing")

            finding_id = f"HTTP-{index:03d}"
            flow = SuspiciousFlow(
                finding_id=finding_id,
                host=src,
                possible_c2="Generic HTTP beaconing",
                confidence=confidence_from_score(score),
                score=score,
                src=src,
                sport="*",
                dst=dst,
                dport=str(dport),
                protocol="HTTP",
                first_seen=requests[0].timestamp,
                last_seen=requests[-1].timestamp,
                request_count=len(requests),
                median_interval=f"{sleep:.3f}",
                method=method,
                host_header=host_header,
                uri=uri,
                evidence=evidence,
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    suspicious_host=src,
                    possible_c2="Generic HTTP beaconing",
                    confidence=confidence_from_score(score),
                    score=score,
                    first_seen=requests[0].timestamp,
                    last_seen=requests[-1].timestamp,
                    evidence=evidence,
                    suspicious_flows=[flow],
                )
            )
            index += 1
        return findings


class GenericTLSBeaconRule(DetectionRule):
    rule_id = "generic-tls-ja3-beacon"
    name = "Generic TLS JA3 beaconing"

    def evaluate(self, result: AnalysisResult, config: AnalysisConfig) -> list[Finding]:
        grouped: dict[tuple[str, str, int, str, str], list[TLSClientHello]] = {}
        for hello in result.tls_client_hellos:
            grouped.setdefault(hello.endpoint_key, []).append(hello)

        findings: list[Finding] = []
        index = 1
        for key, hellos in grouped.items():
            if len(hellos) < config.min_beacon_count:
                continue
            hellos = sorted(hellos, key=lambda item: item.timestamp)
            timestamps = [hello.timestamp for hello in hellos]
            sleep, jitter = median_interval(timestamps)
            if not (config.min_sleep_seconds <= sleep <= config.max_sleep_seconds):
                continue
            if jitter > config.max_jitter_ratio:
                continue

            src, dst, dport, sni, ja3_hash = key
            score = min(100, 55 + min(25, len(hellos) * 3) + 15)
            evidence = [
                f"{len(hellos)} repeated TLS ClientHello events to the same destination",
                f"Fixed sleep interval: ~{format_seconds(sleep)} (jitter ratio {jitter:.2f})",
                f"JA3/TLS pattern match: {ja3_hash}",
                f"SNI: {sni or '<missing>'}",
            ]
            finding_id = f"TLS-{index:03d}"
            flow = SuspiciousFlow(
                finding_id=finding_id,
                host=src,
                possible_c2="Generic TLS beaconing",
                confidence=confidence_from_score(score),
                score=score,
                src=src,
                sport="*",
                dst=dst,
                dport=str(dport),
                protocol="TLS",
                first_seen=hellos[0].timestamp,
                last_seen=hellos[-1].timestamp,
                request_count=len(hellos),
                median_interval=f"{sleep:.3f}",
                ja3_hash=ja3_hash,
                sni=sni,
                evidence=evidence,
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    suspicious_host=src,
                    possible_c2="Generic TLS beaconing",
                    confidence=confidence_from_score(score),
                    score=score,
                    first_seen=hellos[0].timestamp,
                    last_seen=hellos[-1].timestamp,
                    evidence=evidence,
                    suspicious_flows=[flow],
                )
            )
            index += 1
        return findings
