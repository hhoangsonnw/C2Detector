"""DFIR artifact writers."""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import json
import os
import shutil
import string
import sys

from c2detector_core.models import AnalysisResult
from c2detector_core.utils import guess_extension, iso_time


MAX_CONSOLE_DECRYPT_BYTES = 12000
MIN_TEXT_OBJECT_BYTES = 32
CONSOLE_COLOR_MODE = "auto"

ANSI_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}


FILE_SIGNATURES = [
    (b"MZ", ".exe", "Windows PE executable"),
    (b"PK\x03\x04", ".zip", "ZIP archive"),
    (b"7z\xbc\xaf\x27\x1c", ".7z", "7-Zip archive"),
    (b"\x1f\x8b", ".gz", "Gzip archive"),
    (b"BZh", ".bz2", "Bzip2 archive"),
    (b"Rar!\x1a\x07\x00", ".rar", "RAR archive"),
    (b"%PDF-", ".pdf", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".ole", "OLE compound document"),
    (b"\x89PNG\r\n\x1a\n", ".png", "PNG image"),
    (b"\xff\xd8\xff", ".jpg", "JPEG image"),
    (b"GIF87a", ".gif", "GIF image"),
    (b"GIF89a", ".gif", "GIF image"),
    (b"<?xml", ".xml", "XML text"),
    (b"<html", ".html", "HTML text"),
    (b"<!doctype html", ".html", "HTML text"),
]


def configure_console_colors(mode: str) -> None:
    global CONSOLE_COLOR_MODE
    CONSOLE_COLOR_MODE = mode


def console_colors_enabled() -> bool:
    if CONSOLE_COLOR_MODE == "always":
        return True
    if CONSOLE_COLOR_MODE == "never":
        return False
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def colorize(value: object, *styles: str) -> str:
    text = str(value)
    if not styles or not console_colors_enabled():
        return text
    codes = [ANSI_CODES[style] for style in styles if style in ANSI_CODES]
    if not codes:
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def success(value: object) -> str:
    return colorize(value, "green", "bold")


def warning(value: object) -> str:
    return colorize(value, "yellow", "bold")


def danger(value: object) -> str:
    return colorize(value, "red", "bold")


def muted(value: object) -> str:
    return colorize(value, "dim")


def info(value: object) -> str:
    return colorize(value, "cyan")


def confidence_style(confidence: str) -> str:
    normalized = confidence.strip().lower()
    if normalized == "high":
        return danger(confidence)
    if normalized == "medium":
        return warning(confidence)
    if normalized == "low":
        return success(confidence)
    return colorize(confidence, "bold")


class ReportWriter:
    def write(self, result: AnalysisResult) -> None:
        result.output_dir.mkdir(parents=True, exist_ok=True)
        for legacy_dir in ("extracted_http_objects", "havoc_decrypted", "nimplant_decrypted"):
            path = result.output_dir / legacy_dir
            if path.exists():
                shutil.rmtree(path)
        if not result.plugin_artifacts.get("artifact_index_written"):
            (result.output_dir / "index.csv").unlink(missing_ok=True)
        if not result.plugin_artifacts.get("carved_artifacts_written"):
            path = result.output_dir / "carved_artifacts"
            if path.exists():
                shutil.rmtree(path)

        self._write_timeline(result)
        self._write_suspicious_flows(result)
        self._write_report(result)

    def _write_http_objects(self, result: AnalysisResult, object_dir) -> None:
        object_index_rows: list[dict[str, str]] = []
        for index, obj in enumerate(result.http_objects, start=1):
            obj.sha256 = hashlib.sha256(obj.body).hexdigest()
            triage = triage_http_object(obj.body, obj.content_type)
            obj.filename = ""
            if triage["status"] == "saved":
                obj.filename = f"object_{index:04d}_{obj.sha256[:12]}{triage['extension']}"
                object_path = object_dir / obj.filename
                object_path.write_bytes(obj.body)
            object_index_rows.append(
                {
                    "timestamp": iso_time(obj.timestamp),
                    "src": obj.src,
                    "sport": str(obj.sport),
                    "dst": obj.dst,
                    "dport": str(obj.dport),
                    "object_type": obj.object_type,
                    "content_type": obj.content_type,
                    "size": str(obj.size),
                    "sha256": obj.sha256,
                    "status": triage["status"],
                    "artifact_type": triage["artifact_type"],
                    "filename": obj.filename,
                    "reason": triage["reason"],
                    "source_line": obj.source_line,
                }
            )

        index_path = object_dir / "index.csv"
        with index_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "timestamp",
                    "src",
                    "sport",
                    "dst",
                    "dport",
                    "object_type",
                    "content_type",
                    "size",
                    "sha256",
                    "status",
                    "artifact_type",
                    "filename",
                    "reason",
                    "source_line",
                ],
            )
            writer.writeheader()
            writer.writerows(object_index_rows)

    def _write_timeline(self, result: AnalysisResult) -> None:
        path = result.output_dir / "timeline.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "timestamp_utc",
                    "timestamp_epoch",
                    "event_type",
                    "src",
                    "sport",
                    "dst",
                    "dport",
                    "protocol",
                    "summary",
                    "details",
                ],
            )
            writer.writeheader()
            for event in sorted(result.timeline, key=lambda item: item.timestamp):
                writer.writerow(
                    {
                        "timestamp_utc": iso_time(event.timestamp),
                        "timestamp_epoch": f"{event.timestamp:.6f}",
                        "event_type": event.event_type,
                        "src": event.src,
                        "sport": event.sport,
                        "dst": event.dst,
                        "dport": event.dport,
                        "protocol": event.protocol,
                        "summary": event.summary,
                        "details": event.details,
                    }
                )

    def _write_suspicious_flows(self, result: AnalysisResult) -> None:
        path = result.output_dir / "suspicious_flows.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "finding_id",
                    "host",
                    "possible_c2",
                    "confidence",
                    "score",
                    "src",
                    "sport",
                    "dst",
                    "dport",
                    "protocol",
                    "first_seen_utc",
                    "last_seen_utc",
                    "request_count",
                    "median_interval_seconds",
                    "method",
                    "host_header",
                    "uri",
                    "ja3_hash",
                    "sni",
                    "metadata",
                    "evidence",
                ],
            )
            writer.writeheader()
            for finding in result.findings:
                for flow in finding.suspicious_flows:
                    writer.writerow(
                        {
                            "finding_id": flow.finding_id,
                            "host": flow.host,
                            "possible_c2": flow.possible_c2,
                            "confidence": flow.confidence,
                            "score": str(flow.score),
                            "src": flow.src,
                            "sport": flow.sport,
                            "dst": flow.dst,
                            "dport": flow.dport,
                            "protocol": flow.protocol,
                            "first_seen_utc": iso_time(flow.first_seen),
                            "last_seen_utc": iso_time(flow.last_seen),
                            "request_count": str(flow.request_count),
                            "median_interval_seconds": flow.median_interval,
                            "method": flow.method,
                            "host_header": flow.host_header,
                            "uri": flow.uri,
                            "ja3_hash": flow.ja3_hash,
                            "sni": flow.sni,
                            "metadata": json.dumps(flow.metadata, sort_keys=True),
                            "evidence": " | ".join(flow.evidence),
                        }
                    )

    def _write_report(self, result: AnalysisResult) -> None:
        path = result.output_dir / "report.md"
        lines = [
            "# C2Detector DFIR Report",
            "",
            "## Executive Summary",
            "",
        ]
        if result.findings:
            lines.append(
                f"C2Detector identified {len(result.findings)} suspicious C2-like pattern(s) in `{result.pcap_path}`."
            )
        else:
            lines.append(
                f"No C2-like behavior was identified by the current rules in `{result.pcap_path}`."
            )
        lines.extend(
            [
                "",
                "## Capture Summary",
                "",
                f"- Total packets observed: {result.total_packets}",
                f"- Parsed IPv4 TCP/UDP packets: {result.parsed_packets}",
                f"- Unsupported or skipped packets: {result.unsupported_packets}",
                f"- Flow records: {len(result.flows)}",
                f"- HTTP requests: {len(result.http_requests)}",
                f"- TLS ClientHello records: {len(result.tls_client_hellos)}",
                f"- Extracted HTTP objects: {len(result.http_objects)}",
                "",
                "## Findings",
                "",
            ]
        )

        if not result.findings:
            lines.extend(
                [
                    "No findings were generated. Add framework-specific plugins or lower the beacon thresholds if this capture is known malicious.",
                    "",
                ]
            )
        for finding in result.findings:
            lines.extend(
                [
                    f"### {finding.finding_id}: {finding.possible_c2}",
                    "",
                    f"- Suspicious host: `{finding.suspicious_host}`",
                    f"- Confidence: **{finding.confidence}** ({finding.score}/100)",
                    f"- First seen: {iso_time(finding.first_seen)}",
                    f"- Last seen: {iso_time(finding.last_seen)}",
                    "",
                    "Evidence:",
                ]
            )
            lines.extend(f"- {item}" for item in finding.evidence)
            lines.append("")

        for section in result.plugin_artifacts.get("report_sections", []):
            lines.extend([section.rstrip(), ""])

        lines.extend(
            [
                "## Generated Artifacts",
                "",
                "- `timeline.csv`: normalized HTTP, TLS, and finding timeline",
                "- `suspicious_flows.csv`: one row per suspicious flow or endpoint pattern",
                "- `index.csv`: carved artifact index when framework plugins recover files",
                "- `carved_artifacts/`: decoded screenshots, transfers, and other recovered files",
                "",
                "## Notes and Limitations",
                "",
                "- This backbone parses `.pcap` and `.pcapng` files with Ethernet or raw IPv4 link types.",
                "- HTTP parsing uses lightweight directional TCP stream reassembly, not a full TCP engine.",
                "- TLS JA3 is derived from visible ClientHello records only; encrypted payloads are not decrypted.",
                "- Framework-specific C2 logic lives in detector plugins under `plugins/`.",
                "",
            ]
        )
        path.write_text("\n".join(lines), encoding="utf-8")


def triage_http_object(body: bytes, content_type: str) -> dict[str, str]:
    if "ocsp-response" in content_type.lower():
        return {
            "status": "filtered",
            "extension": "",
            "artifact_type": "OCSP response",
            "reason": "certificate status response, not a standalone investigation artifact",
        }

    signature = detect_file_signature(body)
    if signature is not None:
        extension, artifact_type = signature
        return {
            "status": "saved",
            "extension": extension,
            "artifact_type": artifact_type,
            "reason": "recognized file header",
        }

    text_type = detect_text_artifact(body, content_type)
    if text_type is not None:
        extension, artifact_type = text_type
        return {
            "status": "saved",
            "extension": extension,
            "artifact_type": artifact_type,
            "reason": "readable text artifact",
        }

    if looks_like_havoc_wire_body(body):
        return {
            "status": "filtered",
            "extension": "",
            "artifact_type": "Havoc protocol body",
            "reason": "protocol body is handled by framework-specific artifact carving",
        }

    if looks_like_nimplant_wire_body(body):
        return {
            "status": "filtered",
            "extension": "",
            "artifact_type": "Nimplant protocol body",
            "reason": "protocol body is handled by framework-specific artifact carving",
        }

    if len(body) < MIN_TEXT_OBJECT_BYTES:
        return {
            "status": "filtered",
            "extension": "",
            "artifact_type": "small response body",
            "reason": f"too small for standalone object ({len(body)} bytes)",
        }

    return {
        "status": "filtered",
        "extension": "",
        "artifact_type": "unknown binary",
        "reason": "unknown header or low-value protocol payload",
    }


def detect_file_signature(body: bytes) -> tuple[str, str] | None:
    if body.startswith(b"PK\x03\x04"):
        return classify_zip_payload(body)

    lowered = body[:32].lower()
    for signature, extension, artifact_type in FILE_SIGNATURES:
        if lowered.startswith(signature.lower()):
            return (extension, artifact_type)
    if body.startswith(b"-----BEGIN CERTIFICATE-----"):
        return (".pem", "PEM certificate")
    if body.startswith(b"0\x82") and len(body) > 32:
        return (".der", "DER encoded certificate or ASN.1 object")
    return None


def classify_zip_payload(body: bytes) -> tuple[str, str]:
    sample = body[: min(len(body), 2_000_000)]
    if b"[Content_Types].xml" in sample:
        if b"xl/" in sample:
            return (".xlsx", "Microsoft Excel workbook")
        if b"word/" in sample:
            return (".docx", "Microsoft Word document")
        if b"ppt/" in sample:
            return (".pptx", "Microsoft PowerPoint presentation")
        return (".ooxml.zip", "Office Open XML package")
    return (".zip", "ZIP archive")


def detect_text_artifact(body: bytes, content_type: str) -> tuple[str, str] | None:
    if len(body) < MIN_TEXT_OBJECT_BYTES:
        return None
    text = body.decode("utf-8", errors="ignore")
    if printable_ratio(text) < 0.85:
        return None
    lowered_type = content_type.lower()
    lowered_text = text.lstrip().lower()
    if "json" in lowered_type or lowered_text.startswith(("{", "[")):
        return (".json", "JSON text")
    if "xml" in lowered_type or lowered_text.startswith("<?xml"):
        return (".xml", "XML text")
    if "html" in lowered_type or lowered_text.startswith(("<html", "<!doctype html")):
        return (".html", "HTML text")
    if "text" in lowered_type or "javascript" in lowered_type:
        return (guess_extension(content_type), "text response")
    return None


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    allowed = set(string.printable)
    printable = sum(1 for char in text if char in allowed)
    return printable / len(text)


def looks_like_havoc_wire_body(body: bytes) -> bool:
    if len(body) < 16:
        return False
    size = int.from_bytes(body[:4], byteorder="big", signed=False)
    if size > len(body):
        return False
    first_field = int.from_bytes(body[12:16], byteorder="big", signed=False)
    second_field = int.from_bytes(body[16:20], byteorder="big", signed=False) if len(body) >= 20 else 0
    return first_field in {0, 1, 99} or second_field in {1, 99}


def looks_like_nimplant_wire_body(body: bytes) -> bool:
    try:
        obj = json.loads(body.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(obj, dict):
        return False
    if isinstance(obj.get("id"), str) and isinstance(obj.get("k"), str):
        return True
    keys = set(obj)
    if keys == {"data"} and isinstance(obj.get("data"), str):
        return looks_like_base64_iv_blob(obj["data"])
    if keys == {"t"} and isinstance(obj.get("t"), str):
        return looks_like_base64_iv_blob(obj["t"])
    return False


def looks_like_base64_iv_blob(value: str) -> bool:
    normalized = "".join(value.split())
    if len(normalized) < 24:
        return False
    try:
        decoded = base64.b64decode(normalized + "=" * ((-len(normalized)) % 4), validate=False)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) > 16


def print_console_summary(result: AnalysisResult) -> None:
    if not result.findings:
        print(f"{success('[-]')} No C2-like patterns found by current rules.")
        print(f"{success('[+]')} Report written: {info(result.output_dir / 'report.md')}")
        return

    printed_havoc = print_havoc_console_summary(result)
    printed_nimplant = print_nimplant_console_summary(result)

    for finding in result.findings:
        if printed_havoc and finding.metadata.get("plugin") == "havoc":
            continue
        if printed_nimplant and finding.metadata.get("plugin") == "nimplant":
            continue
        print(f"{danger('[+]')} Suspicious host: {danger(finding.suspicious_host)}")
        print(f"{danger('[+]')} Possible C2: {danger(finding.possible_c2)}")
        print(f"{danger('[+]')} Confidence: {confidence_style(finding.confidence)}")
        print(f"{info('[+]')} Evidence:")
        for evidence in finding.evidence:
            print(f"    - {evidence}")
    print(f"{success('[+]')} Report written: {info(result.output_dir / 'report.md')}")
    print(f"{success('[+]')} Timeline written: {info(result.output_dir / 'timeline.csv')}")
    print(
        f"{success('[+]')} Suspicious flows written: "
        f"{info(result.output_dir / 'suspicious_flows.csv')}"
    )


def print_havoc_console_summary(result: AnalysisResult) -> bool:
    sessions = result.plugin_artifacts.get("havoc_demon_inits", [])
    if not sessions:
        return False

    attempts = result.plugin_artifacts.get("havoc_decryption_attempts", [])
    for session in sessions:
        session_attempts = [
            attempt for attempt in attempts if getattr(attempt, "agent_id", "") == session.agent_id
        ]
        backend = next(
            (
                getattr(attempt, "backend", "")
                for attempt in session_attempts
                if getattr(attempt, "backend", "") not in {"", "none"}
            ),
            "none",
        )
        c2_address = havoc_c2_address(session)

        print(f"{danger('[+] Found Havoc C2')}")
        print(f"  {muted('[-]')} Magic Bytes: {info(session.magic)}")
        print(f"  [-] Agent ID: {session.agent_id}")
        print(f"  {muted('[-]')} C2 Address: {danger(c2_address)}")
        print(f"  {muted('[-]')} Confidence: {confidence_style('High')}")
        print(f"  {success('[+]')} Found AES Key")
        print(f"    [-] Key: {session.aes_key}")
        print(f"    [-] IV: {session.aes_iv}")
        print(f"  {warning('[+]')} Attempting decryption using {info(backend)}")

        successes = [attempt for attempt in session_attempts if attempt.status == "success"]
        failures = [attempt for attempt in session_attempts if attempt.status == "failed"]
        skipped = [attempt for attempt in session_attempts if attempt.status == "skipped"]
        filtered = [attempt for attempt in session_attempts if attempt.status == "filtered_noise"]

        if not session_attempts:
            print(f"  {warning('[-]')} No matching Havoc payloads were available for decryption")
        for attempt in successes:
            print_decrypted_attempt(result, attempt)
        for attempt in failures:
            print(
                f"  {danger('[!]')} Failed to decrypt {attempt.direction} body "
                f"{attempt.src}:{attempt.sport} -> {attempt.dst}:{attempt.dport}: {attempt.error}"
            )
        if filtered:
            print(f"  {warning('[-]')} Filtered {len(filtered)} noisy decrypt result(s)")
        if skipped:
            print(
                f"  {warning('[-]')} Skipped {len(skipped)} message(s) "
                "with no encrypted payload after the drop offset"
            )
    return True


def havoc_c2_address(session) -> str:
    scheme = "https" if int(session.dport) == 443 else "http"
    host = session.host_header or session.dst
    uri = session.uri if session.uri.startswith("/") else f"/{session.uri}"
    return f"{scheme}://{host}{uri}"


def print_decrypted_attempt(result: AnalysisResult, attempt) -> None:
    label = "Request Body" if attempt.direction == "request" else "Response Body"
    command = ""
    if getattr(attempt, "command_name", "") and attempt.command_name != "HTTP_RESPONSE":
        command = f" ({attempt.command_id} {attempt.command_name})"
    print(f"  {success('[+]')} Decrypting {info(label)}{command}")
    print(
        f"      {muted('[-]')} Drop rule: strip bytes 0 through "
        f"{info(attempt.payload_offset - 1)}, then AES-CTR decrypt"
    )
    if attempt.filename:
        print(
            f"      {success('[-]')} Saved: "
            f"{info(result.output_dir / attempt.filename)}"
        )
    if getattr(attempt, "artifact_filename", ""):
        artifact_path = result.output_dir / "carved_artifacts" / attempt.artifact_filename
        print(
            f"      {danger('[!] Found artifact:')} {danger(artifact_path)} "
            f"{warning(f'({attempt.artifact_type}, offset {attempt.artifact_offset})')}"
        )
    print(muted("============================================== Result =============================================="))
    print(read_decrypted_text(result, attempt))
    print(muted("===================================================================================================="))


def read_decrypted_text(result: AnalysisResult, attempt) -> str:
    preview = getattr(attempt, "preview", "")
    if preview:
        return preview
    if not attempt.filename:
        return "<no decrypted preview was available>"
    path = result.output_dir / attempt.filename
    try:
        data = path.read_bytes()
    except OSError as exc:
        return f"<unable to read decrypted payload: {exc}>"
    truncated = len(data) > MAX_CONSOLE_DECRYPT_BYTES
    if truncated:
        data = data[:MAX_CONSOLE_DECRYPT_BYTES]
    text = data.decode("utf-8", errors="replace")
    if truncated:
        text += (
            f"\n\n[... truncated console output at {MAX_CONSOLE_DECRYPT_BYTES} bytes; "
            "additional plaintext omitted from console output ...]"
        )
    return text


def print_nimplant_console_summary(result: AnalysisResult) -> bool:
    sessions = result.plugin_artifacts.get("nimplant_sessions", [])
    if not sessions:
        return False

    attempts = result.plugin_artifacts.get("nimplant_decryption_attempts", [])
    for session in sessions:
        session_attempts = [
            attempt
            for attempt in attempts
            if getattr(attempt, "implant_id", "") == session.implant_id
        ]
        backend = next(
            (
                getattr(attempt, "backend", "")
                for attempt in session_attempts
                if getattr(attempt, "backend", "") not in {"", "none"}
            ),
            getattr(session, "key_recovery_backend", "") or "none",
        )
        c2_address = nimplant_c2_address(session)

        print(f"{danger('[+] Found Nimplant C2')}")
        print(f"  {muted('[-]')} Implant ID: {session.implant_id}")
        print(f"  {muted('[-]')} C2 Address: {danger(c2_address)}")
        print(f"  {muted('[-]')} Confidence: {confidence_style('High' if session.aes_key_hex else 'Medium')}")
        print(f"  {muted('[-]')} Obfuscated k: {info(session.obfuscated_key_b64)}")
        if session.aes_key_hex:
            print(f"  {success('[+]')} Recovered AES Key")
            print(f"    [-] Key: {session.aes_key_hex}")
            if getattr(session, "seed", -1) >= 0:
                print(f"    [-] Representative seed: 0x{session.seed:08x}")
            print(f"    [-] Validation: {session.key_recovery_validation}")
            print(f"  {warning('[+]')} Decrypting Nimplant traffic using {info(backend)}")
        else:
            print(f"  {warning('[-]')} AES key not recovered: {session.key_recovery_validation}")

        successes = [attempt for attempt in session_attempts if attempt.status == "success"]
        artifacts = [attempt for attempt in session_attempts if attempt.status == "artifact"]
        failures = [attempt for attempt in session_attempts if attempt.status == "failed"]
        skipped = [attempt for attempt in session_attempts if attempt.status == "skipped"]

        for attempt in successes:
            print_nimplant_attempt(result, attempt)
        for attempt in artifacts:
            print_nimplant_attempt(result, attempt)
        for attempt in failures:
            print(
                f"  {danger('[!]')} Failed to decrypt {attempt.direction} field "
                f"{attempt.field_name} {attempt.src}:{attempt.sport} -> "
                f"{attempt.dst}:{attempt.dport}: {attempt.error}"
            )
        if skipped:
            print(f"  {warning('[-]')} Skipped {len(skipped)} Nimplant decrypt step(s)")
    return True


def nimplant_c2_address(session) -> str:
    scheme = "https" if int(session.dport) == 443 else "http"
    host = session.host_header or session.dst
    uri = session.login_uri if session.login_uri.startswith("/") else f"/{session.login_uri}"
    return f"{scheme}://{host}{uri}"


def print_nimplant_attempt(result: AnalysisResult, attempt) -> None:
    label = "Request data" if attempt.direction == "request" else "Response task"
    if attempt.direction == "session":
        label = "Session"
    if attempt.direction == "transfer":
        label = "Transfer artifact"
    task = f" task={attempt.task}" if getattr(attempt, "task", "") else ""
    guid = f" guid={attempt.task_guid}" if getattr(attempt, "task_guid", "") else ""
    print(f"  {success('[+]')} Decrypted Nimplant {info(label)}{guid}{task}")
    if attempt.filename:
        print(
            f"      {success('[-]')} Saved: "
            f"{info(result.output_dir / attempt.filename)}"
        )
    if getattr(attempt, "artifact_filename", ""):
        artifact_path = result.output_dir / "carved_artifacts" / attempt.artifact_filename
        print(
            f"      {danger('[!] Found artifact:')} {danger(artifact_path)} "
            f"{warning(f'({attempt.artifact_type}, offset {attempt.artifact_offset})')}"
        )
    preview = getattr(attempt, "preview", "")
    if preview:
        if len(preview) > MAX_CONSOLE_DECRYPT_BYTES:
            preview = (
                preview[:MAX_CONSOLE_DECRYPT_BYTES]
                + f"\n\n[... truncated console output at {MAX_CONSOLE_DECRYPT_BYTES} chars; "
                "additional plaintext omitted from console output ...]"
            )
        print(muted("============================================== Result =============================================="))
        print(preview)
        print(muted("===================================================================================================="))
