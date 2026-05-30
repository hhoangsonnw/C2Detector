"""Havoc C2 detection plugin."""

from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from c2detector_core.config import AnalysisConfig
from c2detector_core.engine import DetectionEngine, DetectionRule
from c2detector_core.errors import C2DetectorError
from c2detector_core.models import AnalysisResult, Finding, HTTPRequest, SuspiciousFlow


DEFAULT_MAGIC = bytes.fromhex("deadbeef")
DEMON_INIT_COMMAND_ID = 99
REQUEST_SKIP_AFTER_MAGIC = 12
RESPONSE_PAYLOAD_OFFSET = 12

COMMANDS = {
    1: "GET_JOB",
    10: "COMMAND_NOJOB",
    11: "SLEEP",
    12: "COMMAND_PROC_LIST",
    15: "COMMAND_FS",
    20: "COMMAND_INLINEEXECUTE",
    21: "COMMAND_JOB",
    22: "COMMAND_INJECT_DLL",
    24: "COMMAND_INJECT_SHELLCODE",
    26: "COMMAND_SPAWNDLL",
    27: "COMMAND_PROC_PPIDSPOOF",
    40: "COMMAND_TOKEN",
    99: "DEMON_INIT",
    100: "COMMAND_CHECKIN",
    2100: "COMMAND_NET",
    2500: "COMMAND_CONFIG",
    2510: "COMMAND_SCREENSHOT",
    2520: "COMMAND_PIVOT",
    2530: "COMMAND_TRANSFER",
    2540: "COMMAND_SOCKET",
    2550: "COMMAND_KERBEROS",
    2560: "COMMAND_MEM_FILE",
    4112: "COMMAND_PROC",
    4113: "COMMMAND_PS_IMPORT",
    8193: "COMMAND_ASSEMBLY_INLINE_EXECUTE",
    8195: "COMMAND_ASSEMBLY_LIST_VERSIONS",
}

ATTACK_MAP = [
    "T1071.001 Web Protocols",
    "T1105 Ingress Tool Transfer",
    "T1041 Exfiltration Over C2 Channel",
    "T1573.001 Symmetric Cryptography",
]

MIN_USEFUL_DECRYPT_SIZE = 8
MIN_PRINTABLE_DECRYPT_RATIO = 0.65
GENERIC_CARVABLE_SIGNATURES = (
    (b"7z\xbc\xaf\x27\x1c", ".7z", "7-Zip archive"),
    (b"\x1f\x8b", ".gz", "Gzip archive"),
    (b"Rar!\x1a\x07\x00", ".rar", "RAR archive"),
    (b"%PDF-", ".pdf", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".ole", "OLE compound document"),
)
INTERESTING_TEXT_TOKENS = (
    "Host Name",
    "OS Name",
    "UserName",
    "GROUP INFORMATION",
    "Privilege Name",
    "Microsoft Windows",
    "DESKTOP-",
    "cmd.exe",
    "powershell",
    "whoami",
    "system32",
    "Users\\",
    "Documents",
    "Downloads",
)


@dataclass(frozen=True)
class DemonInit:
    timestamp: float
    src: str
    sport: int
    dst: str
    dport: int
    method: str
    uri: str
    host_header: str
    user_agent: str
    payload_size: int
    magic: str
    agent_id: str
    command_id: int
    command_name: str
    header_layout: str
    mem_id: str
    aes_key: str
    aes_iv: str
    body_sha256: str
    header_offset: int
    key_offset: int
    iv_offset: int


@dataclass(frozen=True)
class CarvedArtifact:
    offset: int
    size: int
    extension: str
    artifact_type: str
    sha256: str
    filename: str


@dataclass
class DecryptionAttempt:
    timestamp: float
    direction: str
    src: str
    sport: int
    dst: str
    dport: int
    uri: str
    agent_id: str
    magic: str
    command_id: int
    command_name: str
    payload_offset: int
    encrypted_size: int
    status: str
    backend: str
    validation: str
    sha256: str = ""
    filename: str = ""
    preview: str = ""
    error: str = ""
    artifact_type: str = ""
    artifact_offset: int = -1
    artifact_size: int = 0
    artifact_sha256: str = ""
    artifact_filename: str = ""


class HavocDemonInitRule(DetectionRule):
    rule_id = "havoc-demon-init"
    name = "Havoc Demon initialization"

    def __init__(self, magic: Optional[bytes] = None, decrypt: bool = True):
        self.magic = magic
        self.decrypt = decrypt

    def evaluate(self, result: AnalysisResult, config: AnalysisConfig) -> list[Finding]:
        sessions: list[DemonInit] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for request in sorted(result.http_requests, key=lambda item: item.timestamp):
            if request.method != "POST" or not request.body:
                continue
            init = parse_demon_init(request, self.magic)
            if init is None:
                continue
            dedupe_key = (
                init.agent_id,
                init.aes_key,
                init.aes_iv,
                init.dst,
                init.uri,
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            sessions.append(init)

        result.plugin_artifacts["havoc_demon_inits"] = sessions
        attempts = []
        if sessions and self.decrypt:
            attempts = decrypt_havoc_traffic(result, sessions)
        elif sessions:
            attempts = [
                DecryptionAttempt(
                    timestamp=sessions[0].timestamp,
                    direction="session",
                    src=sessions[0].src,
                    sport=sessions[0].sport,
                    dst=sessions[0].dst,
                    dport=sessions[0].dport,
                    uri=sessions[0].uri,
                    agent_id=sessions[0].agent_id,
                    magic=sessions[0].magic,
                    command_id=0,
                    command_name="",
                    payload_offset=0,
                    encrypted_size=0,
                    status="skipped",
                    backend="none",
                    validation="disabled by --havoc-no-decrypt",
                )
            ]
        result.plugin_artifacts["havoc_decryption_attempts"] = attempts
        if attempts:
            append_havoc_decryption_report(result, attempts)
        return [
            self._finding(index, init, attempts)
            for index, init in enumerate(sessions, start=1)
        ]

    def _finding(
        self, index: int, init: DemonInit, attempts: list[DecryptionAttempt]
    ) -> Finding:
        session_attempts = [attempt for attempt in attempts if attempt.agent_id == init.agent_id]
        completed = sum(1 for attempt in session_attempts if attempt.status == "success")
        failed = sum(1 for attempt in session_attempts if attempt.status == "failed")
        skipped = sum(1 for attempt in session_attempts if attempt.status == "skipped")
        filtered = sum(1 for attempt in session_attempts if attempt.status == "filtered_noise")
        backend = next(
            (
                attempt.backend
                for attempt in session_attempts
                if attempt.backend and attempt.backend != "none"
            ),
            "none",
        )
        evidence = [
            "POST body matches Havoc Demon init structure",
            f"Magic bytes: {init.magic}",
            f"Command ID: {init.command_id} ({init.command_name})",
            f"Header layout: {init.header_layout}",
            f"Agent ID: {init.agent_id}",
            f"AES key extracted after magic+12 bytes: {init.aes_key}",
            f"AES IV extracted after AES key: {init.aes_iv}",
            f"Destination: {init.dst}:{init.dport} host={init.host_header or '<missing>'} uri={init.uri}",
        ]
        if session_attempts:
            evidence.append(
                "Decryption attempted: "
                f"{completed} useful, {filtered} filtered, {failed} failed, "
                f"{skipped} skipped using {backend}"
            )
        if init.user_agent:
            evidence.append(f"User-Agent: {init.user_agent}")
        if init.header_layout == "agent_id, command_id, mem_id":
            evidence.append(
                "YARA-like match: 00 00 ?? ?? <magic> <agent_id> 00 00 00 63 00 00 00 00"
            )
        else:
            evidence.append(
                "Havoc init variant: 00 00 ?? ?? <magic> <agent_id> 00 00 00 00 00 00 00 63"
            )

        metadata = {
            "plugin": "havoc",
            "agent_id": init.agent_id,
            "command_id": str(init.command_id),
            "header_layout": init.header_layout,
            "magic": init.magic,
            "aes_key": init.aes_key,
            "aes_iv": init.aes_iv,
            "payload_size": str(init.payload_size),
            "body_sha256": init.body_sha256,
            "header_offset": str(init.header_offset),
            "key_offset": str(init.key_offset),
            "iv_offset": str(init.iv_offset),
            "decryption_success": str(completed),
            "decryption_filtered": str(filtered),
            "decryption_failed": str(failed),
            "decryption_skipped": str(skipped),
            "decryption_backend": backend,
        }
        finding_id = f"HAVOC-{index:03d}"
        flow = SuspiciousFlow(
            finding_id=finding_id,
            host=init.src,
            possible_c2="Havoc Demon HTTP C2",
            confidence="High",
            score=95,
            src=init.src,
            sport=str(init.sport),
            dst=init.dst,
            dport=str(init.dport),
            protocol="HTTP",
            first_seen=init.timestamp,
            last_seen=init.timestamp,
            request_count=1,
            method=init.method,
            host_header=init.host_header,
            uri=init.uri,
            metadata=metadata,
            evidence=evidence,
        )
        return Finding(
            finding_id=finding_id,
            suspicious_host=init.src,
            possible_c2="Havoc Demon HTTP C2",
            confidence="High",
            score=95,
            first_seen=init.timestamp,
            last_seen=init.timestamp,
            evidence=evidence,
            attack=ATTACK_MAP,
            suspicious_flows=[flow],
            metadata=metadata,
        )


def parse_demon_init(
    request: HTTPRequest, magic_bytes: Optional[bytes] = None
) -> Optional[DemonInit]:
    body = request.body
    if magic_bytes is not None:
        for magic_offset in find_all(body, magic_bytes):
            init = parse_demon_init_at(request, header_offset=magic_offset - 4)
            if init is not None:
                return init
        return None

    for header_offset in range(0, max(0, len(body) - 67)):
        init = parse_demon_init_at(request, header_offset=header_offset)
        if init is not None:
            return init
    return None


def parse_demon_init_at(request: HTTPRequest, header_offset: int) -> Optional[DemonInit]:
    body = request.body
    if header_offset < 0:
        return None

    magic_offset = header_offset + 4
    magic_end = magic_offset + 4
    agent_offset = magic_end
    first_field_offset = agent_offset + 4
    second_field_offset = first_field_offset + 4
    key_offset = magic_end + REQUEST_SKIP_AFTER_MAGIC
    iv_offset = key_offset + 32
    end_offset = iv_offset + 16
    if end_offset > len(body):
        return None

    payload_size = struct.unpack(">I", body[header_offset:magic_offset])[0]
    remaining = len(body) - header_offset
    if payload_size < 64 or payload_size > remaining:
        return None

    first_field = body[first_field_offset:second_field_offset]
    second_field = body[second_field_offset:key_offset]
    first_value = struct.unpack(">I", first_field)[0]
    second_value = struct.unpack(">I", second_field)[0]
    layout = parse_demon_init_layout(first_value, second_value)
    if layout is None:
        return None
    command_id, mem_id, header_layout = layout

    magic = body[magic_offset:magic_end]
    agent_id = body[agent_offset:first_field_offset]
    aes_key = body[key_offset:iv_offset]
    aes_iv = body[iv_offset:end_offset]
    return DemonInit(
        timestamp=request.timestamp,
        src=request.src,
        sport=request.sport,
        dst=request.dst,
        dport=request.dport,
        method=request.method,
        uri=request.uri,
        host_header=request.host,
        user_agent=request.user_agent,
        payload_size=payload_size,
        magic=magic.hex(),
        agent_id=agent_id.hex(),
        command_id=command_id,
        command_name=COMMANDS.get(command_id, f"Unknown Command ID: {command_id}"),
        header_layout=header_layout,
        mem_id=mem_id,
        aes_key=aes_key.hex(),
        aes_iv=aes_iv.hex(),
        body_sha256=hashlib.sha256(body).hexdigest(),
        header_offset=header_offset,
        key_offset=key_offset,
        iv_offset=iv_offset,
    )


def parse_demon_init_layout(first_value: int, second_value: int) -> Optional[tuple[int, str, str]]:
    if first_value == DEMON_INIT_COMMAND_ID and second_value == 0:
        return (first_value, f"{second_value:08x}", "agent_id, command_id, mem_id")
    if first_value == 0 and second_value == DEMON_INIT_COMMAND_ID:
        return (second_value, f"{first_value:08x}", "agent_id, mem_id, command_id")
    return None


def parse_havoc_message_header(body: bytes, magic_offset: int) -> Optional[dict[str, object]]:
    if magic_offset < 4:
        return None
    magic_end = magic_offset + 4
    agent_offset = magic_end
    first_field_offset = agent_offset + 4
    second_field_offset = first_field_offset + 4
    payload_offset = magic_end + REQUEST_SKIP_AFTER_MAGIC
    if payload_offset > len(body):
        return None

    agent_id = body[agent_offset:first_field_offset]
    first_value = struct.unpack(">I", body[first_field_offset:second_field_offset])[0]
    second_value = struct.unpack(">I", body[second_field_offset:payload_offset])[0]
    if first_value == 0 and second_value in COMMANDS:
        command_id = second_value
        mem_id = f"{first_value:08x}"
        header_layout = "agent_id, mem_id, command_id"
    else:
        command_id = first_value
        mem_id = f"{second_value:08x}"
        header_layout = "agent_id, command_id, mem_id"

    return {
        "agent_id": agent_id,
        "command_id": command_id,
        "command_name": COMMANDS.get(command_id, f"Unknown Command ID: {command_id}"),
        "mem_id": mem_id,
        "header_layout": header_layout,
        "payload_offset": payload_offset,
    }


def decrypt_havoc_traffic(
    result: AnalysisResult, sessions: list[DemonInit]
) -> list[DecryptionAttempt]:
    output_dir = result.output_dir / "havoc_decrypted"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    attempts: list[DecryptionAttempt] = []

    for session in sessions:
        key = bytes.fromhex(session.aes_key)
        iv = bytes.fromhex(session.aes_iv)
        attempts.extend(decrypt_matching_requests(result, session, key, iv, output_dir))
        attempts.extend(decrypt_matching_responses(result, session, key, iv, output_dir))

    write_decryption_index(output_dir, attempts)
    return attempts


def decrypt_matching_requests(
    result: AnalysisResult,
    session: DemonInit,
    key: bytes,
    iv: bytes,
    output_dir: Path,
) -> list[DecryptionAttempt]:
    attempts: list[DecryptionAttempt] = []
    magic = bytes.fromhex(session.magic)
    agent_id = bytes.fromhex(session.agent_id)
    for request in sorted(result.http_requests, key=lambda item: item.timestamp):
        if request.src != session.src or request.dst != session.dst:
            continue
        if request.dport != session.dport or request.method != "POST" or not request.body:
            continue
        magic_offset = request.body.find(magic)
        if magic_offset < 0:
            continue
        message_header = parse_havoc_message_header(request.body, magic_offset)
        if message_header is None:
            continue
        if message_header["agent_id"] != agent_id:
            continue
        if int(message_header["command_id"]) == DEMON_INIT_COMMAND_ID:
            continue
        payload_offset = int(message_header["payload_offset"])
        payload = request.body[payload_offset:]
        attempts.append(
            decrypt_payload_to_file(
                payload=payload,
                key=key,
                iv=iv,
                output_dir=output_dir,
                timestamp=request.timestamp,
                direction="request",
                src=request.src,
                sport=request.sport,
                dst=request.dst,
                dport=request.dport,
                uri=request.uri,
                agent_id=session.agent_id,
                magic=session.magic,
                command_id=int(message_header["command_id"]),
                command_name=str(message_header["command_name"]),
                payload_offset=payload_offset,
            )
        )
    return attempts


def decrypt_matching_responses(
    result: AnalysisResult,
    session: DemonInit,
    key: bytes,
    iv: bytes,
    output_dir: Path,
) -> list[DecryptionAttempt]:
    attempts: list[DecryptionAttempt] = []
    for message in sorted(result.http_messages, key=lambda item: item.timestamp):
        if message.message_type != "response" or not message.body:
            continue
        if message.src != session.dst or message.dst != session.src:
            continue
        if message.sport != session.dport or message.dport != session.sport:
            continue
        payload_offset = RESPONSE_PAYLOAD_OFFSET
        payload = message.body[payload_offset:]
        attempts.append(
            decrypt_payload_to_file(
                payload=payload,
                key=key,
                iv=iv,
                output_dir=output_dir,
                timestamp=message.timestamp,
                direction="response",
                src=message.src,
                sport=message.sport,
                dst=message.dst,
                dport=message.dport,
                uri=session.uri,
                agent_id=session.agent_id,
                magic=session.magic,
                command_id=0,
                command_name="HTTP_RESPONSE",
                payload_offset=payload_offset,
            )
        )
    return attempts


def decrypt_payload_to_file(
    payload: bytes,
    key: bytes,
    iv: bytes,
    output_dir: Path,
    timestamp: float,
    direction: str,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    uri: str,
    agent_id: str,
    magic: str,
    command_id: int,
    command_name: str,
    payload_offset: int,
) -> DecryptionAttempt:
    if not payload:
        return DecryptionAttempt(
            timestamp=timestamp,
            direction=direction,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            uri=uri,
            agent_id=agent_id,
            magic=magic,
            command_id=command_id,
            command_name=command_name,
            payload_offset=payload_offset,
            encrypted_size=0,
            status="skipped",
            backend="none",
            validation="no encrypted payload after offset",
        )

    try:
        decrypted, backend = aes_ctr_decrypt(key, iv, payload)
    except C2DetectorError as exc:
        return DecryptionAttempt(
            timestamp=timestamp,
            direction=direction,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            uri=uri,
            agent_id=agent_id,
            magic=magic,
            command_id=command_id,
            command_name=command_name,
            payload_offset=payload_offset,
            encrypted_size=len(payload),
            status="failed",
            backend="none",
            validation="not decrypted",
            error=str(exc),
        )

    sha256 = hashlib.sha256(decrypted).hexdigest()
    carved_artifact = carve_decrypted_artifact(
        decrypted, output_dir, direction, agent_id, timestamp
    )
    useful, validation, preview = assess_decrypted_payload(decrypted, carved_artifact)
    if not useful:
        return DecryptionAttempt(
            timestamp=timestamp,
            direction=direction,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            uri=uri,
            agent_id=agent_id,
            magic=magic,
            command_id=command_id,
            command_name=command_name,
            payload_offset=payload_offset,
            encrypted_size=len(payload),
            status="filtered_noise",
            backend=backend,
            validation=validation,
            sha256=sha256,
            preview=preview,
            artifact_type=carved_artifact.artifact_type if carved_artifact else "",
            artifact_offset=carved_artifact.offset if carved_artifact else -1,
            artifact_size=carved_artifact.size if carved_artifact else 0,
            artifact_sha256=carved_artifact.sha256 if carved_artifact else "",
            artifact_filename=carved_artifact.filename if carved_artifact else "",
        )

    filename = f"{direction}_{agent_id}_{timestamp:.6f}_{sha256[:12]}.bin"
    path = output_dir / safe_filename(filename)
    path.write_bytes(decrypted)
    return DecryptionAttempt(
        timestamp=timestamp,
        direction=direction,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        uri=uri,
        agent_id=agent_id,
        magic=magic,
        command_id=command_id,
        command_name=command_name,
        payload_offset=payload_offset,
        encrypted_size=len(payload),
        status="success",
        backend=backend,
        validation=validation,
        sha256=sha256,
        filename=path.name,
        preview=preview,
        artifact_type=carved_artifact.artifact_type if carved_artifact else "",
        artifact_offset=carved_artifact.offset if carved_artifact else -1,
        artifact_size=carved_artifact.size if carved_artifact else 0,
        artifact_sha256=carved_artifact.sha256 if carved_artifact else "",
        artifact_filename=carved_artifact.filename if carved_artifact else "",
    )


def carve_decrypted_artifact(
    payload: bytes,
    output_dir: Path,
    direction: str,
    agent_id: str,
    timestamp: float,
) -> Optional[CarvedArtifact]:
    artifact = find_carvable_artifact(payload)
    if artifact is None:
        return None

    offset, size, extension, artifact_type = artifact
    artifact_bytes = payload[offset : offset + size]
    sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    artifact_dir = output_dir / "carved_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    filename = safe_filename(
        f"artifact_{direction}_{agent_id}_{timestamp:.6f}_{sha256[:12]}{extension}"
    )
    (artifact_dir / filename).write_bytes(artifact_bytes)
    return CarvedArtifact(
        offset=offset,
        size=len(artifact_bytes),
        extension=extension,
        artifact_type=artifact_type,
        sha256=sha256,
        filename=filename,
    )


def find_carvable_artifact(payload: bytes) -> Optional[tuple[int, int, str, str]]:
    pe_artifact = find_pe_artifact(payload)
    if pe_artifact is not None:
        return pe_artifact

    zip_artifact = find_zip_artifact(payload)
    if zip_artifact is not None:
        return zip_artifact

    for signature, extension, artifact_type in GENERIC_CARVABLE_SIGNATURES:
        offset = payload.find(signature)
        if offset >= 0:
            return (offset, len(payload) - offset, extension, artifact_type)
    return None


def find_zip_artifact(payload: bytes) -> Optional[tuple[int, int, str, str]]:
    for offset in find_all(payload, b"PK\x03\x04"):
        extension, artifact_type = classify_zip_payload(payload[offset:])
        return (offset, len(payload) - offset, extension, artifact_type)
    return None


def classify_zip_payload(payload: bytes) -> tuple[str, str]:
    sample = payload[: min(len(payload), 2_000_000)]
    if b"[Content_Types].xml" in sample:
        if b"xl/" in sample:
            return (".xlsx", "Microsoft Excel workbook")
        if b"word/" in sample:
            return (".docx", "Microsoft Word document")
        if b"ppt/" in sample:
            return (".pptx", "Microsoft PowerPoint presentation")
        return (".ooxml.zip", "Office Open XML package")
    return (".zip", "ZIP archive")


def find_pe_artifact(payload: bytes) -> Optional[tuple[int, int, str, str]]:
    for offset in find_all(payload, b"MZ"):
        size = pe_file_size(payload, offset)
        if size > 0:
            return (offset, size, ".exe", "Windows PE executable")
    return None


def pe_file_size(payload: bytes, offset: int) -> int:
    if offset < 0 or offset + 0x40 > len(payload):
        return 0

    e_lfanew = struct.unpack_from("<I", payload, offset + 0x3C)[0]
    pe_offset = offset + e_lfanew
    if e_lfanew <= 0 or pe_offset + 24 > len(payload):
        return 0
    if payload[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return 0

    number_of_sections = struct.unpack_from("<H", payload, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", payload, pe_offset + 20)[0]
    optional_header_offset = pe_offset + 24
    section_table_offset = optional_header_offset + optional_header_size
    if section_table_offset > len(payload):
        return len(payload) - offset

    artifact_size = 0
    if optional_header_size >= 64 and optional_header_offset + 64 <= len(payload):
        size_of_headers = struct.unpack_from("<I", payload, optional_header_offset + 60)[0]
        artifact_size = max(artifact_size, size_of_headers)

    for section_index in range(number_of_sections):
        section_offset = section_table_offset + section_index * 40
        if section_offset + 40 > len(payload):
            break
        raw_size = struct.unpack_from("<I", payload, section_offset + 16)[0]
        raw_pointer = struct.unpack_from("<I", payload, section_offset + 20)[0]
        if raw_size and raw_pointer:
            artifact_size = max(artifact_size, raw_pointer + raw_size)

    if artifact_size <= 0:
        return len(payload) - offset
    return min(artifact_size, len(payload) - offset)


def aes_ctr_decrypt(key: bytes, iv: bytes, payload: bytes) -> tuple[bytes, str]:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
    except ImportError:
        return openssl_aes_ctr_decrypt(key, iv, payload)

    counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return (cipher.decrypt(payload), "pycryptodome")


def openssl_aes_ctr_decrypt(key: bytes, iv: bytes, payload: bytes) -> tuple[bytes, str]:
    openssl_path = shutil.which("openssl")
    if openssl_path is None:
        raise C2DetectorError("AES CTR backend unavailable: install pycryptodome or openssl")
    key_bits = len(key) * 8
    if key_bits not in {128, 192, 256}:
        raise C2DetectorError(f"Unsupported AES key length: {len(key)} bytes")
    proc = subprocess.run(
        [
            openssl_path,
            "enc",
            f"-aes-{key_bits}-ctr",
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
            "-nosalt",
            "-nopad",
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        error = proc.stderr.decode("utf-8", errors="replace").strip()
        raise C2DetectorError(f"openssl AES CTR failed: {error or 'unknown error'}")
    return (proc.stdout, "openssl")


def assess_decrypted_payload(
    payload: bytes, carved_artifact: Optional[CarvedArtifact] = None
) -> tuple[bool, str, str]:
    if not payload:
        return (False, "empty plaintext", "")
    if carved_artifact is not None:
        return (
            True,
            (
                f"embedded {carved_artifact.artifact_type} carved at decrypted "
                f"offset {carved_artifact.offset}"
            ),
            (
                f"Carved {carved_artifact.artifact_type} from decrypted offset "
                f"{carved_artifact.offset} ({carved_artifact.size} bytes)"
            ),
        )
    preview = clean_decrypted_preview(payload)
    if len(payload) < MIN_USEFUL_DECRYPT_SIZE:
        return (False, f"filtered noise: short plaintext ({len(payload)} bytes)", "")
    command_hint = command_hint_from_plaintext(payload)
    if command_hint and not command_hint.startswith("1 (GET_JOB)"):
        return (True, f"recognized Havoc command hint: {command_hint}", preview)
    if has_interesting_text(preview):
        return (True, "readable DFIR text extracted", preview)
    utf16_strings = extract_utf16le_strings(payload)
    if utf16_strings:
        return (True, f"UTF-16LE strings extracted: {len(utf16_strings)}", preview)
    printable = sum(1 for byte in payload if byte in b"\r\n\t" or 32 <= byte <= 126)
    printable_ratio = printable / len(payload)
    if printable_ratio >= MIN_PRINTABLE_DECRYPT_RATIO and len(payload) >= 16:
        return (True, f"printable plaintext ratio {printable_ratio:.2f}", preview)
    if any(token in payload.lower() for token in (b"cmd", b"powershell", b"whoami", b"download")):
        return (True, "operator-like plaintext tokens present", preview)
    return (False, "filtered noise: semantic validation inconclusive", "")


def clean_decrypted_preview(payload: bytes, max_chars: int = 4000) -> str:
    candidates = [
        payload.decode("utf-8", errors="ignore"),
        payload.decode("utf-16le", errors="ignore"),
    ]
    ascii_strings = extract_ascii_strings(payload)
    utf16_strings = extract_utf16le_strings(payload)
    if ascii_strings:
        candidates.append("\n".join(ascii_strings))
    if utf16_strings:
        candidates.append("\n".join(utf16_strings))

    cleaned = trim_to_interesting_text(
        max((normalize_text(candidate) for candidate in candidates), key=text_score)
    )
    if len(cleaned) > max_chars:
        return cleaned[:max_chars] + "\n[... preview truncated ...]"
    return cleaned


def normalize_text(value: str) -> str:
    normalized = []
    for char in value.replace("\x00", ""):
        if char in "\r\n\t" or 32 <= ord(char) <= 126:
            normalized.append(char)
        elif char.isspace():
            normalized.append(" ")
    lines = [line.rstrip() for line in "".join(normalized).splitlines()]
    compacted = []
    previous_blank = False
    for line in lines:
        blank = not line.strip()
        if blank and previous_blank:
            continue
        compacted.append(line)
        previous_blank = blank
    return "\n".join(compacted).strip()


def trim_to_interesting_text(value: str) -> str:
    if not value:
        return value
    lowered = value.lower()
    positions = [
        lowered.find(token.lower())
        for token in INTERESTING_TEXT_TOKENS
        if lowered.find(token.lower()) >= 0
    ]
    if not positions:
        return value
    start = min(positions)
    line_start = value.rfind("\n", 0, start)
    return value[line_start + 1 :].lstrip()


def text_score(value: str) -> int:
    if not value:
        return 0
    score = sum(1 for char in value if char.isalnum() or char in "\\/:._ -")
    score += sum(50 for token in INTERESTING_TEXT_TOKENS if token.lower() in value.lower())
    return score


def has_interesting_text(value: str) -> bool:
    lowered = value.lower()
    return any(token.lower() in lowered for token in INTERESTING_TEXT_TOKENS)


def extract_ascii_strings(payload: bytes, min_len: int = 6) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in payload:
        if byte in b"\t" or 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_len:
                strings.append(current.decode("ascii", errors="ignore"))
            current = bytearray()
    if len(current) >= min_len:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings


def extract_utf16le_strings(payload: bytes, min_len: int = 4) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for offset in range(0, len(payload) - 1, 2):
        low = payload[offset]
        high = payload[offset + 1]
        if high == 0 and (low in b"\t" or 32 <= low <= 126):
            current.extend((low, high))
        else:
            append_utf16_string(strings, current, min_len)
            current = bytearray()
    append_utf16_string(strings, current, min_len)
    return strings


def append_utf16_string(strings: list[str], current: bytearray, min_len: int) -> None:
    if len(current) >= min_len * 2:
        text = bytes(current).decode("utf-16le", errors="ignore").strip()
        if text:
            strings.append(text)


def command_hint_from_plaintext(payload: bytes) -> str:
    candidates: list[int] = []
    if len(payload) >= 2:
        candidates.extend(
            [
                struct.unpack("<H", payload[:2])[0],
                struct.unpack(">H", payload[:2])[0],
            ]
        )
    if len(payload) >= 4:
        candidates.extend(
            [
                struct.unpack("<I", payload[:4])[0],
                struct.unpack(">I", payload[:4])[0],
            ]
        )
    for candidate in candidates:
        if candidate in COMMANDS:
            return f"{candidate} ({COMMANDS[candidate]})"
    return ""


def write_decryption_index(output_dir: Path, attempts: list[DecryptionAttempt]) -> None:
    path = output_dir / "index.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "timestamp",
                "direction",
                "src",
                "sport",
                "dst",
                "dport",
                "uri",
                "agent_id",
                "magic",
                "command_id",
                "command_name",
                "payload_offset",
                "encrypted_size",
                "status",
                "backend",
                "validation",
                "sha256",
                "filename",
                "preview",
                "artifact_type",
                "artifact_offset",
                "artifact_size",
                "artifact_sha256",
                "artifact_filename",
                "error",
            ],
        )
        writer.writeheader()
        for attempt in attempts:
            writer.writerow(
                {
                    "timestamp": f"{attempt.timestamp:.6f}",
                    "direction": attempt.direction,
                    "src": attempt.src,
                    "sport": str(attempt.sport),
                    "dst": attempt.dst,
                    "dport": str(attempt.dport),
                    "uri": attempt.uri,
                    "agent_id": attempt.agent_id,
                    "magic": attempt.magic,
                    "command_id": str(attempt.command_id),
                    "command_name": attempt.command_name,
                    "payload_offset": str(attempt.payload_offset),
                    "encrypted_size": str(attempt.encrypted_size),
                    "status": attempt.status,
                    "backend": attempt.backend,
                    "validation": attempt.validation,
                    "sha256": attempt.sha256,
                    "filename": attempt.filename,
                    "preview": attempt.preview,
                    "artifact_type": attempt.artifact_type,
                    "artifact_offset": (
                        str(attempt.artifact_offset) if attempt.artifact_offset >= 0 else ""
                    ),
                    "artifact_size": str(attempt.artifact_size) if attempt.artifact_size else "",
                    "artifact_sha256": attempt.artifact_sha256,
                    "artifact_filename": attempt.artifact_filename,
                    "error": attempt.error,
                }
            )


def append_havoc_decryption_report(
    result: AnalysisResult, attempts: list[DecryptionAttempt]
) -> None:
    completed = sum(1 for attempt in attempts if attempt.status == "success")
    filtered = sum(1 for attempt in attempts if attempt.status == "filtered_noise")
    failed = sum(1 for attempt in attempts if attempt.status == "failed")
    skipped = sum(1 for attempt in attempts if attempt.status == "skipped")
    carved = sum(1 for attempt in attempts if attempt.artifact_filename)
    backends = sorted(
        {attempt.backend for attempt in attempts if attempt.backend and attempt.backend != "none"}
    )
    lines = [
        "## Havoc Decryption",
        "",
        f"- Attempts: {len(attempts)}",
        f"- Useful decrypts saved: {completed}",
        f"- Filtered noise: {filtered}",
        f"- Failed: {failed}",
        f"- Skipped: {skipped}",
        f"- Carved file artifacts: {carved}",
        f"- Backend: {', '.join(backends) if backends else 'none'}",
        f"- Request decrypt rule: drop through `magic_offset + 4 + {REQUEST_SKIP_AFTER_MAGIC}` bytes, then AES-CTR decrypt",
        f"- Response decrypt rule: drop the first `{RESPONSE_PAYLOAD_OFFSET}` bytes of the HTTP response body, then AES-CTR decrypt",
        "- Output directory: `havoc_decrypted/`",
        "- Index: `havoc_decrypted/index.csv`",
        "",
    ]
    interesting = [
        attempt
        for attempt in attempts
        if attempt.status in {"success", "failed"} and attempt.encrypted_size > 0
    ][:10]
    if interesting:
        lines.extend(["Sample attempts:", ""])
        for attempt in interesting:
            filename = f" file={attempt.filename}" if attempt.filename else ""
            artifact = (
                f" artifact={attempt.artifact_filename}"
                f" artifact_type={attempt.artifact_type}"
                f" artifact_offset={attempt.artifact_offset}"
                if attempt.artifact_filename
                else ""
            )
            error = f" error={attempt.error}" if attempt.error else ""
            command = (
                f" command={attempt.command_id} ({attempt.command_name})"
                if attempt.command_name
                else ""
            )
            lines.append(
                f"- {attempt.direction} {attempt.src}:{attempt.sport} -> "
                f"{attempt.dst}:{attempt.dport} size={attempt.encrypted_size} "
                f"offset={attempt.payload_offset} status={attempt.status}{command} "
                f"validation={attempt.validation}{filename}{artifact}{error}"
            )
        lines.append("")
    result.plugin_artifacts.setdefault("report_sections", []).append("\n".join(lines))


def safe_filename(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)


def find_all(haystack: bytes, needle: bytes) -> Iterator[int]:
    if not needle:
        return
    cursor = 0
    while True:
        index = haystack.find(needle, cursor)
        if index < 0:
            break
        yield index
        cursor = index + 1


def parse_magic(value: str) -> bytes:
    normalized = value.strip().lower().replace("0x", "").replace(":", "").replace(" ", "")
    if not normalized:
        raise C2DetectorError("--havoc-magic cannot be empty")
    if len(normalized) % 2:
        raise C2DetectorError("--havoc-magic must contain an even number of hex characters")
    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise C2DetectorError("--havoc-magic must be hex bytes, for example deadbeef") from exc


def register_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Havoc plugin")
    group.add_argument(
        "--havoc-magic",
        default="auto",
        help="Magic bytes marker used by Havoc Demon traffic, or auto, default: auto",
    )
    group.add_argument(
        "--disable-havoc",
        action="store_true",
        help="Disable the Havoc Demon init detector",
    )
    group.add_argument(
        "--havoc-no-decrypt",
        action="store_true",
        help="Detect Havoc but skip AES-CTR decryption attempts",
    )


def register(engine: DetectionEngine, args: argparse.Namespace) -> None:
    if args.disable_havoc:
        return
    magic = None if args.havoc_magic.strip().lower() == "auto" else parse_magic(args.havoc_magic)
    engine.register(HavocDemonInitRule(magic, decrypt=not args.havoc_no_decrypt))
