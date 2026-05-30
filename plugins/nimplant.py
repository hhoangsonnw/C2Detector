"""Nimplant C2 detection plugin."""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import csv
import ctypes
import ctypes.util
import gzip
import hashlib
import json
import shutil
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from c2detector_core.config import AnalysisConfig
from c2detector_core.engine import DetectionEngine, DetectionRule
from c2detector_core.errors import C2DetectorError
from c2detector_core.models import AnalysisResult, Finding, HTTPMessage, HTTPRequest, SuspiciousFlow
from plugins.havoc import aes_ctr_decrypt, clean_decrypted_preview, safe_filename


BOOTSTRAP_KEYS = {"i", "u", "h", "o", "p", "P", "r"}
LOWER_FOLD_DELTAS = tuple((1 << bits) - 1 for bits in range(1, 9))
FOLD_DELTAS = tuple(sorted(set(LOWER_FOLD_DELTAS + tuple(0xFF ^ item for item in LOWER_FOLD_DELTAS))))
MAX_PREVIEW_CHARS = 4000
_FOLD_MASK_CANDIDATES: Optional[list[tuple[int, bytes]]] = None
_AES_CTR_KEY_RECOVERY_BACKEND = None
ARTIFACT_INDEX_FIELDS = [
    "plugin",
    "timestamp",
    "direction",
    "src",
    "sport",
    "dst",
    "dport",
    "uri",
    "framework_id",
    "field_name",
    "command_id",
    "command_name",
    "task_guid",
    "task",
    "encrypted_size",
    "plaintext_size",
    "payload_offset",
    "status",
    "backend",
    "validation",
    "source_sha256",
    "artifact_type",
    "artifact_offset",
    "artifact_size",
    "artifact_sha256",
    "artifact_filename",
    "error",
    "preview",
]


class PycryptodomeCtrBackend:
    name = "pycryptodome"

    def __init__(self) -> None:
        try:
            from Crypto.Cipher import AES
            from Crypto.Util import Counter
        except ImportError as exc:
            raise C2DetectorError("pycryptodome is unavailable") from exc
        self._aes = AES
        self._counter = Counter

    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        counter = self._counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
        cipher = self._aes.new(key, self._aes.MODE_CTR, counter=counter)
        return cipher.decrypt(ciphertext)


class LibcryptoCtrBackend:
    name = "libcrypto"

    def __init__(self) -> None:
        library_path = ctypes.util.find_library("crypto")
        if library_path is None:
            raise C2DetectorError("OpenSSL libcrypto is unavailable")
        self._lib = ctypes.CDLL(library_path)
        self._configure_symbols()

    def _configure_symbols(self) -> None:
        self._lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        self._lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

        for name in ("EVP_aes_128_ctr", "EVP_aes_192_ctr", "EVP_aes_256_ctr"):
            symbol = getattr(self._lib, name)
            symbol.restype = ctypes.c_void_p

        self._lib.EVP_DecryptInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._lib.EVP_DecryptInit_ex.restype = ctypes.c_int
        self._lib.EVP_DecryptUpdate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        self._lib.EVP_DecryptUpdate.restype = ctypes.c_int
        self._lib.EVP_DecryptFinal_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        self._lib.EVP_DecryptFinal_ex.restype = ctypes.c_int

    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        cipher = self._cipher_for_key(key)
        ctx = self._lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise C2DetectorError("OpenSSL EVP_CIPHER_CTX_new failed")
        try:
            out_buffer = ctypes.create_string_buffer(len(ciphertext) + 16)
            out_len = ctypes.c_int(0)
            final_len = ctypes.c_int(0)
            key_buffer = ctypes.create_string_buffer(key)
            iv_buffer = ctypes.create_string_buffer(iv)
            in_buffer = ctypes.create_string_buffer(ciphertext)

            if self._lib.EVP_DecryptInit_ex(ctx, cipher, None, key_buffer, iv_buffer) != 1:
                raise C2DetectorError("OpenSSL EVP_DecryptInit_ex failed")
            if (
                self._lib.EVP_DecryptUpdate(
                    ctx,
                    out_buffer,
                    ctypes.byref(out_len),
                    in_buffer,
                    len(ciphertext),
                )
                != 1
            ):
                raise C2DetectorError("OpenSSL EVP_DecryptUpdate failed")
            if (
                self._lib.EVP_DecryptFinal_ex(
                    ctx,
                    ctypes.byref(out_buffer, out_len.value),
                    ctypes.byref(final_len),
                )
                != 1
            ):
                raise C2DetectorError("OpenSSL EVP_DecryptFinal_ex failed")
            return out_buffer.raw[: out_len.value + final_len.value]
        finally:
            self._lib.EVP_CIPHER_CTX_free(ctx)

    def _cipher_for_key(self, key: bytes) -> int:
        if len(key) == 16:
            return self._lib.EVP_aes_128_ctr()
        if len(key) == 24:
            return self._lib.EVP_aes_192_ctr()
        if len(key) == 32:
            return self._lib.EVP_aes_256_ctr()
        raise C2DetectorError(f"unsupported AES key length for libcrypto: {len(key)}")


@dataclass(frozen=True)
class KeyRecovery:
    status: str
    seed: int
    aes_key_hex: str
    candidates_tested: int
    backend: str
    validation: str
    plaintext: bytes = b""
    error: str = ""


@dataclass(frozen=True)
class NimplantSession:
    timestamp: float
    first_seen: float
    last_seen: float
    request_count: int
    src: str
    sport: int
    dst: str
    dport: int
    login_uri: str
    host_header: str
    user_agent: str
    implant_id: str
    obfuscated_key_b64: str
    obfuscated_key_hex: str
    aes_key_hex: str
    seed: int
    key_recovery_status: str
    key_recovery_validation: str
    key_recovery_backend: str
    key_candidates_tested: int
    first_data_uri: str
    first_plaintext_preview: str
    body_sha256: str


@dataclass(frozen=True)
class NimplantCarvedArtifact:
    offset: int
    size: int
    extension: str
    artifact_type: str
    sha256: str
    filename: str


@dataclass
class NimplantDecryptionAttempt:
    timestamp: float
    direction: str
    src: str
    sport: int
    dst: str
    dport: int
    uri: str
    implant_id: str
    field_name: str
    encrypted_size: int
    plaintext_size: int
    status: str
    backend: str
    validation: str
    sha256: str = ""
    filename: str = ""
    preview: str = ""
    error: str = ""
    task_guid: str = ""
    task: str = ""
    artifact_type: str = ""
    artifact_offset: int = -1
    artifact_size: int = 0
    artifact_sha256: str = ""
    artifact_filename: str = ""


class NimplantRule(DetectionRule):
    rule_id = "nimplant-http"
    name = "Nimplant HTTP C2"

    def __init__(self, decrypt: bool = True, aes_key: Optional[bytes] = None):
        self.decrypt = decrypt
        self.aes_key = aes_key

    def evaluate(self, result: AnalysisResult, config: AnalysisConfig) -> list[Finding]:
        sessions = find_nimplant_sessions(result, self.decrypt, self.aes_key)
        result.plugin_artifacts["nimplant_sessions"] = sessions

        attempts: list[NimplantDecryptionAttempt] = []
        if sessions and self.decrypt:
            attempts = decrypt_nimplant_traffic(result, sessions)
        elif sessions:
            attempts = [
                NimplantDecryptionAttempt(
                    timestamp=session.timestamp,
                    direction="session",
                    src=session.src,
                    sport=session.sport,
                    dst=session.dst,
                    dport=session.dport,
                    uri=session.login_uri,
                    implant_id=session.implant_id,
                    field_name="",
                    encrypted_size=0,
                    plaintext_size=0,
                    status="skipped",
                    backend="none",
                    validation="disabled by --nimplant-no-decrypt",
                )
                for session in sessions
            ]

        result.plugin_artifacts["nimplant_decryption_attempts"] = attempts
        if attempts:
            append_nimplant_decryption_report(result, attempts)

        return [
            self._finding(index, session, attempts)
            for index, session in enumerate(sessions, start=1)
        ]

    def _finding(
        self,
        index: int,
        session: NimplantSession,
        attempts: list[NimplantDecryptionAttempt],
    ) -> Finding:
        session_attempts = [
            attempt for attempt in attempts if attempt.implant_id == session.implant_id
        ]
        completed = sum(1 for attempt in session_attempts if attempt.status == "success")
        failed = sum(1 for attempt in session_attempts if attempt.status == "failed")
        skipped = sum(1 for attempt in session_attempts if attempt.status == "skipped")
        carved = sum(1 for attempt in session_attempts if attempt.artifact_filename)
        backend = next(
            (
                attempt.backend
                for attempt in session_attempts
                if attempt.backend and attempt.backend != "none"
            ),
            session.key_recovery_backend or "none",
        )
        task_count = len({attempt.task_guid for attempt in session_attempts if attempt.task_guid})
        confidence = "High" if session.aes_key_hex else "Medium"
        score = 92 if session.aes_key_hex else 76
        finding_id = f"NIMPLANT-{index:03d}"
        evidence = [
            "Nimplant-like login response returned JSON fields `id` and `k`",
            f"Implant ID: {session.implant_id}",
            f"Obfuscated key (base64): {session.obfuscated_key_b64}",
            f"X-Identifier matched on {session.request_count} later HTTP request(s)",
            f"Destination: {session.dst}:{session.dport} host={session.host_header or '<missing>'} uri={session.login_uri}",
        ]
        if session.aes_key_hex:
            evidence.extend(
                [
                    f"Recovered AES key: {session.aes_key_hex}",
                    f"Representative XOR seed: 0x{session.seed:08x}",
                    f"Key validation: {session.key_recovery_validation}",
                ]
            )
        else:
            evidence.append(f"Key recovery status: {session.key_recovery_validation}")
        if completed or failed or skipped:
            evidence.append(
                f"Decryption attempted: {completed} successful, {failed} failed, "
                f"{skipped} skipped using {backend}"
            )
        if carved:
            evidence.append(f"Carved Nimplant artifact files: {carved}")
        if task_count:
            evidence.append(f"Recovered task/result GUIDs: {task_count}")
        if session.user_agent:
            evidence.append(f"User-Agent: {session.user_agent}")

        metadata = {
            "plugin": "nimplant",
            "implant_id": session.implant_id,
            "obfuscated_key_b64": session.obfuscated_key_b64,
            "obfuscated_key_hex": session.obfuscated_key_hex,
            "aes_key": session.aes_key_hex,
            "seed": f"0x{session.seed:08x}" if session.seed >= 0 else "",
            "key_recovery_status": session.key_recovery_status,
            "key_recovery_validation": session.key_recovery_validation,
            "key_recovery_backend": session.key_recovery_backend,
            "key_candidates_tested": str(session.key_candidates_tested),
            "decryption_success": str(completed),
            "decryption_failed": str(failed),
            "decryption_skipped": str(skipped),
            "artifacts_carved": str(carved),
            "body_sha256": session.body_sha256,
        }
        flow = SuspiciousFlow(
            finding_id=finding_id,
            host=session.src,
            possible_c2="Nimplant HTTP C2",
            confidence=confidence,
            score=score,
            src=session.src,
            sport=str(session.sport),
            dst=session.dst,
            dport=str(session.dport),
            protocol="HTTP",
            first_seen=session.first_seen,
            last_seen=session.last_seen,
            request_count=session.request_count,
            method="GET/POST",
            host_header=session.host_header,
            uri=session.login_uri,
            metadata=metadata,
            evidence=evidence,
        )
        return Finding(
            finding_id=finding_id,
            suspicious_host=session.src,
            possible_c2="Nimplant HTTP C2",
            confidence=confidence,
            score=score,
            first_seen=session.first_seen,
            last_seen=session.last_seen,
            evidence=evidence,
            suspicious_flows=[flow],
            metadata=metadata,
        )


def find_nimplant_sessions(
    result: AnalysisResult,
    recover_keys: bool,
    provided_key: Optional[bytes],
) -> list[NimplantSession]:
    sessions: list[NimplantSession] = []
    seen: set[tuple[str, str, str, int]] = set()
    messages = sorted(result.http_messages, key=lambda item: item.timestamp)

    for response in messages:
        if response.message_type != "response" or not response.body:
            continue
        handshake = parse_login_handshake(response.body)
        if handshake is None:
            continue
        implant_id, obfuscated_key_b64 = handshake
        login_request = find_request_message_for_response(messages, response)
        if login_request is None:
            continue
        method, uri, _version = parse_request_start_line(login_request.start_line)
        if method != "GET":
            continue

        dedupe_key = (implant_id, obfuscated_key_b64, response.src, response.sport)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        related_requests = [
            request
            for request in result.http_requests
            if request.headers.get("x-identifier") == implant_id
            and request.dst == response.src
            and request.dport == response.sport
        ]
        if not related_requests:
            continue

        first_data_request = first_encrypted_request_after(related_requests, response.timestamp)
        first_data_uri = first_data_request.uri if first_data_request else ""
        first_data_b64 = encrypted_field_from_request(first_data_request) if first_data_request else ""
        obfuscated_key = decode_base64(obfuscated_key_b64)
        recovery = resolve_nimplant_key(
            obfuscated_key,
            first_data_b64,
            recover_keys,
            provided_key,
        )
        first_seen = min([login_request.timestamp] + [request.timestamp for request in related_requests])
        last_seen = max([response.timestamp] + [request.timestamp for request in related_requests])
        sessions.append(
            NimplantSession(
                timestamp=response.timestamp,
                first_seen=first_seen,
                last_seen=last_seen,
                request_count=len(related_requests),
                src=login_request.src,
                sport=login_request.sport,
                dst=login_request.dst,
                dport=login_request.dport,
                login_uri=uri,
                host_header=login_request.host,
                user_agent=login_request.user_agent,
                implant_id=implant_id,
                obfuscated_key_b64=obfuscated_key_b64,
                obfuscated_key_hex=obfuscated_key.hex(),
                aes_key_hex=recovery.aes_key_hex,
                seed=recovery.seed,
                key_recovery_status=recovery.status,
                key_recovery_validation=recovery.validation,
                key_recovery_backend=recovery.backend,
                key_candidates_tested=recovery.candidates_tested,
                first_data_uri=first_data_uri,
                first_plaintext_preview=clean_decrypted_preview(
                    recovery.plaintext, max_chars=MAX_PREVIEW_CHARS
                )
                if recovery.plaintext
                else "",
                body_sha256=hashlib.sha256(response.body).hexdigest(),
            )
        )
    return sessions


def parse_login_handshake(body: bytes) -> Optional[tuple[str, str]]:
    obj = parse_json_body(body)
    if not isinstance(obj, dict):
        return None
    implant_id = obj.get("id")
    key = obj.get("k")
    if not isinstance(implant_id, str) or not isinstance(key, str):
        return None
    if not implant_id or not key:
        return None
    try:
        decoded = decode_base64(key)
    except C2DetectorError:
        return None
    if not decoded:
        return None
    return (implant_id, key)


def find_request_message_for_response(
    messages: list[HTTPMessage], response: HTTPMessage
) -> Optional[HTTPMessage]:
    for candidate in reversed([message for message in messages if message.timestamp <= response.timestamp]):
        if candidate.message_type != "request":
            continue
        if (
            candidate.src == response.dst
            and candidate.sport == response.dport
            and candidate.dst == response.src
            and candidate.dport == response.sport
        ):
            return candidate
    return None


def first_encrypted_request_after(
    requests: list[HTTPRequest], timestamp: float
) -> Optional[HTTPRequest]:
    for request in sorted(requests, key=lambda item: item.timestamp):
        if request.timestamp < timestamp:
            continue
        if encrypted_field_from_request(request):
            return request
    return None


def encrypted_field_from_request(request: Optional[HTTPRequest]) -> str:
    if request is None or not request.body:
        return ""
    field = extract_encrypted_field(request.body, ("data",))
    return field[1] if field else ""


def resolve_nimplant_key(
    obfuscated_key: bytes,
    first_data_b64: str,
    recover_keys: bool,
    provided_key: Optional[bytes],
) -> KeyRecovery:
    if provided_key is not None:
        plaintext = b""
        validation = "provided by --nimplant-aes-key"
        if first_data_b64:
            try:
                plaintext, _backend = decrypt_b64_blob(first_data_b64, provided_key)
                validation = validate_recovered_plaintext(plaintext)
            except C2DetectorError as exc:
                return KeyRecovery(
                    status="failed",
                    seed=-1,
                    aes_key_hex=provided_key.hex(),
                    candidates_tested=0,
                    backend="provided",
                    validation="provided key failed to decrypt first data field",
                    error=str(exc),
                )
        return KeyRecovery(
            status="success",
            seed=-1,
            aes_key_hex=provided_key.hex(),
            candidates_tested=0,
            backend="provided",
            validation=validation,
            plaintext=plaintext,
        )

    if not recover_keys:
        return KeyRecovery(
            status="skipped",
            seed=-1,
            aes_key_hex="",
            candidates_tested=0,
            backend="none",
            validation="disabled by --nimplant-no-decrypt",
        )
    if not first_data_b64:
        return KeyRecovery(
            status="skipped",
            seed=-1,
            aes_key_hex="",
            candidates_tested=0,
            backend="none",
            validation="no encrypted data field available for key validation",
        )
    return recover_key_from_obfuscated_k(obfuscated_key, first_data_b64)


def recover_key_from_obfuscated_k(obfuscated_key: bytes, b64_blob: str) -> KeyRecovery:
    try:
        blob = decode_base64(b64_blob)
    except C2DetectorError as exc:
        return KeyRecovery(
            status="failed",
            seed=-1,
            aes_key_hex="",
            candidates_tested=0,
            backend="none",
            validation="first data field is not valid base64",
            error=str(exc),
        )
    if len(blob) <= 16:
        return KeyRecovery(
            status="failed",
            seed=-1,
            aes_key_hex="",
            candidates_tested=0,
            backend="none",
            validation="first data blob is too small for IV+ciphertext",
        )
    try:
        backend = key_recovery_aes_backend()
    except C2DetectorError as exc:
        return KeyRecovery(
            status="failed",
            seed=-1,
            aes_key_hex="",
            candidates_tested=0,
            backend="none",
            validation="AES CTR backend unavailable for key recovery",
            error=str(exc),
        )

    normalized_key = normalize_obfuscated_key(obfuscated_key)
    iv = blob[:16]
    ciphertext = blob[16:]
    candidates_tested = 0
    for seed, mask in folded_key_candidates():
        candidates_tested += 1
        key = bytes(normalized_key[index] ^ mask[index] for index in range(16))
        plaintext = backend.decrypt(key, iv, ciphertext)
        validation = validate_recovered_plaintext(plaintext)
        if validation:
            return KeyRecovery(
                status="success",
                seed=seed,
                aes_key_hex=key.hex(),
                candidates_tested=candidates_tested,
                backend=backend.name,
                validation=validation,
                plaintext=plaintext,
            )

    return KeyRecovery(
        status="failed",
        seed=-1,
        aes_key_hex="",
        candidates_tested=candidates_tested,
        backend=backend.name,
        validation="exhausted optimized XOR-fold key candidates",
    )


def key_recovery_aes_backend():
    global _AES_CTR_KEY_RECOVERY_BACKEND
    if _AES_CTR_KEY_RECOVERY_BACKEND is not None:
        return _AES_CTR_KEY_RECOVERY_BACKEND

    errors: list[str] = []
    for backend_class in (PycryptodomeCtrBackend, LibcryptoCtrBackend):
        try:
            _AES_CTR_KEY_RECOVERY_BACKEND = backend_class()
            return _AES_CTR_KEY_RECOVERY_BACKEND
        except C2DetectorError as exc:
            errors.append(str(exc))
    raise C2DetectorError(
        "AES CTR backend unavailable for Nimplant key recovery: " + "; ".join(errors)
    )


def normalize_obfuscated_key(obfuscated_key: bytes) -> bytes:
    return obfuscated_key[:16].ljust(16, b"\x00")


def validate_recovered_plaintext(plaintext: bytes) -> str:
    if not is_human_readable(plaintext):
        return ""
    text = plaintext.decode("utf-8", errors="strict")
    try:
        obj = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "human-readable plaintext"
    if isinstance(obj, dict):
        matched = sorted(BOOTSTRAP_KEYS.intersection(obj.keys()))
        if len(matched) >= 4:
            return f"Nimplant bootstrap JSON fields: {', '.join(matched)}"
        return "human-readable JSON object"
    return "human-readable JSON"


def is_human_readable(data: bytes) -> bool:
    if not data:
        return False
    for byte in data[:16]:
        if not (0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D)):
            return False
    printable = sum(1 for byte in data if 0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D))
    return (printable / len(data)) > 0.95


def folded_key_candidates() -> list[tuple[int, bytes]]:
    global _FOLD_MASK_CANDIDATES
    if _FOLD_MASK_CANDIDATES is not None:
        return _FOLD_MASK_CANDIDATES

    candidates: list[tuple[int, bytes]] = []
    seen_masks: set[bytes] = set()
    for low_byte in range(256):
        if low_byte <= 240:
            for high_fold in range(256):
                seed = (high_fold << 8) | low_byte
                mask = mask_for_seed(seed)
                if mask in seen_masks:
                    continue
                seen_masks.add(mask)
                candidates.append((seed, mask))
            continue

        split = 256 - low_byte
        for high_fold in range(256):
            for delta in FOLD_DELTAS:
                next_high_fold = high_fold ^ delta
                mask = bytes(
                    ((low_byte + index) & 0xFF)
                    ^ (high_fold if index < split else next_high_fold)
                    for index in range(16)
                )
                if mask in seen_masks:
                    continue
                seen_masks.add(mask)
                high_value = representative_high_value(high_fold, next_high_fold)
                candidates.append(((high_value << 8) | low_byte, mask))

    candidates.sort(key=lambda item: item[0])
    _FOLD_MASK_CANDIDATES = candidates
    return candidates


def mask_for_seed(seed: int) -> bytes:
    return bytes(fold32((seed + index) & 0xFFFFFFFF) for index in range(16))


def fold32(value: int) -> int:
    return (
        (value & 0xFF)
        ^ ((value >> 8) & 0xFF)
        ^ ((value >> 16) & 0xFF)
        ^ ((value >> 24) & 0xFF)
    )


def representative_high_value(high_fold: int, next_high_fold: int) -> int:
    delta = high_fold ^ next_high_fold
    if delta in LOWER_FOLD_DELTAS:
        byte0 = delta >> 1
        byte1 = high_fold ^ byte0
        byte2 = 0
    else:
        lower_delta = 0xFF ^ delta
        byte0 = 0xFF
        byte1 = lower_delta >> 1
        byte2 = high_fold ^ byte0 ^ byte1
    return byte0 | (byte1 << 8) | (byte2 << 16)


def decrypt_nimplant_traffic(
    result: AnalysisResult, sessions: list[NimplantSession]
) -> list[NimplantDecryptionAttempt]:
    output_dir = result.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    legacy_dir = output_dir / "nimplant_decrypted"
    if legacy_dir.exists():
        shutil.rmtree(legacy_dir)
    if not result.plugin_artifacts.get("artifact_output_prepared"):
        artifact_dir = output_dir / "carved_artifacts"
        if artifact_dir.exists():
            shutil.rmtree(artifact_dir)
        (output_dir / "index.csv").unlink(missing_ok=True)
        result.plugin_artifacts["artifact_output_prepared"] = True

    messages = sorted(result.http_messages, key=lambda item: item.timestamp)
    attempts: list[NimplantDecryptionAttempt] = []
    for session in sessions:
        if not session.aes_key_hex:
            attempts.append(
                NimplantDecryptionAttempt(
                    timestamp=session.timestamp,
                    direction="session",
                    src=session.src,
                    sport=session.sport,
                    dst=session.dst,
                    dport=session.dport,
                    uri=session.login_uri,
                    implant_id=session.implant_id,
                    field_name="",
                    encrypted_size=0,
                    plaintext_size=0,
                    status="skipped",
                    backend="none",
                    validation=session.key_recovery_validation,
                    error="AES key was not recovered",
                )
            )
            continue

        key = bytes.fromhex(session.aes_key_hex)
        for message in messages:
            encrypted_field = encrypted_field_for_session(messages, message, session)
            if encrypted_field is None:
                continue
            field_name, b64_blob, uri, direction = encrypted_field
            attempts.append(
                decrypt_field_to_file(
                    b64_blob=b64_blob,
                    key=key,
                    output_dir=output_dir,
                    timestamp=message.timestamp,
                    direction=direction,
                    src=message.src,
                    sport=message.sport,
                    dst=message.dst,
                    dport=message.dport,
                    uri=uri,
                    implant_id=session.implant_id,
                    field_name=field_name,
                )
            )
        attempts.extend(carve_transfer_artifacts(messages, session, output_dir, key))

    write_decryption_index(output_dir, attempts)
    result.plugin_artifacts["artifact_index_written"] = True
    if any(attempt.artifact_filename for attempt in attempts):
        result.plugin_artifacts["carved_artifacts_written"] = True
    return attempts


def encrypted_field_for_session(
    messages: list[HTTPMessage],
    message: HTTPMessage,
    session: NimplantSession,
) -> Optional[tuple[str, str, str, str]]:
    if not message.body:
        return None

    if message.message_type == "request":
        method, uri, _version = parse_request_start_line(message.start_line)
        if (
            message.src != session.src
            or message.dst != session.dst
            or message.dport != session.dport
            or message.headers.get("x-identifier") != session.implant_id
        ):
            return None
        field = extract_encrypted_field(message.body, ("data",))
        if field is None:
            return None
        return (field[0], field[1], uri, "request")

    if message.message_type == "response":
        request = find_request_message_for_response(messages, message)
        if request is None or request.headers.get("x-identifier") != session.implant_id:
            return None
        if request.src != session.src or request.dst != session.dst or request.dport != session.dport:
            return None
        _method, uri, _version = parse_request_start_line(request.start_line)
        field = extract_encrypted_field(message.body, ("t",))
        if field is None:
            return None
        return (field[0], field[1], uri, "response")

    return None


def decrypt_field_to_file(
    b64_blob: str,
    key: bytes,
    output_dir: Path,
    timestamp: float,
    direction: str,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    uri: str,
    implant_id: str,
    field_name: str,
) -> NimplantDecryptionAttempt:
    try:
        encrypted_blob = decode_base64(b64_blob)
    except C2DetectorError as exc:
        return NimplantDecryptionAttempt(
            timestamp=timestamp,
            direction=direction,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            uri=uri,
            implant_id=implant_id,
            field_name=field_name,
            encrypted_size=0,
            plaintext_size=0,
            status="failed",
            backend="none",
            validation="base64 decode failed",
            error=str(exc),
        )

    try:
        plaintext, backend = decrypt_blob_bytes(encrypted_blob, key)
    except C2DetectorError as exc:
        return NimplantDecryptionAttempt(
            timestamp=timestamp,
            direction=direction,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            uri=uri,
            implant_id=implant_id,
            field_name=field_name,
            encrypted_size=len(encrypted_blob),
            plaintext_size=0,
            status="failed",
            backend="none",
            validation="not decrypted",
            error=str(exc),
        )

    sha256 = hashlib.sha256(plaintext).hexdigest()
    validation, preview, task_guid, task = assess_plaintext(plaintext)
    carved_artifact = carve_plaintext_artifact(
        plaintext, output_dir, direction, implant_id, timestamp, task_guid
    )
    if carved_artifact is not None:
        validation = f"{validation}; carved {carved_artifact.artifact_type}"
    return NimplantDecryptionAttempt(
        timestamp=timestamp,
        direction=direction,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        uri=uri,
        implant_id=implant_id,
        field_name=field_name,
        encrypted_size=len(encrypted_blob),
        plaintext_size=len(plaintext),
        status="success",
        backend=backend,
        validation=validation,
        sha256=sha256,
        preview=preview,
        task_guid=task_guid,
        task=task,
        artifact_type=carved_artifact.artifact_type if carved_artifact else "",
        artifact_offset=carved_artifact.offset if carved_artifact else -1,
        artifact_size=carved_artifact.size if carved_artifact else 0,
        artifact_sha256=carved_artifact.sha256 if carved_artifact else "",
        artifact_filename=carved_artifact.filename if carved_artifact else "",
    )


def decrypt_b64_blob(b64_blob: str, key: bytes) -> tuple[bytes, str]:
    return decrypt_blob_bytes(decode_base64(b64_blob), key)


def decrypt_blob_bytes(blob: bytes, key: bytes) -> tuple[bytes, str]:
    if len(blob) <= 16:
        raise C2DetectorError("Nimplant blob is too small for a 16-byte IV and ciphertext")
    return aes_ctr_decrypt(key, blob[:16], blob[16:])


def assess_plaintext(plaintext: bytes) -> tuple[str, str, str, str]:
    text = plaintext.decode("utf-8", errors="replace").strip()
    parsed = parse_structured_text(text)
    if isinstance(parsed, dict):
        guid = str(parsed.get("guid", ""))
        task = str(parsed.get("task", ""))
        if task:
            return (
                f"Nimplant task `{task}`",
                f"Task {guid or '<missing-guid>'}: {task}",
                guid,
                task,
            )
        if "result" in parsed:
            result_preview = decode_result_preview(parsed.get("result"))
            preview = f"Result {guid or '<missing-guid>'}:"
            if result_preview:
                preview = f"{preview}\n{result_preview}"
            else:
                preview = f"{preview}\n{clean_decrypted_preview(plaintext, max_chars=MAX_PREVIEW_CHARS)}"
            return ("Nimplant task result", preview[:MAX_PREVIEW_CHARS], guid, "")
        matched = sorted(BOOTSTRAP_KEYS.intersection(parsed.keys()))
        if len(matched) >= 4:
            return (
                f"Nimplant bootstrap JSON fields: {', '.join(matched)}",
                clean_decrypted_preview(plaintext, max_chars=MAX_PREVIEW_CHARS),
                "",
                "",
            )
        return (
            "readable structured plaintext",
            clean_decrypted_preview(plaintext, max_chars=MAX_PREVIEW_CHARS),
            guid,
            task,
        )

    return (
        "readable plaintext" if is_human_readable(plaintext) else "decrypted binary/plaintext",
        clean_decrypted_preview(plaintext, max_chars=MAX_PREVIEW_CHARS),
        "",
        "",
    )


def carve_plaintext_artifact(
    plaintext: bytes,
    output_dir: Path,
    direction: str,
    implant_id: str,
    timestamp: float,
    task_guid: str,
) -> Optional[NimplantCarvedArtifact]:
    text = plaintext.decode("utf-8", errors="replace").strip()
    parsed = parse_structured_text(text)
    if isinstance(parsed, dict) and "result" in parsed:
        return carve_result_artifact(
            parsed.get("result"), output_dir, direction, implant_id, timestamp, task_guid
        )

    artifact = artifact_info_for_payload(plaintext)
    if artifact is None:
        return None
    extension, artifact_type = artifact
    return write_carved_artifact(
        plaintext,
        output_dir,
        direction,
        implant_id,
        timestamp,
        task_guid,
        extension,
        artifact_type,
    )


def carve_result_artifact(
    value: object,
    output_dir: Path,
    direction: str,
    implant_id: str,
    timestamp: float,
    task_guid: str,
) -> Optional[NimplantCarvedArtifact]:
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = decode_base64(value)
    except C2DetectorError:
        return None

    result_artifact = result_artifact_payload(decoded)
    if result_artifact is None:
        return None
    artifact_payload, artifact, _decode_path = result_artifact

    extension, artifact_type = artifact
    return write_carved_artifact(
        artifact_payload,
        output_dir,
        direction,
        implant_id,
        timestamp,
        task_guid,
        extension,
        artifact_type,
    )


def write_carved_artifact(
    payload: bytes,
    output_dir: Path,
    direction: str,
    implant_id: str,
    timestamp: float,
    task_guid: str,
    extension: str,
    artifact_type: str,
) -> NimplantCarvedArtifact:
    sha256 = hashlib.sha256(payload).hexdigest()
    artifact_dir = output_dir / "carved_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    guid = f"_{task_guid}" if task_guid else ""
    filename = safe_filename(
        f"artifact_{direction}_{implant_id}{guid}_{timestamp:.6f}_{sha256[:12]}{extension}"
    )
    (artifact_dir / filename).write_bytes(payload)
    return NimplantCarvedArtifact(
        offset=0,
        size=len(payload),
        extension=extension,
        artifact_type=artifact_type,
        sha256=sha256,
        filename=filename,
    )


def carve_transfer_artifacts(
    messages: list[HTTPMessage],
    session: NimplantSession,
    output_dir: Path,
    key: bytes,
) -> list[NimplantDecryptionAttempt]:
    attempts: list[NimplantDecryptionAttempt] = []
    seen: set[tuple[float, str]] = set()
    for message in messages:
        if message.message_type != "response" or not message.body:
            continue
        request = find_request_message_for_response(messages, message)
        if request is None:
            continue
        if request.headers.get("x-identifier") != session.implant_id:
            continue
        task_guid = request.headers.get("x-unique-id", "")
        if not task_guid:
            continue
        transfer_artifact = transfer_artifact_payload(message.body, key)
        if transfer_artifact is None:
            continue
        dedupe_key = (message.timestamp, hashlib.sha256(message.body).hexdigest())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        _method, uri, _version = parse_request_start_line(request.start_line)
        artifact_payload, (extension, artifact_type), decode_path, backend, encrypted_size = (
            transfer_artifact
        )
        carved_artifact = write_carved_artifact(
            artifact_payload,
            output_dir,
            "transfer",
            session.implant_id,
            message.timestamp,
            task_guid,
            extension,
            artifact_type,
        )
        attempts.append(
            NimplantDecryptionAttempt(
                timestamp=message.timestamp,
                direction="transfer",
                src=message.src,
                sport=message.sport,
                dst=message.dst,
                dport=message.dport,
                uri=uri,
                implant_id=session.implant_id,
                field_name="body",
                encrypted_size=encrypted_size,
                plaintext_size=len(artifact_payload),
                status="artifact",
                backend=backend,
                validation=f"Nimplant transfer artifact {decode_path} {artifact_type}",
                sha256=carved_artifact.sha256,
                preview=(
                    f"Carved {artifact_type} transfer body "
                    f"({carved_artifact.size} bytes, {decode_path})"
                ),
                task_guid=task_guid,
                artifact_type=carved_artifact.artifact_type,
                artifact_offset=carved_artifact.offset,
                artifact_size=carved_artifact.size,
                artifact_sha256=carved_artifact.sha256,
                artifact_filename=carved_artifact.filename,
            )
        )
    return attempts


def decode_result_preview(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        decoded = decode_base64(value)
    except C2DetectorError:
        return ""
    result_artifact = result_artifact_payload(decoded)
    if result_artifact:
        artifact_payload, (_extension, artifact_type), decode_path = result_artifact
        return f"<base64 result {decode_path} {artifact_type}, {len(artifact_payload)} bytes>"
    if is_human_readable(decoded):
        text = decoded.decode("utf-8", errors="replace").strip()
        if len(text) > MAX_PREVIEW_CHARS:
            return text[:MAX_PREVIEW_CHARS] + "\n[... preview truncated ...]"
        return text
    return f"<base64 result decodes to {len(decoded)} non-text bytes>"


def result_artifact_payload(decoded: bytes) -> tuple[bytes, tuple[str, str], str] | None:
    gunzipped = gunzip_artifact_payload(decoded)
    if gunzipped is not None:
        payload, artifact = gunzipped
        return (payload, artifact, "gunzips to")

    artifact = artifact_info_for_payload(decoded)
    if artifact is not None:
        return (decoded, artifact, "decodes to")

    nested = nested_base64_artifact_payload(decoded)
    if nested is not None:
        return nested
    return None


def transfer_artifact_payload(
    payload: bytes, key: bytes
) -> tuple[bytes, tuple[str, str], str, str, int] | None:
    upload = decrypt_upload_transfer_payload(payload, key)
    if upload is not None:
        artifact_payload, decode_path, backend, encrypted_size = upload
        artifact = artifact_info_for_payload(artifact_payload)
        if artifact is not None:
            return (artifact_payload, artifact, decode_path, backend, encrypted_size)

    artifact = artifact_info_for_payload(payload)
    if artifact is None:
        return None
    extension, _artifact_type = artifact
    if extension == ".gz":
        return None
    return (payload, artifact, "is", "none", len(payload))


def decrypt_upload_transfer_payload(
    payload: bytes, key: bytes
) -> tuple[bytes, str, str, int] | None:
    candidates: list[tuple[bytes, str]] = []
    if payload.startswith(b"\x1f\x8b"):
        try:
            candidates.append((gzip.decompress(payload), "gunzip/base64/AES-CTR/zlib decodes to"))
        except (EOFError, OSError):
            pass
    if is_base64_text(payload):
        candidates.append((payload, "base64/AES-CTR/zlib decodes to"))

    for candidate, decode_path in candidates:
        try:
            encrypted_blob = decode_base64_bytes(candidate)
        except C2DetectorError:
            continue
        if len(encrypted_blob) <= 16:
            continue
        try:
            decrypted, backend = decrypt_blob_bytes(encrypted_blob, key)
        except C2DetectorError:
            continue
        try:
            decompressed = zlib.decompress(decrypted, zlib.MAX_WBITS | 32)
            return (decompressed, decode_path, backend, len(encrypted_blob))
        except zlib.error:
            artifact = artifact_info_for_payload(decrypted)
            if artifact is not None:
                raw_path = decode_path.replace("/zlib", "")
                return (decrypted, raw_path, backend, len(encrypted_blob))
    return None


def nested_base64_artifact_payload(
    payload: bytes,
) -> tuple[bytes, tuple[str, str], str] | None:
    if len(payload) < 64 or not is_human_readable(payload):
        return None
    text = payload.decode("ascii", errors="ignore").strip()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n\t "
    if not text or any(char not in alphabet for char in text):
        return None
    try:
        nested = decode_base64(text)
    except C2DetectorError:
        return None
    gunzipped = gunzip_artifact_payload(nested)
    if gunzipped is not None:
        nested_payload, artifact = gunzipped
        return (nested_payload, artifact, "decodes through nested base64/gzip to")

    artifact = artifact_info_for_payload(nested)
    if artifact is None:
        return None
    return (nested, artifact, "decodes through nested base64 to")


def gunzip_artifact_payload(payload: bytes) -> tuple[bytes, tuple[str, str]] | None:
    if not payload.startswith(b"\x1f\x8b"):
        return None
    try:
        decompressed = gzip.decompress(payload)
    except (EOFError, OSError):
        return None
    artifact = artifact_info_for_payload(decompressed)
    if artifact is None:
        return None
    return (decompressed, artifact)


def classify_result_payload(payload: bytes) -> str:
    artifact = artifact_info_for_payload(payload)
    return artifact[1] if artifact else ""


def artifact_info_for_payload(payload: bytes) -> tuple[str, str] | None:
    signatures = (
        (b"\x1f\x8b", ".gz", "gzip data"),
        (b"\x89PNG\r\n\x1a\n", ".png", "PNG image"),
        (b"\xff\xd8\xff", ".jpg", "JPEG image"),
        (b"GIF87a", ".gif", "GIF image"),
        (b"GIF89a", ".gif", "GIF image"),
        (b"PK\x03\x04", ".zip", "ZIP archive"),
        (b"MZ", ".exe", "Windows PE executable"),
        (b"%PDF-", ".pdf", "PDF document"),
    )
    for signature, extension, label in signatures:
        if payload.startswith(signature):
            return (extension, label)
    return None


def write_decryption_index(
    output_dir: Path, attempts: list[NimplantDecryptionAttempt]
) -> None:
    path = output_dir / "index.csv"
    write_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=ARTIFACT_INDEX_FIELDS,
        )
        if write_header:
            writer.writeheader()
        for attempt in attempts:
            if not attempt.artifact_filename:
                continue
            writer.writerow(
                {
                    "plugin": "nimplant",
                    "timestamp": f"{attempt.timestamp:.6f}",
                    "direction": attempt.direction,
                    "src": attempt.src,
                    "sport": str(attempt.sport),
                    "dst": attempt.dst,
                    "dport": str(attempt.dport),
                    "uri": attempt.uri,
                    "framework_id": attempt.implant_id,
                    "field_name": attempt.field_name,
                    "command_id": "",
                    "command_name": "",
                    "task_guid": attempt.task_guid,
                    "task": attempt.task,
                    "encrypted_size": str(attempt.encrypted_size),
                    "plaintext_size": str(attempt.plaintext_size),
                    "payload_offset": "",
                    "status": attempt.status,
                    "backend": attempt.backend,
                    "validation": attempt.validation,
                    "source_sha256": attempt.sha256,
                    "artifact_type": attempt.artifact_type,
                    "artifact_offset": (
                        str(attempt.artifact_offset) if attempt.artifact_offset >= 0 else ""
                    ),
                    "artifact_size": str(attempt.artifact_size) if attempt.artifact_size else "",
                    "artifact_sha256": attempt.artifact_sha256,
                    "artifact_filename": attempt.artifact_filename,
                    "error": attempt.error,
                    "preview": attempt.preview,
                }
            )


def append_nimplant_decryption_report(
    result: AnalysisResult, attempts: list[NimplantDecryptionAttempt]
) -> None:
    completed = sum(1 for attempt in attempts if attempt.status == "success")
    failed = sum(1 for attempt in attempts if attempt.status == "failed")
    skipped = sum(1 for attempt in attempts if attempt.status == "skipped")
    artifact_only = sum(1 for attempt in attempts if attempt.status == "artifact")
    carved = sum(1 for attempt in attempts if attempt.artifact_filename)
    backends = sorted(
        {attempt.backend for attempt in attempts if attempt.backend and attempt.backend != "none"}
    )
    lines = [
        "## Nimplant Decryption",
        "",
        f"- Attempts: {len(attempts)}",
        f"- Successful decrypts: {completed}",
        f"- Transfer artifacts: {artifact_only}",
        f"- Carved file artifacts: {carved}",
        f"- Failed: {failed}",
        f"- Skipped: {skipped}",
        f"- Backend: {', '.join(backends) if backends else 'none'}",
        "- Request decrypt rule: base64-decode JSON `data`, use the first 16 decoded bytes as IV, AES-CTR decrypt the remainder",
        "- Response decrypt rule: base64-decode JSON `t`, use the first 16 decoded bytes as IV, AES-CTR decrypt the remainder",
        "- Output directory: report root",
        "- Carved artifacts: `carved_artifacts/`",
        "- Artifact index: `index.csv`",
        "- Raw decrypted request and response bodies are parsed for context but are not written to disk",
        "",
    ]
    interesting = [
        attempt for attempt in attempts if attempt.status in {"success", "failed", "artifact"}
    ][:12]
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
            task = f" task={attempt.task}" if attempt.task else ""
            guid = f" guid={attempt.task_guid}" if attempt.task_guid else ""
            lines.append(
                f"- {attempt.direction} {attempt.src}:{attempt.sport} -> "
                f"{attempt.dst}:{attempt.dport} uri={attempt.uri} field={attempt.field_name} "
                f"size={attempt.encrypted_size} status={attempt.status}{guid}{task} "
                f"validation={attempt.validation}{filename}{artifact}{error}"
            )
        lines.append("")

    artifact_attempts = [attempt for attempt in attempts if attempt.artifact_filename]
    if artifact_attempts:
        lines.extend(["Carved artifacts:", ""])
        for attempt in artifact_attempts:
            guid = f" guid={attempt.task_guid}" if attempt.task_guid else ""
            lines.append(
                f"- {attempt.artifact_filename} type={attempt.artifact_type} "
                f"size={attempt.artifact_size} sha256={attempt.artifact_sha256}"
                f"{guid} source={attempt.direction} {attempt.uri}"
            )
        lines.append("")
    result.plugin_artifacts.setdefault("report_sections", []).append("\n".join(lines))


def extract_encrypted_field(body: bytes, names: tuple[str, ...]) -> Optional[tuple[str, str]]:
    obj = parse_json_body(body)
    if not isinstance(obj, dict):
        return None
    for name in names:
        value = obj.get(name)
        if isinstance(value, str) and value:
            return (name, value)
    return None


def parse_json_body(body: bytes) -> object:
    try:
        return json.loads(body.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def parse_structured_text(text: str) -> object:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return ast.literal_eval(text)
    except (SyntaxError, ValueError):
        return None


def parse_request_start_line(start_line: str) -> tuple[str, str, str]:
    parts = start_line.split(" ", 2)
    if len(parts) != 3:
        return ("", "", "")
    return (parts[0], parts[1], parts[2])


def decode_base64(value: str) -> bytes:
    normalized = "".join(str(value).split())
    missing_padding = (-len(normalized)) % 4
    if missing_padding:
        normalized += "=" * missing_padding
    try:
        return base64.b64decode(normalized, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise C2DetectorError("invalid base64 field") from exc


def decode_base64_bytes(value: bytes) -> bytes:
    normalized = b"".join(value.split())
    missing_padding = (-len(normalized)) % 4
    if missing_padding:
        normalized += b"=" * missing_padding
    try:
        return base64.b64decode(normalized, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise C2DetectorError("invalid base64 field") from exc


def is_base64_text(value: bytes) -> bool:
    if not value:
        return False
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n\t "
    return all(byte in alphabet for byte in value)


def parse_key(value: str) -> bytes:
    raw = value.strip()
    normalized_hex = raw.lower().replace("0x", "").replace(":", "").replace(" ", "")
    if normalized_hex and len(normalized_hex) % 2 == 0:
        try:
            key = bytes.fromhex(normalized_hex)
            if len(key) in {16, 24, 32}:
                return key
        except ValueError:
            pass
    try:
        key = decode_base64(raw)
        if len(key) in {16, 24, 32}:
            return key
    except C2DetectorError:
        pass
    key = raw.encode("utf-8")
    if len(key) in {16, 24, 32}:
        return key
    raise C2DetectorError(
        "--nimplant-aes-key must be a 16/24/32-byte hex, base64, or UTF-8 AES key"
    )


def register_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Nimplant plugin")
    group.add_argument(
        "--disable-nimplant",
        action="store_true",
        help="Disable the Nimplant HTTP detector",
    )
    group.add_argument(
        "--nimplant-no-decrypt",
        action="store_true",
        help="Detect Nimplant but skip XOR-fold key recovery and AES-CTR decryption",
    )
    group.add_argument(
        "--nimplant-aes-key",
        default="",
        help="Known Nimplant AES key as hex, base64, or 16-byte UTF-8 text; skips key recovery",
    )


def register(engine: DetectionEngine, args: argparse.Namespace) -> None:
    if args.disable_nimplant:
        return
    aes_key = parse_key(args.nimplant_aes_key) if args.nimplant_aes_key.strip() else None
    engine.register(NimplantRule(decrypt=not args.nimplant_no_decrypt, aes_key=aes_key))
