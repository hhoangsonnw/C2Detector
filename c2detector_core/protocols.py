"""Protocol metadata extraction for HTTP and TLS."""

from __future__ import annotations

import hashlib
import struct
from typing import Iterator, Optional

from c2detector_core.config import HTTP_METHODS
from c2detector_core.models import HTTPMessage, HTTPRequest, PacketEvent, TLSClientHello
from c2detector_core.utils import parse_headers


class ProtocolExtractor:
    @staticmethod
    def extract_tls_client_hello(event: PacketEvent) -> Optional[TLSClientHello]:
        if event.protocol != "TCP" or len(event.payload) < 9:
            return None
        try:
            parsed = parse_tls_client_hello(event.payload)
        except (IndexError, struct.error, ValueError):
            return None
        if parsed is None:
            return None
        return TLSClientHello(
            timestamp=event.timestamp,
            src=event.src,
            dst=event.dst,
            sport=event.sport,
            dport=event.dport,
            tls_version=parsed["tls_version"],
            sni=parsed["sni"],
            alpn=tuple(parsed["alpn"]),
            ja3=parsed["ja3"],
            ja3_hash=parsed["ja3_hash"],
        )

    @staticmethod
    def http_request_from_message(message: HTTPMessage) -> Optional[HTTPRequest]:
        parts = message.start_line.split(" ", 2)
        if len(parts) != 3 or not parts[2].startswith("HTTP/"):
            return None
        return HTTPRequest(
            timestamp=message.timestamp,
            src=message.src,
            dst=message.dst,
            sport=message.sport,
            dport=message.dport,
            method=parts[0],
            uri=parts[1],
            version=parts[2],
            headers=message.headers,
            body_len=len(message.body),
            body=message.body,
        )


class HTTPStreamExtractor:
    """Small directional TCP reassembly pass for plaintext HTTP metadata."""

    @staticmethod
    def extract(events: list[PacketEvent]) -> list[HTTPMessage]:
        grouped: dict[tuple[str, int, str, int], list[PacketEvent]] = {}
        for event in events:
            if event.protocol != "TCP" or not event.payload:
                continue
            grouped.setdefault((event.src, event.sport, event.dst, event.dport), []).append(event)

        messages: list[HTTPMessage] = []
        for stream_events in grouped.values():
            stream, ranges = HTTPStreamExtractor._reassemble(stream_events)
            if not stream:
                continue
            messages.extend(HTTPStreamExtractor._parse_messages(stream, ranges, stream_events[0]))
        messages.sort(key=lambda item: item.timestamp)
        return messages

    @staticmethod
    def _reassemble(events: list[PacketEvent]) -> tuple[bytes, list[tuple[int, int, float]]]:
        ordered = sorted(events, key=lambda item: (item.tcp_seq, item.timestamp))
        base_seq = min(event.tcp_seq for event in ordered)
        stream = bytearray()
        ranges: list[tuple[int, int, float]] = []

        for event in ordered:
            offset = tcp_seq_delta(event.tcp_seq, base_seq)
            if offset < 0:
                continue
            end = offset + len(event.payload)
            if end > len(stream):
                stream.extend(b"\x00" * (end - len(stream)))
            stream[offset:end] = event.payload
            ranges.append((offset, end, event.timestamp))

        ranges.sort(key=lambda item: (item[0], item[2]))
        return (bytes(stream), ranges)

    @staticmethod
    def _parse_messages(
        stream: bytes, ranges: list[tuple[int, int, float]], first_event: PacketEvent
    ) -> list[HTTPMessage]:
        messages: list[HTTPMessage] = []
        cursor = 0
        while cursor < len(stream):
            start = find_next_http_start(stream, cursor)
            if start < 0:
                break
            header_end, separator_len = find_http_header_end(stream, start)
            if header_end < 0:
                break

            header_blob = stream[start:header_end]
            try:
                lines = header_blob.decode("iso-8859-1", errors="replace").splitlines()
            except UnicodeDecodeError:
                cursor = start + 1
                continue
            if not lines:
                cursor = start + 1
                continue

            start_line = lines[0]
            message_type = "response" if start_line.startswith("HTTP/") else "request"
            if message_type == "request" and not is_http_request_line(start_line):
                cursor = start + 1
                continue

            headers = parse_headers(lines[1:])
            body_start = header_end + separator_len
            body, body_end = extract_http_body(stream, body_start, headers)

            messages.append(
                HTTPMessage(
                    timestamp=timestamp_for_stream_offset(ranges, start, first_event.timestamp),
                    src=first_event.src,
                    dst=first_event.dst,
                    sport=first_event.sport,
                    dport=first_event.dport,
                    message_type=message_type,
                    start_line=start_line,
                    headers=headers,
                    body=body,
                )
            )
            cursor = max(body_end, header_end + separator_len, start + 1)
        return messages


def tcp_seq_delta(seq: int, base_seq: int) -> int:
    if seq >= base_seq:
        return seq - base_seq
    return seq + (2**32) - base_seq


def find_next_http_start(stream: bytes, cursor: int) -> int:
    candidates = []
    for method in HTTP_METHODS:
        index = stream.find(method + b" ", cursor)
        if index >= 0:
            candidates.append(index)
    response_index = stream.find(b"HTTP/", cursor)
    if response_index >= 0:
        candidates.append(response_index)
    return min(candidates) if candidates else -1


def find_http_header_end(stream: bytes, start: int) -> tuple[int, int]:
    crlf = stream.find(b"\r\n\r\n", start)
    lf = stream.find(b"\n\n", start)
    candidates = []
    if crlf >= 0:
        candidates.append((crlf, 4))
    if lf >= 0:
        candidates.append((lf, 2))
    return min(candidates, key=lambda item: item[0]) if candidates else (-1, 0)


def is_http_request_line(start_line: str) -> bool:
    parts = start_line.split(" ", 2)
    return len(parts) == 3 and parts[0].encode("ascii", errors="ignore") in HTTP_METHODS


def http_content_length(headers: dict[str, str]) -> int:
    try:
        return max(0, int(headers.get("content-length", "0").strip()))
    except ValueError:
        return 0


def extract_http_body(stream: bytes, body_start: int, headers: dict[str, str]) -> tuple[bytes, int]:
    if http_transfer_is_chunked(headers):
        return decode_chunked_body(stream, body_start)

    body_end = min(len(stream), body_start + http_content_length(headers))
    return (stream[body_start:body_end], body_end)


def http_transfer_is_chunked(headers: dict[str, str]) -> bool:
    transfer_encoding = headers.get("transfer-encoding", "")
    encodings = [item.strip().lower() for item in transfer_encoding.split(",")]
    return "chunked" in encodings


def decode_chunked_body(stream: bytes, body_start: int) -> tuple[bytes, int]:
    chunks = bytearray()
    cursor = body_start

    while cursor < len(stream):
        line_end, separator_len = find_line_end(stream, cursor)
        if line_end < 0:
            return (bytes(chunks), len(stream))

        size_line = stream[cursor:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            return (bytes(chunks), cursor)

        cursor = line_end + separator_len
        if chunk_size == 0:
            trailer_end, trailer_separator_len = find_http_header_end(stream, cursor)
            if trailer_end >= 0:
                return (bytes(chunks), trailer_end + trailer_separator_len)
            line_end, separator_len = find_line_end(stream, cursor)
            if line_end >= 0:
                return (bytes(chunks), line_end + separator_len)
            return (bytes(chunks), cursor)

        chunk_end = min(len(stream), cursor + chunk_size)
        chunks.extend(stream[cursor:chunk_end])
        cursor = chunk_end
        if cursor >= len(stream):
            return (bytes(chunks), cursor)

        if stream.startswith(b"\r\n", cursor):
            cursor += 2
        elif stream.startswith(b"\n", cursor):
            cursor += 1

    return (bytes(chunks), cursor)


def find_line_end(stream: bytes, cursor: int) -> tuple[int, int]:
    crlf = stream.find(b"\r\n", cursor)
    lf = stream.find(b"\n", cursor)
    candidates = []
    if crlf >= 0:
        candidates.append((crlf, 2))
    if lf >= 0:
        candidates.append((lf, 1))
    return min(candidates, key=lambda item: item[0]) if candidates else (-1, 0)


def timestamp_for_stream_offset(
    ranges: list[tuple[int, int, float]], offset: int, fallback: float
) -> float:
    for start, end, timestamp in ranges:
        if start <= offset < end:
            return timestamp
    for start, _end, timestamp in reversed(ranges):
        if start <= offset:
            return timestamp
    return fallback


def parse_tls_client_hello(payload: bytes) -> Optional[dict[str, object]]:
    if len(payload) < 9 or payload[0] != 22:
        return None
    record_len = struct.unpack("!H", payload[3:5])[0]
    record_end = min(len(payload), 5 + record_len)
    if record_end < 9 or payload[5] != 1:
        return None

    handshake_len = int.from_bytes(payload[6:9], "big")
    handshake_end = min(record_end, 9 + handshake_len)
    body = payload[9:handshake_end]
    if len(body) < 42:
        return None

    cursor = 0
    client_version = struct.unpack("!H", body[cursor : cursor + 2])[0]
    cursor += 2 + 32

    session_id_len = body[cursor]
    cursor += 1 + session_id_len
    if cursor + 2 > len(body):
        return None

    cipher_len = struct.unpack("!H", body[cursor : cursor + 2])[0]
    cursor += 2
    cipher_bytes = body[cursor : cursor + cipher_len]
    cursor += cipher_len
    ciphers = [
        str(value)
        for value in iter_u16(cipher_bytes)
        if not is_grease_value(value)
    ]

    if cursor >= len(body):
        return None
    compression_len = body[cursor]
    cursor += 1 + compression_len

    extensions: list[str] = []
    supported_groups: list[str] = []
    ec_point_formats: list[str] = []
    sni = ""
    alpn: list[str] = []

    if cursor + 2 <= len(body):
        extension_len = struct.unpack("!H", body[cursor : cursor + 2])[0]
        cursor += 2
        extension_end = min(len(body), cursor + extension_len)
        while cursor + 4 <= extension_end:
            ext_type = struct.unpack("!H", body[cursor : cursor + 2])[0]
            ext_len = struct.unpack("!H", body[cursor + 2 : cursor + 4])[0]
            cursor += 4
            ext_data = body[cursor : cursor + ext_len]
            cursor += ext_len
            if is_grease_value(ext_type):
                continue
            extensions.append(str(ext_type))
            if ext_type == 0:
                sni = parse_sni(ext_data)
            elif ext_type == 16:
                alpn = parse_alpn(ext_data)
            elif ext_type == 10:
                supported_groups = [
                    str(value)
                    for value in parse_supported_groups(ext_data)
                    if not is_grease_value(value)
                ]
            elif ext_type == 11:
                ec_point_formats = [str(value) for value in parse_ec_point_formats(ext_data)]

    ja3 = ",".join(
        [
            str(client_version),
            "-".join(ciphers),
            "-".join(extensions),
            "-".join(supported_groups),
            "-".join(ec_point_formats),
        ]
    )
    return {
        "tls_version": client_version,
        "sni": sni,
        "alpn": alpn,
        "ja3": ja3,
        "ja3_hash": hashlib.md5(ja3.encode("ascii")).hexdigest(),
    }


def iter_u16(data: bytes) -> Iterator[int]:
    for offset in range(0, len(data) - 1, 2):
        yield struct.unpack("!H", data[offset : offset + 2])[0]


def is_grease_value(value: int) -> bool:
    high = (value >> 8) & 0xFF
    low = value & 0xFF
    return high == low and (low & 0x0F) == 0x0A


def parse_sni(data: bytes) -> str:
    if len(data) < 5:
        return ""
    list_len = struct.unpack("!H", data[:2])[0]
    cursor = 2
    end = min(len(data), cursor + list_len)
    while cursor + 3 <= end:
        name_type = data[cursor]
        name_len = struct.unpack("!H", data[cursor + 1 : cursor + 3])[0]
        cursor += 3
        name = data[cursor : cursor + name_len]
        cursor += name_len
        if name_type == 0:
            return name.decode("idna", errors="replace")
    return ""


def parse_alpn(data: bytes) -> list[str]:
    if len(data) < 2:
        return []
    list_len = struct.unpack("!H", data[:2])[0]
    cursor = 2
    end = min(len(data), cursor + list_len)
    protocols: list[str] = []
    while cursor < end:
        name_len = data[cursor]
        cursor += 1
        protocols.append(data[cursor : cursor + name_len].decode("ascii", errors="replace"))
        cursor += name_len
    return protocols


def parse_supported_groups(data: bytes) -> list[int]:
    if len(data) < 2:
        return []
    list_len = struct.unpack("!H", data[:2])[0]
    return list(iter_u16(data[2 : 2 + list_len]))


def parse_ec_point_formats(data: bytes) -> list[int]:
    if not data:
        return []
    list_len = data[0]
    return list(data[1 : 1 + list_len])
