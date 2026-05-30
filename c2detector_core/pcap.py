"""Classic PCAP/PCAPNG reader and packet normalizer."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

from c2detector_core.errors import UnsupportedPcapError
from c2detector_core.models import PacketEvent


class PcapReader:
    """Minimal PCAP/PCAPNG reader for Ethernet and raw IPv4 captures."""

    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101
    LINKTYPE_IPV4 = 228

    PCAPNG_SHB = 0x0A0D0D0A
    PCAPNG_IDB = 0x00000001
    PCAPNG_SPB = 0x00000003
    PCAPNG_EPB = 0x00000006

    MAGIC = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }

    def __init__(self, path: Path):
        self.path = path
        self.endian = "<"
        self.ts_scale = 1_000_000
        self.linktype = self.LINKTYPE_ETHERNET
        self.interfaces: list[dict[str, float | int]] = []

    def __iter__(self) -> Iterator[tuple[float, bytes]]:
        with self.path.open("rb") as handle:
            magic = handle.read(4)
            if magic == b"\x0a\x0d\x0d\x0a":
                yield from self._iter_pcapng(handle)
                return
            yield from self._iter_classic_pcap(handle, magic)

    def _iter_classic_pcap(
        self, handle: BinaryIO, magic: bytes
    ) -> Iterator[tuple[float, bytes]]:
        self._read_global_header(handle, magic)
        packet_header = struct.Struct(f"{self.endian}IIII")
        while True:
            header = handle.read(packet_header.size)
            if not header:
                break
            if len(header) != packet_header.size:
                raise UnsupportedPcapError("Truncated packet header in pcap")
            ts_sec, ts_frac, incl_len, _orig_len = packet_header.unpack(header)
            packet = handle.read(incl_len)
            if len(packet) != incl_len:
                raise UnsupportedPcapError("Truncated packet data in pcap")
            yield (ts_sec + (ts_frac / self.ts_scale), packet)

    def _read_global_header(self, handle: BinaryIO, magic: bytes) -> None:
        if magic not in self.MAGIC:
            raise UnsupportedPcapError("Input does not look like a classic .pcap file")

        self.endian, self.ts_scale = self.MAGIC[magic]
        rest = handle.read(20)
        if len(rest) != 20:
            raise UnsupportedPcapError("Truncated pcap global header")
        _major, _minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(
            f"{self.endian}HHIIII", rest
        )
        self.linktype = linktype
        if self.linktype not in {
            self.LINKTYPE_ETHERNET,
            self.LINKTYPE_RAW,
            self.LINKTYPE_IPV4,
        }:
            raise UnsupportedPcapError(
                f"Unsupported pcap linktype {self.linktype}; currently supports Ethernet/raw IPv4"
            )

    def _iter_pcapng(self, handle: BinaryIO) -> Iterator[tuple[float, bytes]]:
        self._read_pcapng_section_header(handle)
        while True:
            header = handle.read(8)
            if not header:
                break
            if len(header) != 8:
                raise UnsupportedPcapError("Truncated pcapng block header")
            block_type, block_len = struct.unpack(f"{self.endian}II", header)
            if block_len < 12:
                raise UnsupportedPcapError("Invalid pcapng block length")
            body = handle.read(block_len - 12)
            trailer = handle.read(4)
            if len(body) != block_len - 12 or len(trailer) != 4:
                raise UnsupportedPcapError("Truncated pcapng block")
            trailer_len = struct.unpack(f"{self.endian}I", trailer)[0]
            if trailer_len != block_len:
                raise UnsupportedPcapError("Mismatched pcapng block length trailer")

            if block_type == self.PCAPNG_SHB:
                self._parse_pcapng_section_body(body)
            elif block_type == self.PCAPNG_IDB:
                self._parse_pcapng_interface(body)
            elif block_type == self.PCAPNG_EPB:
                packet = self._parse_pcapng_enhanced_packet(body)
                if packet is not None:
                    yield packet
            elif block_type == self.PCAPNG_SPB:
                packet = self._parse_pcapng_simple_packet(body)
                if packet is not None:
                    yield packet

    def _read_pcapng_section_header(self, handle: BinaryIO) -> None:
        raw_len = handle.read(4)
        if len(raw_len) != 4:
            raise UnsupportedPcapError("Truncated pcapng section header")
        block_len = struct.unpack("<I", raw_len)[0]
        if block_len < 28:
            block_len = struct.unpack(">I", raw_len)[0]
        if block_len < 28:
            raise UnsupportedPcapError("Invalid pcapng section header length")
        body = handle.read(block_len - 12)
        trailer = handle.read(4)
        if len(body) != block_len - 12 or len(trailer) != 4:
            raise UnsupportedPcapError("Truncated pcapng section header")
        self._parse_pcapng_section_body(body)
        trailer_len = struct.unpack(f"{self.endian}I", trailer)[0]
        if trailer_len != block_len:
            raise UnsupportedPcapError("Mismatched pcapng section header trailer")

    def _parse_pcapng_section_body(self, body: bytes) -> None:
        if len(body) < 16:
            raise UnsupportedPcapError("Truncated pcapng section body")
        byte_order_magic = body[:4]
        if byte_order_magic == b"\x4d\x3c\x2b\x1a":
            self.endian = "<"
        elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
            self.endian = ">"
        else:
            raise UnsupportedPcapError("Invalid pcapng byte-order magic")
        self.interfaces = []

    def _parse_pcapng_interface(self, body: bytes) -> None:
        if len(body) < 8:
            raise UnsupportedPcapError("Truncated pcapng interface description")
        linktype, _reserved, _snaplen = struct.unpack(f"{self.endian}HHI", body[:8])
        ts_multiplier = parse_pcapng_ts_multiplier(body[8:], self.endian)
        self.interfaces.append({"linktype": linktype, "ts_multiplier": ts_multiplier})

    def _parse_pcapng_enhanced_packet(
        self, body: bytes
    ) -> Optional[tuple[float, bytes]]:
        if len(body) < 20:
            raise UnsupportedPcapError("Truncated pcapng enhanced packet")
        interface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack(
            f"{self.endian}IIIII", body[:20]
        )
        if interface_id >= len(self.interfaces):
            raise UnsupportedPcapError(f"Unknown pcapng interface id {interface_id}")
        padded_len = align32(cap_len)
        if len(body) < 20 + padded_len:
            raise UnsupportedPcapError("Truncated pcapng enhanced packet data")
        packet = body[20 : 20 + cap_len]
        interface = self.interfaces[interface_id]
        self.linktype = int(interface["linktype"])
        timestamp_raw = (ts_high << 32) | ts_low
        timestamp = timestamp_raw * float(interface["ts_multiplier"])
        return (timestamp, packet)

    def _parse_pcapng_simple_packet(self, body: bytes) -> Optional[tuple[float, bytes]]:
        if len(body) < 4:
            raise UnsupportedPcapError("Truncated pcapng simple packet")
        if not self.interfaces:
            raise UnsupportedPcapError("pcapng simple packet appeared before an interface")
        packet_len = struct.unpack(f"{self.endian}I", body[:4])[0]
        if len(body) < 4 + align32(packet_len):
            raise UnsupportedPcapError("Truncated pcapng simple packet data")
        interface = self.interfaces[0]
        self.linktype = int(interface["linktype"])
        return (0.0, body[4 : 4 + packet_len])


def align32(value: int) -> int:
    return (value + 3) & ~3


def parse_pcapng_ts_multiplier(options: bytes, endian: str) -> float:
    cursor = 0
    while cursor + 4 <= len(options):
        code, length = struct.unpack(f"{endian}HH", options[cursor : cursor + 4])
        cursor += 4
        value = options[cursor : cursor + length]
        cursor += align32(length)
        if code == 0:
            break
        if code == 9 and value:
            resolution = value[0]
            if resolution & 0x80:
                return 2 ** -(resolution & 0x7F)
            return 10 ** -resolution
    return 1e-6


class PacketParser:
    @staticmethod
    def parse(timestamp: float, packet: bytes, linktype: int) -> Optional[PacketEvent]:
        if linktype == PcapReader.LINKTYPE_ETHERNET:
            ip_packet = PacketParser._unwrap_ethernet(packet)
            if ip_packet is None:
                return None
        elif linktype in {PcapReader.LINKTYPE_RAW, PcapReader.LINKTYPE_IPV4}:
            ip_packet = packet
        else:
            return None
        return PacketParser._parse_ipv4(timestamp, ip_packet, len(packet))

    @staticmethod
    def _unwrap_ethernet(packet: bytes) -> Optional[bytes]:
        if len(packet) < 14:
            return None
        offset = 12
        eth_type = struct.unpack("!H", packet[offset : offset + 2])[0]
        offset += 2

        for _ in range(2):
            if eth_type not in {0x8100, 0x88A8}:
                break
            if len(packet) < offset + 4:
                return None
            eth_type = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
            offset += 4

        if eth_type != 0x0800:
            return None
        return packet[offset:]

    @staticmethod
    def _parse_ipv4(timestamp: float, packet: bytes, wire_len: int) -> Optional[PacketEvent]:
        if len(packet) < 20:
            return None
        version = packet[0] >> 4
        ihl = (packet[0] & 0x0F) * 4
        if version != 4 or ihl < 20 or len(packet) < ihl:
            return None
        total_len = struct.unpack("!H", packet[2:4])[0]
        if total_len and len(packet) >= total_len:
            packet = packet[:total_len]
        if len(packet) < ihl:
            return None

        flags_fragment = struct.unpack("!H", packet[6:8])[0]
        fragment_offset = flags_fragment & 0x1FFF
        if fragment_offset != 0:
            return None

        proto = packet[9]
        src = str(ipaddress.IPv4Address(packet[12:16]))
        dst = str(ipaddress.IPv4Address(packet[16:20]))
        transport = packet[ihl:]

        if proto == 6:
            return PacketParser._parse_tcp(timestamp, src, dst, transport, wire_len)
        if proto == 17:
            return PacketParser._parse_udp(timestamp, src, dst, transport, wire_len)
        return None

    @staticmethod
    def _parse_tcp(
        timestamp: float, src: str, dst: str, segment: bytes, wire_len: int
    ) -> Optional[PacketEvent]:
        if len(segment) < 20:
            return None
        sport, dport = struct.unpack("!HH", segment[:4])
        seq, ack = struct.unpack("!II", segment[4:12])
        data_offset = ((segment[12] >> 4) & 0x0F) * 4
        if data_offset < 20 or len(segment) < data_offset:
            return None
        flags_value = segment[13]
        flags = "".join(
            label
            for bit, label in (
                (0x01, "F"),
                (0x02, "S"),
                (0x04, "R"),
                (0x08, "P"),
                (0x10, "A"),
                (0x20, "U"),
            )
            if flags_value & bit
        )
        payload = segment[data_offset:]
        return PacketEvent(
            timestamp=timestamp,
            src=src,
            dst=dst,
            sport=sport,
            dport=dport,
            protocol="TCP",
            wire_len=wire_len,
            payload_len=len(payload),
            tcp_flags=flags,
            tcp_seq=seq,
            tcp_ack=ack,
            payload=payload,
        )

    @staticmethod
    def _parse_udp(
        timestamp: float, src: str, dst: str, datagram: bytes, wire_len: int
    ) -> Optional[PacketEvent]:
        if len(datagram) < 8:
            return None
        sport, dport, udp_len = struct.unpack("!HHH", datagram[:6])
        payload = datagram[8:udp_len] if udp_len >= 8 else datagram[8:]
        return PacketEvent(
            timestamp=timestamp,
            src=src,
            dst=dst,
            sport=sport,
            dport=dport,
            protocol="UDP",
            wire_len=wire_len,
            payload_len=len(payload),
            payload=payload,
        )
