#!/usr/bin/env python3
"""C2Detector command-line entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from c2detector_core.analyzer import C2Analyzer
from c2detector_core.config import VERSION, AnalysisConfig
from c2detector_core.engine import DetectionEngine
from c2detector_core.errors import C2DetectorError
from c2detector_core.generic_rules import GenericHTTPBeaconRule, GenericTLSBeaconRule
from c2detector_core.report import ReportWriter, configure_console_colors, print_console_summary
from plugins import register_plugin_arguments, register_plugins


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be >= 1")
    return parsed


def jitter_ratio(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="c2detector.py",
        description="Analyze a .pcap for possible C2 behavior and write DFIR artifacts.",
    )
    parser.add_argument("--pcap", required=True, type=Path, help="Input classic .pcap file")
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output parent directory; artifacts are written under <out>/report/",
    )
    parser.add_argument(
        "--min-beacon-count",
        type=positive_int,
        default=4,
        help="Minimum repeated requests or handshakes before beaconing is considered",
    )
    parser.add_argument(
        "--max-jitter-ratio",
        type=jitter_ratio,
        default=0.25,
        help="Maximum median absolute deviation divided by median interval",
    )
    parser.add_argument(
        "--min-sleep",
        type=float,
        default=2.0,
        help="Minimum beacon interval in seconds",
    )
    parser.add_argument(
        "--max-sleep",
        type=float,
        default=900.0,
        help="Maximum beacon interval in seconds",
    )
    parser.add_argument(
        "--no-extract-http-objects",
        action="store_true",
        help="Disable HTTP body extraction",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Colorize console output: auto, always, or never",
    )
    register_plugin_arguments(parser)
    parser.add_argument("--version", action="version", version=f"C2Detector {VERSION}")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if not args.pcap.exists():
        raise C2DetectorError(f"PCAP does not exist: {args.pcap}")
    if not args.pcap.is_file():
        raise C2DetectorError(f"PCAP path is not a file: {args.pcap}")
    if args.min_sleep < 0:
        raise C2DetectorError("--min-sleep must be >= 0")
    if args.max_sleep < args.min_sleep:
        raise C2DetectorError("--max-sleep must be >= --min-sleep")
    if args.out.exists() and args.out.is_file():
        raise C2DetectorError(f"--out must be a directory, not a file: {args.out}")
    report_dir = resolve_report_dir(args.out)
    if report_dir.exists() and report_dir.is_file():
        raise C2DetectorError(f"Report path is a file, not a directory: {report_dir}")


def resolve_report_dir(output_parent: Path) -> Path:
    return output_parent / "report"


def build_detection_engine(args: argparse.Namespace) -> DetectionEngine:
    engine = DetectionEngine()
    register_plugins(engine, args)
    engine.register(GenericHTTPBeaconRule())
    engine.register(GenericTLSBeaconRule())
    return engine


def build_config(args: argparse.Namespace) -> AnalysisConfig:
    return AnalysisConfig(
        min_beacon_count=args.min_beacon_count,
        max_jitter_ratio=args.max_jitter_ratio,
        min_sleep_seconds=args.min_sleep,
        max_sleep_seconds=args.max_sleep,
        extract_http_objects=not args.no_extract_http_objects,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    configure_console_colors(args.color)
    try:
        validate_args(args)
        config = build_config(args)
        engine = build_detection_engine(args)
        analyzer = C2Analyzer(config, engine)
        result = analyzer.analyze(args.pcap, resolve_report_dir(args.out))
        ReportWriter().write(result)
        print_console_summary(result)
        return 0
    except C2DetectorError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[!] File error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
