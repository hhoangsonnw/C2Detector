"""Detector plugin registration."""

from argparse import ArgumentParser, Namespace

from c2detector_core.engine import DetectionEngine
from plugins import havoc, nimplant


def register_plugin_arguments(parser: ArgumentParser) -> None:
    havoc.register_arguments(parser)
    nimplant.register_arguments(parser)


def register_plugins(engine: DetectionEngine, args: Namespace) -> None:
    havoc.register(engine, args)
    nimplant.register(engine, args)
