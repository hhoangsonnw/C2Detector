"""User-facing exceptions for C2Detector."""


class C2DetectorError(Exception):
    """Base exception for analysis errors that should be printed cleanly."""


class UnsupportedPcapError(C2DetectorError):
    """Raised when a capture format is not supported by the current parser."""

