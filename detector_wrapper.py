"""
NetSpecter Detector Wrapper
===========================
Bridge between low-level packet capture bytes and higher-order protocol detection engines.
"""

from __future__ import annotations
from typing import Optional, Union
from core.models import DetectionResult
from core.detector_engine import DetectorEngine

_engine = DetectorEngine()


def process_payload(
    payload_bytes: bytes,
    src_ip: str = "0.0.0.0",
    dst_ip: str = "0.0.0.0",
    src_port: int = 0,
    dst_port: int = 0,
    as_result_object: bool = False
) -> Union[dict, DetectionResult, None]:
    """
    Fast bytes filter and decoder bridge.
    Returns:
        DetectionResult if as_result_object is True, else legacy dict (or None).
    """
    res = _engine.inspect_payload(
        payload_bytes=payload_bytes,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port
    )
    if not res:
        return None

    if as_result_object:
        return res

    return res.to_dict()
