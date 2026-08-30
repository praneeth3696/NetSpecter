"""
NetSpecter Stream Reassembler
=============================
Tracks TCP flows and buffers fragmented segments to reconstruct multi-packet
credentials and payloads that span segment/MTU boundaries.
"""

from __future__ import annotations
import time
from typing import Optional
from core.models import FlowKey


class StreamBuffer:
    """Maintains sequential TCP payload chunks for a unidirectional flow."""
    def __init__(self, max_buffer_size: int = 65536):
        self.max_buffer_size = max_buffer_size
        self.buffer = bytearray()
        self.last_seen = time.time()
        self.initial_seq: Optional[int] = None
        self.next_seq: Optional[int] = None
        self.segments: dict[int, bytes] = {}

    def add_segment(self, seq: int, data: bytes) -> bytes:
        """
        Store segment and reassemble contiguous bytes.
        Returns newly assembled contiguous bytes, or current buffered view.
        """
        self.last_seen = time.time()
        if not data:
            return bytes(self.buffer)

        # Cap individual buffer
        if len(self.buffer) + len(data) > self.max_buffer_size:
            # Shift buffer keeping the last half to stay within window
            keep_bytes = self.max_buffer_size // 2
            self.buffer = self.buffer[-keep_bytes:]

        # Simple contiguous append or sequence stitching
        self.buffer.extend(data)
        return bytes(self.buffer)


class TCPStreamReassembler:
    """Manages flow tables and coordinates stream reassembly across connections."""
    def __init__(self, max_flows: int = 1000, flow_timeout_seconds: float = 45.0):
        self.flows: dict[FlowKey, StreamBuffer] = {}
        self.max_flows = max_flows
        self.flow_timeout_seconds = flow_timeout_seconds
        self.last_cleanup = time.time()

    def process_segment(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        seq: int,
        data: bytes
    ) -> tuple[bytes, bytes]:
        """
        Processes a TCP packet.
        Returns:
            (raw_segment_data, accumulated_stream_data)
        """
        if not data:
            return b"", b""

        self._maybe_cleanup()

        key = FlowKey(src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port)
        if key not in self.flows:
            if len(self.flows) >= self.max_flows:
                self._evict_oldest()
            self.flows[key] = StreamBuffer()

        buf = self.flows[key]
        accumulated = buf.add_segment(seq, data)
        return data, accumulated

    def clear_flow(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> None:
        key = FlowKey(src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port)
        self.flows.pop(key, None)

    @property
    def active_flows_count(self) -> int:
        return len(self.flows)

    def _maybe_cleanup(self) -> None:
        now = time.time()
        if now - self.last_cleanup < 10.0:
            return
        self.last_cleanup = now
        stale_threshold = now - self.flow_timeout_seconds
        stale_keys = [k for k, v in self.flows.items() if v.last_seen < stale_threshold]
        for k in stale_keys:
            del self.flows[k]

    def _evict_oldest(self) -> None:
        if not self.flows:
            return
        oldest_key = min(self.flows.keys(), key=lambda k: self.flows[k].last_seen)
        del self.flows[oldest_key]
