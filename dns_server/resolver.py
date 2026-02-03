"""Forward allowed queries to an upstream DNS server.

Every network call has a timeout, so a slow or dead upstream can never hang a
worker thread. Replies are only accepted if they come from the upstream we
asked and match the question we sent.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import time

from dnslib import RCODE, DNSError, DNSRecord

logger = logging.getLogger(__name__)

_MAX_UDP_REPLY = 65535


class UpstreamError(Exception):
    """Raised when the upstream server fails, times out or answers badly."""


class UpstreamResolver:
    """Sends DNS queries to one upstream server over UDP, falling back to TCP."""

    def __init__(self, address: str, port: int, timeout: float) -> None:
        self._address = str(ipaddress.ip_address(address))  # validates the address
        self._port = port
        self._timeout = timeout
        self._family = (
            socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        )

    def forward(self, request: DNSRecord) -> DNSRecord:
        """Ask the upstream server and return its validated reply.

        Raises :class:`UpstreamError` on any failure; the caller turns that
        into a SERVFAIL for the client.
        """
        packet = request.pack()
        try:
            reply = self._parse_and_check(self._query_udp(packet), request)
            if reply.header.tc:
                # The answer did not fit in a UDP packet: ask again over TCP.
                reply = self._parse_and_check(self._query_tcp(packet), request)
        except (OSError, DNSError) as exc:
            raise UpstreamError(f"upstream query failed: {exc}") from exc
        return reply

    @staticmethod
    def _parse_and_check(data: bytes, request: DNSRecord) -> DNSRecord:
        """Parse ``data`` and make sure it answers ``request``."""
        reply = DNSRecord.parse(data)
        if not reply.header.qr:
            raise UpstreamError("upstream sent a query instead of a reply")
        if reply.header.id != request.header.id:
            raise UpstreamError("upstream reply has the wrong id")
        if reply.questions:
            if len(reply.questions) != 1 or (
                reply.q.qname != request.q.qname or reply.q.qtype != request.q.qtype
            ):
                raise UpstreamError("upstream reply does not match the question")
        elif not (reply.header.tc or reply.header.rcode != RCODE.NOERROR):
            # Servers may leave the question out of truncated or error replies,
            # but a successful answer without a question is not trustworthy.
            raise UpstreamError("upstream reply has no question section")
        return reply

    def _query_udp(self, packet: bytes) -> bytes:
        deadline = time.monotonic() + self._timeout
        expected_id = packet[:2]
        with socket.socket(self._family, socket.SOCK_DGRAM) as sock:
            # connect() makes the kernel drop datagrams from any other source.
            sock.connect((self._address, self._port))
            sock.send(packet)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("upstream UDP query timed out")
                sock.settimeout(remaining)
                data = sock.recv(_MAX_UDP_REPLY)
                if data[:2] == expected_id:
                    return data
                # Wrong id: ignore it and keep waiting until the deadline.

    def _query_tcp(self, packet: bytes) -> bytes:
        deadline = time.monotonic() + self._timeout
        with socket.create_connection((self._address, self._port), timeout=self._timeout) as sock:
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            (length,) = struct.unpack("!H", self._recv_exact(sock, 2, deadline))
            return self._recv_exact(sock, length, deadline)

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int, deadline: float) -> bytes:
        chunks: list[bytes] = []
        received = 0
        while received < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("upstream TCP query timed out")
            sock.settimeout(remaining)
            chunk = sock.recv(size - received)
            if not chunk:
                raise ConnectionError("upstream closed the connection early")
            chunks.append(chunk)
            received += len(chunk)
        return b"".join(chunks)
