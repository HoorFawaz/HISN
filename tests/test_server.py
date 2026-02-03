"""Integration tests: a real HISN server talking to a fake upstream, all on localhost.

No test touches the internet. A tiny fake upstream DNS server answers every
query with documentation addresses (192.0.2.0/24, RFC 5737).
"""

from __future__ import annotations

import dataclasses
import ipaddress
import socket
from collections.abc import Callable, Iterator

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSLabel, DNSQuestion, DNSRecord
from dnslib.server import BaseResolver, DNSHandler, DNSLogger, DNSServer

from config import Settings, settings
from dns_server.decision import DecisionEngine
from dns_server.resolver import UpstreamResolver
from dns_server.server import BLOCK_TTL, HisnResolver, build_servers

BLOCK_PAGE_IP = "192.0.2.80"
CLIENT_TIMEOUT = 2.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FakeUpstream(BaseResolver):
    """Answers with 192.0.2.1; names starting with "many" get 40 records."""

    def resolve(self, request: DNSRecord, handler: DNSHandler) -> DNSRecord:
        reply = request.reply()
        count = 40 if str(request.q.qname).startswith("many") else 1
        for index in range(count):
            reply.add_answer(
                RR(request.q.qname, QTYPE.A, rdata=A(f"192.0.2.{index + 1}"), ttl=60)
            )
        if getattr(handler, "protocol", "") == "udp":
            handler.udplen = 512  # force truncation of big answers over UDP
        return reply


def _start_pair(resolver: BaseResolver, port: int, handler: type[DNSHandler]) -> list[DNSServer]:
    quiet = DNSLogger("-request,-reply,-truncated,-error", prefix=False)
    servers = [
        DNSServer(resolver, address="127.0.0.1", port=port, tcp=False, logger=quiet, handler=handler),
        DNSServer(resolver, address="127.0.0.1", port=port, tcp=True, logger=quiet, handler=handler),
    ]
    for server in servers:
        server.start_thread()
    return servers


def _stop(servers: list[DNSServer]) -> None:
    for server in servers:
        server.server.shutdown()
        server.server.server_close()


@pytest.fixture
def upstream_port() -> Iterator[int]:
    port = _free_port()
    servers = _start_pair(FakeUpstream(), port, DNSHandler)
    yield port
    _stop(servers)


@pytest.fixture
def start_hisn(upstream_port: int) -> Iterator[Callable[..., int]]:
    """Return a function that starts a HISN server and gives back its port."""
    started: list[DNSServer] = []

    def _start(**overrides: object) -> int:
        port = _free_port()
        values: dict[str, object] = {
            "dns_host": "127.0.0.1",
            "dns_port": port,
            "upstream_dns": ipaddress.ip_address("127.0.0.1"),
            "upstream_port": upstream_port,
            "upstream_timeout": 1.0,
            "block_page_ip": ipaddress.ip_address(BLOCK_PAGE_IP),
            "allowed_networks": (ipaddress.ip_network("127.0.0.0/8"),),
        }
        values.update(overrides)  # tests may override any default above
        config: Settings = dataclasses.replace(settings, **values)  # type: ignore[arg-type]
        engine = DecisionEngine(
            whitelist=frozenset({"absher.gov.sa"}),
            blacklist=frozenset({"absher-sa.com"}),
        )
        upstream = UpstreamResolver(
            str(config.upstream_dns), config.upstream_port, config.upstream_timeout
        )
        resolver = HisnResolver(config, engine, upstream)
        udp, tcp = build_servers(resolver, config.dns_host, config.dns_port)
        udp.start_thread()
        tcp.start_thread()
        started.extend([udp, tcp])
        return port

    yield _start
    _stop(started)


def _ask(port: int, name: str, qtype: str = "A", *, tcp: bool = False) -> DNSRecord:
    request = DNSRecord.question(name, qtype)
    data = request.send("127.0.0.1", port, tcp=tcp, timeout=CLIENT_TIMEOUT)
    return DNSRecord.parse(data)


def _addresses(reply: DNSRecord) -> list[str]:
    return [str(rr.rdata) for rr in reply.rr if rr.rtype == QTYPE.A]


def test_allowed_domain_is_forwarded_upstream(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    reply = _ask(port, "example.net")
    assert reply.header.rcode == RCODE.NOERROR
    assert _addresses(reply) == ["192.0.2.1"]


def test_whitelisted_domain_is_forwarded_upstream(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    assert _addresses(_ask(port, "absher.gov.sa")) == ["192.0.2.1"]


def test_blacklisted_domain_gets_block_page_address(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    reply = _ask(port, "absher-sa.com")
    assert reply.header.rcode == RCODE.NOERROR
    assert _addresses(reply) == [BLOCK_PAGE_IP]
    assert reply.rr[0].ttl == BLOCK_TTL


def test_blocking_ignores_case_and_covers_subdomains(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    assert _addresses(_ask(port, "ABSHER-SA.com")) == [BLOCK_PAGE_IP]
    assert _addresses(_ask(port, "secure.login.absher-sa.com")) == [BLOCK_PAGE_IP]


def test_blocked_aaaa_query_gets_empty_answer(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    reply = _ask(port, "absher-sa.com", "AAAA")
    assert reply.header.rcode == RCODE.NOERROR
    assert reply.rr == []


def test_blocked_non_address_query_gets_empty_answer(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    reply = _ask(port, "absher-sa.com", "MX")
    assert reply.header.rcode == RCODE.NOERROR
    assert reply.rr == []


def test_lookalike_of_official_domain_is_not_whitelisted(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    # Not blacklisted either, so it is forwarded; the point is that it never
    # takes the whitelist path. Full coverage of that is in test_decision.py.
    assert _addresses(_ask(port, "absher.gov.sa.fake-login.com")) == ["192.0.2.1"]


def test_name_with_dot_inside_a_label_is_refused(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    question = DNSQuestion(DNSLabel([b"x.absher", b"gov", b"sa"]), QTYPE.A)
    data = DNSRecord(q=question).send("127.0.0.1", port, timeout=CLIENT_TIMEOUT)
    assert DNSRecord.parse(data).header.rcode == RCODE.REFUSED


def test_non_ascii_label_is_refused(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    question = DNSQuestion(DNSLabel([b"\xc3\xa9", b"com"]), QTYPE.A)
    data = DNSRecord(q=question).send("127.0.0.1", port, timeout=CLIENT_TIMEOUT)
    assert DNSRecord.parse(data).header.rcode == RCODE.REFUSED


def test_client_outside_allowed_networks_gets_no_answer(start_hisn: Callable[..., int]) -> None:
    port = start_hisn(allowed_networks=(ipaddress.ip_network("10.0.0.0/8"),))
    with pytest.raises(socket.timeout):
        DNSRecord.question("example.net").send("127.0.0.1", port, timeout=0.5)


def test_response_packets_are_ignored(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    packet = DNSRecord.question("example.net")
    packet.header.qr = 1
    with pytest.raises(socket.timeout):
        packet.send("127.0.0.1", port, timeout=0.5)


def test_malformed_packets_do_not_crash_the_server(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for garbage in (b"", b"\x00", b"\xff" * 64, b"\x12\x34\x01\x00\x00\x05" + b"\x00" * 6):
            sock.sendto(garbage, ("127.0.0.1", port))
    assert _addresses(_ask(port, "example.net")) == ["192.0.2.1"]


def test_upstream_failure_returns_servfail(start_hisn: Callable[..., int]) -> None:
    dead_port = _free_port()  # nothing listens here
    port = start_hisn(upstream_port=dead_port, upstream_timeout=0.3)
    assert _ask(port, "example.net").header.rcode == RCODE.SERVFAIL


def test_tcp_queries_work(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    assert _addresses(_ask(port, "example.net", tcp=True)) == ["192.0.2.1"]
    assert _addresses(_ask(port, "absher-sa.com", tcp=True)) == [BLOCK_PAGE_IP]


def test_large_upstream_answer_falls_back_to_tcp(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    reply = _ask(port, "many.example.net", tcp=True)
    # The fake upstream truncates this answer over UDP, so getting all 40
    # records proves the resolver retried over TCP.
    assert len(_addresses(reply)) == 40


def test_oversized_udp_reply_is_truncated_for_the_client(start_hisn: Callable[..., int]) -> None:
    port = start_hisn()
    reply = _ask(port, "many.example.net")
    assert reply.header.tc == 1
