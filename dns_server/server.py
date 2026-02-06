"""HISN DNS server: receive a query, decide, answer.

Run with ``python -m dns_server.server`` from the project root.

Flow for each query:

1. Drop it silently if the client is outside the allowed networks, so the
   server can never be abused as an open resolver.
2. Validate and normalize the queried name. Invalid names get REFUSED.
3. Ask the decision engine (lists, cache, look-alike rule, model; see
   ``dns_server/decision.py``) and log the decision (minimal data, see
   ``storage/schema.sql``). Blocked names get the block page address,
   everything else is forwarded to the upstream DNS server.

The model and the rule are optional at startup: if the model file is missing
or cannot be loaded, the server logs a warning and runs without it.
"""

from __future__ import annotations

import logging
import socket
import sqlite3
import struct
import time

from dnslib import (
    AAAA,
    OPCODE,
    QTYPE,
    RCODE,
    RR,
    A,
    DNSError,
    DNSHeader,
    DNSRecord,
)
from dnslib.server import BaseResolver, DNSHandler, DNSLogger, DNSServer

from config import Settings, settings
from dns_server.decision import Decision, DecisionEngine, Verdict
from dns_server.domain import InvalidDomainError, name_from_labels, normalize_domain
from dns_server.resolver import UpstreamError, UpstreamResolver
from ml.lookalike import LookalikeChecker
from ml.predictor import Predictor
from storage.cache import TTLCache
from storage.db import Database

logger = logging.getLogger(__name__)

BLOCK_TTL = 30  # seconds; short, so a wrongly blocked site recovers quickly
TCP_CLIENT_TIMEOUT = 5.0  # seconds; stops idle TCP clients from pinning a thread
DEFAULT_UDP_LIMIT = 512  # classic DNS limit when the client sent no EDNS size
MAX_UDP_LIMIT = 1232  # conservative cap that avoids IP fragmentation
PURGE_INTERVAL = 3600  # seconds between retention clean-ups


class HisnResolver(BaseResolver):
    """Resolver plugged into dnslib: allow-list, validation, decision, answer."""

    def __init__(
        self,
        config: Settings,
        engine: DecisionEngine,
        upstream: UpstreamResolver,
        database: Database | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._upstream = upstream
        self._database = database

    def resolve(self, request: DNSRecord, handler: DNSHandler) -> DNSRecord:
        client_ip = handler.client_address[0]

        if not self._config.is_client_allowed(client_ip):
            # No reply at all: answering strangers would help reflection
            # attacks. dnslib's handler catches DNSError and sends nothing.
            logger.debug("dropped query from disallowed client %s", client_ip)
            raise DNSError("client not allowed")

        if request.header.qr:
            # A response, not a query. Never answer those (avoids reply loops).
            raise DNSError("not a query")

        reply = self._answer(request, client_ip)
        if getattr(handler, "protocol", "") == "udp":
            reply = _truncate_for_udp(reply, _udp_limit(request))
        return reply

    def _answer(self, request: DNSRecord, client_ip: str) -> DNSRecord:
        """Validate the query and build the reply (no size limit applied yet)."""
        if request.header.opcode != OPCODE.QUERY:
            return _error_reply(request, RCODE.NOTIMP)
        if len(request.questions) != 1:
            return _error_reply(request, RCODE.FORMERR)

        try:
            domain = normalize_domain(name_from_labels(request.q.qname.label))
        except InvalidDomainError as exc:
            logger.info("refused %s: invalid name (%s)", client_ip, exc)
            return _error_reply(request, RCODE.REFUSED)

        decision = self._engine.decide(domain)
        qtype = QTYPE[request.q.qtype]
        logger.info(
            "%s %s %s -> %s (%s%s)",
            client_ip,
            domain,
            qtype,
            decision.verdict.value,
            decision.reason.value,
            f" {decision.matched}" if decision.matched else "",
        )

        self._log_decision(domain, decision, client_ip)

        if decision.blocked:
            return self._blocked_reply(request)

        try:
            return self._upstream.forward(request)
        except UpstreamError as exc:
            logger.warning("upstream failure for %s: %s", domain, exc)
            return _error_reply(request, RCODE.SERVFAIL)

    def _log_decision(self, domain: str, decision: Decision, client_ip: str) -> None:
        """Store the decision. A storage problem must never stop DNS answers."""
        if self._database is None:
            return
        try:
            self._database.log_decision(
                domain, decision.verdict.value, decision.reason.value, client_ip
            )
        except sqlite3.Error as exc:
            logger.warning("could not log decision for %s: %s", domain, exc)

    def _blocked_reply(self, request: DNSRecord) -> DNSRecord:
        """Answer with the block page address instead of the real one.

        Only the record type that matches the block page address family gets
        an answer. Everything else (AAAA when the block page is IPv4, HTTPS,
        MX, ANY, ...) gets an empty NOERROR answer, so the client cannot
        learn the real address from a side channel and cannot fall back to it.
        """
        reply = request.reply(ra=1, aa=0)
        block_ip = self._config.block_page_ip
        qtype = request.q.qtype
        if qtype == QTYPE.A and block_ip.version == 4:
            rdata = A(str(block_ip))
        elif qtype == QTYPE.AAAA and block_ip.version == 6:
            rdata = AAAA(str(block_ip))
        else:
            return reply
        reply.add_answer(RR(request.q.qname, qtype, rdata=rdata, ttl=BLOCK_TTL))
        return reply


def _error_reply(request: DNSRecord, rcode: int) -> DNSRecord:
    reply = request.reply(ra=1, aa=0)
    reply.header.rcode = rcode
    return reply


def _udp_limit(request: DNSRecord) -> int:
    """Largest UDP reply the client accepts (EDNS size, capped for safety)."""
    for record in request.ar:
        if record.rtype == QTYPE.OPT:
            return max(DEFAULT_UDP_LIMIT, min(record.rclass, MAX_UDP_LIMIT))
    return DEFAULT_UDP_LIMIT


def _truncate_for_udp(reply: DNSRecord, limit: int) -> DNSRecord:
    """Return ``reply`` unchanged if it fits in ``limit`` bytes, else a TC reply.

    The truncated reply keeps the question section (dnslib's own truncate()
    drops it, and some stub resolvers reject a reply that does not echo the
    question). Clients that see the TC flag retry the query over TCP.
    """
    if len(reply.pack()) <= limit:
        return reply
    header = DNSHeader(id=reply.header.id, bitmap=reply.header.bitmap, tc=1)
    return DNSRecord(header, questions=list(reply.questions))


class HisnHandler(DNSHandler):
    """dnslib handler with a read timeout and quiet handling of bad clients."""

    def setup(self) -> None:
        if self.server.socket_type == socket.SOCK_STREAM:
            self.request.settimeout(TCP_CLIENT_TIMEOUT)

    def handle(self) -> None:
        try:
            super().handle()
        except (OSError, struct.error, DNSError) as exc:
            # Slow, broken or malicious clients must never crash a worker or
            # fill the console with tracebacks.
            logger.debug("client %s: %s", self.client_address[0], exc)


def build_servers(
    resolver: HisnResolver, host: str, port: int
) -> tuple[DNSServer, DNSServer]:
    """Create the UDP and TCP servers (dnslib needs one object per protocol)."""
    quiet = DNSLogger("-request,-reply,-truncated", prefix=False, logf=logger.debug)
    udp = DNSServer(resolver, address=host, port=port, tcp=False, logger=quiet, handler=HisnHandler)
    tcp = DNSServer(resolver, address=host, port=port, tcp=True, logger=quiet, handler=HisnHandler)
    return udp, tcp


def _purge_old_logs(database: Database) -> None:
    """Apply the retention period (privacy: logs do not live forever)."""
    try:
        removed = database.purge_older_than(settings.log_retention_days)
    except sqlite3.Error as exc:
        logger.warning("log purge failed: %s", exc)
        return
    if removed:
        logger.info("purged %d requests older than %d days", removed, settings.log_retention_days)


def load_lookalike(config: Settings) -> LookalikeChecker | None:
    """The look-alike rule, or None if it is turned off (HISN_LOOKALIKE_BLOCK empty)."""
    if not config.lookalike_block:
        logger.info("look-alike rule is off")
        return None
    checker = LookalikeChecker.from_files(config.brands_path, config.whitelist_path)
    logger.info("look-alike rule blocks: %s", ", ".join(sorted(config.lookalike_block)))
    return checker


def load_predictor(config: Settings) -> Predictor | None:
    """The trained model, or None (fail open) if it is missing or unusable."""
    if not config.model_path.exists():
        logger.warning("no model at %s; running without it (python -m ml.train)", config.model_path)
        return None
    try:
        predictor = Predictor.from_files(config.model_path, config.brands_path, config.whitelist_path)
    except Exception:  # a bad model file must not stop DNS
        logger.exception("could not load the model at %s; running without it", config.model_path)
        return None
    logger.info("model loaded from %s, blocking at %.2f", config.model_path, config.model_threshold)
    return predictor


def build_engine(config: Settings, cache: TTLCache[Verdict]) -> DecisionEngine:
    return DecisionEngine.from_files(
        config.whitelist_path,
        config.blacklist_path,
        cache,
        lookalike=load_lookalike(config),
        block_techniques=config.lookalike_block,
        scorer=load_predictor(config),
        threshold=config.model_threshold,
    )


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    cache: TTLCache[Verdict] = TTLCache(settings.verdict_cache_ttl)
    engine = build_engine(settings, cache)
    upstream = UpstreamResolver(
        str(settings.upstream_dns), settings.upstream_port, settings.upstream_timeout
    )
    database = Database(settings.db_path)
    _purge_old_logs(database)
    resolver = HisnResolver(settings, engine, upstream, database)
    udp, tcp = build_servers(resolver, settings.dns_host, settings.dns_port)

    udp.start_thread()
    tcp.start_thread()
    logger.info(
        "HISN DNS listening on %s:%d (UDP+TCP), upstream %s:%d",
        settings.dns_host,
        settings.dns_port,
        settings.upstream_dns,
        settings.upstream_port,
    )

    try:
        while True:
            time.sleep(PURGE_INTERVAL)
            _purge_old_logs(database)
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        udp.server.shutdown()
        tcp.server.shutdown()
        udp.server.server_close()
        tcp.server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
