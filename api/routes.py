"""JSON endpoints of the dashboard API. Every route needs a session (see ``api/app.py``).

- ``GET  /api/stats``        totals, daily counts, blocks by reason
- ``GET  /api/blocked``      most blocked domains
- ``GET  /api/devices``      devices, most targeted first
- ``GET  /api/recent``       latest blocked threats (``after`` = last id seen, for alerts)
- ``GET  /api/allowed``          sites the owner unblocked, and the latest unblock/re-block actions
- ``POST /api/allowed``          unblock a site (body ``{"domain": "..."}``)
- ``POST /api/allowed/delete``   block it again (body ``{"domain": "..."}``)
- ``POST /api/logs/delete``  delete every log entry (body ``{"confirm": "delete"}``)

Domains in the answers are attacker-controlled text. They are returned as JSON
strings and the dashboard only ever inserts them with ``textContent``.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, Response, jsonify, request

from dns_server.domain import InvalidDomainError, normalize_domain
from storage.db import Database

logger = logging.getLogger(__name__)

DEFAULT_DAYS = 14


class BadParameter(ValueError):
    pass


def int_param(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise BadParameter(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise BadParameter(f"{name} must be between {minimum} and {maximum}")
    return value


def domain_from_body() -> str:
    """The validated, normalized ``domain`` field of the JSON body."""
    body = request.get_json(silent=True)
    raw = body.get("domain") if isinstance(body, dict) else None
    if not isinstance(raw, str):
        raise BadParameter('send {"domain": "<site>"}')
    try:
        return normalize_domain(raw)
    except InvalidDomainError as exc:
        raise BadParameter(f"invalid domain: {exc}") from exc


def daily_series(rows: dict[str, tuple[int, int]], days: int, today: datetime) -> list[dict[str, Any]]:
    """One entry per UTC day for the last ``days`` days, oldest first; missing days are zero."""
    series = []
    for offset in range(days - 1, -1, -1):
        day = (today - timedelta(days=offset)).strftime("%Y-%m-%d")
        allowed, blocked = rows.get(day, (0, 0))
        series.append({"day": day, "allowed": allowed, "blocked": blocked})
    return series


def build_blueprint(database: Database, retention_days: int, clock: Callable[[], float] = time.time) -> Blueprint:
    api = Blueprint("api", __name__, url_prefix="/api")

    @api.errorhandler(BadParameter)
    def bad_parameter(exc: BadParameter) -> tuple[Response, int]:
        return jsonify(error=str(exc)), 400

    @api.get("/stats")
    def stats() -> Response:
        days = int_param("days", DEFAULT_DAYS, 1, 90)
        today = datetime.fromtimestamp(clock(), tz=timezone.utc)
        rows = {row.day: (row.allowed, row.blocked) for row in database.daily_stats(days)}
        daily = daily_series(rows, days, today)
        return jsonify(
            retention_days=retention_days,
            today=daily[-1],
            totals={
                "allowed": sum(d["allowed"] for d in daily),
                "blocked": sum(d["blocked"] for d in daily),
            },
            daily=daily,
            by_reason=database.blocked_by_reason(),
            doh_blocked=database.doh_count(),
            devices=len(database.device_stats(1000)),
        )

    @api.get("/blocked")
    def blocked() -> Response:
        limit = int_param("limit", 10, 1, 100)
        return jsonify(
            [
                {"domain": r.domain, "hits": r.hits, "reason": r.reason, "first_seen": r.first_seen, "last_seen": r.last_seen}
                for r in database.top_blocked(limit)
            ]
        )

    @api.get("/devices")
    def devices() -> Response:
        limit = int_param("limit", 20, 1, 200)
        return jsonify(
            [
                {"device": r.device, "requests": r.requests, "blocked": r.blocked, "last_seen": r.last_seen}
                for r in database.device_stats(limit)
            ]
        )

    @api.get("/recent")
    def recent() -> Response:
        after = int_param("after", 0, 0, 2**62)
        limit = int_param("limit", 20, 1, 100)
        return jsonify(
            [
                {"id": e.id, "ts": e.ts, "domain": e.domain, "reason": e.reason, "device": e.device}
                for e in database.recent_blocks(after, limit)
            ]
        )

    @api.get("/allowed")
    def allowed() -> Response:
        return jsonify(
            allowed=[
                {"domain": r.domain, "added_at": r.added_at, "was_reason": r.was_reason}
                for r in database.allowed_domains(200)
            ],
            actions=[{"ts": a.ts, "action": a.action, "domain": a.domain} for a in database.owner_actions(20)],
        )

    @api.post("/allowed")
    def unblock() -> Response:
        domain = domain_from_body()
        added = database.allow_domain(domain, ts=clock())
        logger.info("owner unblocked %s%s", domain, "" if added else " (already allowed)")
        return jsonify(domain=domain, added=added)

    @api.post("/allowed/delete")
    def reblock() -> tuple[Response, int]:
        domain = domain_from_body()
        if not database.remove_allowed(domain, ts=clock()):
            return jsonify(error="this site is not in the allowed list"), 404
        logger.info("owner blocked %s again", domain)
        return jsonify(domain=domain, removed=True), 200

    @api.post("/logs/delete")
    def delete_logs() -> tuple[Response, int]:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or body.get("confirm") != "delete":
            return jsonify(error='send {"confirm": "delete"} to delete every log entry'), 400
        database.delete_all_logs()
        return jsonify(deleted=True), 200

    return api
