"""Build the official reference hashes the visual check compares against.

The references are screenshots of the official pages that phishing kits copy
(home and login pages of the protected brands). They live in
``data/references/`` as PNG files named ``<brand>--<anything>.png``; the PNG
files are the source of truth and ``hashes.json`` is rebuilt from them.

Two ways to add a reference (run from the project root, in a normal window,
not as administrator)::

    # 1. Photograph every page listed in data/references/references.txt
    python -m ml.visual.reference_hashes

    # 2. Add a screenshot you took yourself (for example a login page that
    #    only appears after a click). Maximise the browser first: the check
    #    photographs a 1900 x 900 window, so pages lay out the same way
    python -m ml.visual.reference_hashes --add alrajhi path/to/login.png

    # Rebuild hashes.json from the PNG files only, without the browser
    python -m ml.visual.reference_hashes --no-capture

Every page in ``references.txt`` must be on a whitelisted (official) domain:
a reference taken from a look-alike site would teach HISN that the fake site
is the real one.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dns_server.domain import InvalidDomainError, normalize_domain, parent_domains
from ml.visual.compare import Reference, from_hex, header_hash, is_nearly_empty, phash, to_hex

HASHES_FILE = "hashes.json"
PAGES_FILE = "references.txt"
_BRAND_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_SEPARATOR = "--"  # brand--name.png
REFERENCE_SHOTS = 3  # screenshots per official page


class ReferenceError(ValueError):
    """A references.txt line or a reference file is invalid."""


@dataclass(frozen=True)
class OfficialPage:
    brand: str
    url: str
    host: str
    path: str


def check_brand(brand: str) -> str:
    if not _BRAND_RE.match(brand):
        raise ReferenceError(f"brand must be lowercase letters, digits and hyphens: {brand!r}")
    return brand


def is_official(host: str, whitelist: frozenset[str]) -> bool:
    return any(candidate in whitelist for candidate in parent_domains(host))


def parse_pages(path: Path, whitelist: frozenset[str]) -> list[OfficialPage]:
    """Read ``references.txt``: ``brand https://official.page/path`` per line."""
    pages: list[OfficialPage] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ReferenceError(f"{path.name}:{number}: expected 'brand url'")
        brand, url = parts
        try:
            check_brand(brand)
            split = urlsplit(url)
            if split.scheme != "https" or split.port is not None or split.username or split.query:
                raise ReferenceError("the URL must be https://host/path with no port, login or query")
            host = normalize_domain(split.hostname or "")
        except (ReferenceError, InvalidDomainError, ValueError) as exc:
            raise ReferenceError(f"{path.name}:{number}: {exc}") from exc
        if not is_official(host, whitelist):
            raise ReferenceError(f"{path.name}:{number}: {host} is not on the whitelist (official domains only)")
        pages.append(OfficialPage(brand, url, host, split.path or "/"))
    return pages


def file_name(brand: str, label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:60] or "page"
    return f"{brand}{_SEPARATOR}{slug}.png"


def build_hashes(directory: Path) -> list[Reference]:
    """Hash every ``brand--*.png`` in ``directory`` and write ``hashes.json``."""
    references: list[Reference] = []
    for png in sorted(directory.glob("*.png")):
        brand, separator, _ = png.stem.partition(_SEPARATOR)
        if not separator or not _BRAND_RE.match(brand):
            print(f"  ignored {png.name}: name it <brand>--<anything>.png")
            continue
        data = png.read_bytes()
        if is_nearly_empty(data):
            print(f"  ignored {png.name}: nearly empty (an error page or a bot check?); take a screenshot by hand")
            continue
        references.append(Reference(brand, png.name, phash(data), header_hash(data)))
    payload = {
        "built_at": int(time.time()),
        "references": [
            {"brand": r.brand, "source": r.source, "hash": to_hex(r.hash)}
            | ({"header": to_hex(r.header)} if r.header is not None else {})
            for r in references
        ],
    }
    (directory / HASHES_FILE).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return references


def load_references(directory: Path) -> list[Reference]:
    """The references in ``directory/hashes.json`` ([] if it does not exist yet)."""
    path = directory / HASHES_FILE
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return [
            Reference(
                check_brand(str(item["brand"])),
                str(item["source"]),
                from_hex(str(item["hash"])),
                from_hex(str(item["header"])) if "header" in item else None,
            )
            for item in payload["references"]
        ]
    except (ValueError, KeyError, TypeError) as exc:
        raise ReferenceError(f"{path} is damaged ({exc}); rebuild it with --no-capture") from exc


Capture = Callable[[OfficialPage], Sequence[bytes]]


def capture_pages(pages: Sequence[OfficialPage], directory: Path, capture: Capture) -> int:
    """Photograph ``pages`` into ``directory``; returns how many screenshots were saved.

    Each page gives several screenshots a few seconds apart, so a home page
    with a rotating banner has a reference for each banner it showed.
    """
    saved = 0
    for page in pages:
        try:
            images = capture(page)
        except Exception as exc:  # one unreachable site must not stop the others
            print(f"  skipped {page.url}: {exc}")
            continue
        stem = file_name(page.brand, f"{page.host}{page.path}")[: -len(".png")]
        usable = [png for png in images if not is_nearly_empty(png)]
        if not usable:
            print(
                f"  skipped {page.url}: the site showed an empty page, an error or a bot check "
                f"(add a screenshot by hand: --add {page.brand} file.png)"
            )
            continue
        for old in directory.glob(f"{stem}*.png"):  # a page photographed again replaces its old shots
            old.unlink()
        for number, png in enumerate(usable, start=1):
            name = f"{stem}-{number}.png"
            (directory / name).write_bytes(png)
            saved += 1
            print(f"  saved {name}")
    return saved


def main(argv: Sequence[str] | None = None) -> int:
    from config import settings
    from dns_server.decision import load_domain_list
    from dns_server.resolver import UpstreamResolver
    from ml.visual.capture import CaptureError, capture, privilege_problem
    from ml.visual.ssrf_guard import GuardedFetcher, GuardError, UpstreamLookup

    parser = argparse.ArgumentParser(prog="python -m ml.visual.reference_hashes", description=__doc__.split("\n")[0])
    parser.add_argument("--add", nargs=2, metavar=("BRAND", "PNG"), help="add a screenshot you took yourself")
    parser.add_argument("--no-capture", action="store_true", help="only rebuild hashes.json from the PNG files")
    args = parser.parse_args(argv)

    directory = settings.references_dir
    directory.mkdir(parents=True, exist_ok=True)
    try:
        if args.add:
            brand, source = check_brand(args.add[0]), Path(args.add[1])
            if not source.is_file():
                raise ReferenceError(f"{source} not found")
            if is_nearly_empty(source.read_bytes()):
                raise ReferenceError(f"{source} is nearly empty: it must show the site's page")
            target = directory / file_name(brand, source.stem)
            shutil.copyfile(source, target)
            print(f"  added {target.name}")
        elif not args.no_capture:
            problem = privilege_problem()
            if problem:
                print(f"Not started: {problem}.", file=sys.stderr)
                return 1
            pages = parse_pages(directory / PAGES_FILE, load_domain_list(settings.whitelist_path))

            lookup = UpstreamLookup(
                UpstreamResolver(str(settings.upstream_dns), settings.upstream_port, settings.upstream_timeout)
            )

            def official(page: OfficialPage) -> list[bytes]:
                # Exactly the same browser and guard as the checks, so a check of
                # the official page itself sees what its reference saw.
                try:
                    return capture(
                        page.host,
                        GuardedFetcher(lookup),
                        path=page.path,
                        shots=REFERENCE_SHOTS,
                        timeout=settings.visual_timeout,
                        browser_path=settings.visual_browser_path,
                    )
                except (CaptureError, GuardError) as exc:
                    raise RuntimeError(str(exc)) from exc

            capture_pages(pages, directory, official)
        references = build_hashes(directory)
    except (ReferenceError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    brands = sorted({r.brand for r in references})
    print(f"{len(references)} reference(s) for {len(brands)} brand(s) in {directory / HASHES_FILE}: {', '.join(brands)}")
    return 0 if references else 1


if __name__ == "__main__":
    raise SystemExit(main())
