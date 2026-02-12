"""Visual impersonation check (Phase 11, optional).

A site the model finds suspicious, but not suspicious enough to block, is
opened once in a locked-down headless browser on the HISN computer. Its
screenshot is reduced to a 64-bit perceptual hash (pHash) and compared with the
hashes of screenshots of the official sites. A page that looks like an official
site on a domain that is not official gets blocked from then on.

- ``ssrf_guard.py``: every host the browser asks for must resolve (through
  the upstream DNS server) to public addresses only, so the browser can never
  be pointed at the home network; the guard fetches every file itself.
- ``capture.py``: the headless browser, which connects to nothing itself.
- ``compare.py``: pHash and the closest official reference.
- ``reference_hashes.py``: builds ``data/references/hashes.json`` from
  screenshots of official sites.
- ``worker.py``: the separate program that works through the queue the DNS
  server fills.
- ``evaluate.py``: precision and recall of the visual match on its own.
"""
