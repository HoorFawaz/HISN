# HISN (حصن)

Network-level protection against phishing and fake websites. HISN acts as the DNS
server of a home network: every domain request is checked, and dangerous domains
are answered with the address of a block page.

> Status: Phase 3 (DNS server with lists, verdict cache and decision log; dataset preparation and domain features for the model). See the project brief for the full roadmap.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env               # optional, defaults are safe for development
```

## Check the setup

```bash
python -c "from config import settings; print(settings.dns_host, settings.dns_port)"
```

Expected output: `127.0.0.1 5353`.

## Run the DNS server (development)

```bash
python -m dns_server.server
```

It listens on `127.0.0.1:5353` (UDP and TCP). Port 5353 needs no admin rights; port 53 is only for the real demo.
Stop it with `Ctrl+C`. If another program already uses port 5353, set `HISN_DNS_PORT` to a free port in `.env`.

Query it from a second terminal (works on every OS):

```bash
python -c "import sys; from dnslib import DNSRecord; print(DNSRecord.parse(DNSRecord.question(sys.argv[1]).send('127.0.0.1', 5353, timeout=5)))" absher-sa.com
```

Replace the last word with any domain. A blocked domain answers `127.0.0.1` (the block page address).
`nslookup -port=...` is not reliable on Windows (it may ignore the port), so use the command above.
On Linux and macOS `dig @127.0.0.1 -p 5353 absher-sa.com` also works.

Blocked domains get the block page address (`HISN_BLOCK_PAGE_IP`). Everything else is forwarded to the upstream DNS.
Edit `data/lists/whitelist.txt` and `data/lists/blacklist.txt`, then restart the server.

## Logs and privacy

Every decision is stored in a local SQLite file (`data/hisn.db`, never committed): time, domain,
verdict, reason and the client address. Nothing else (no URLs, no answers). Invalid queries are not logged.

- Entries older than `HISN_LOG_RETENTION_DAYS` (default 30) are deleted at startup and every hour.
- Delete old entries now: `python -m storage.db purge`
- Delete everything: `python -m storage.db delete-all --yes`

Daily allow/block totals contain no domains or devices, so they are kept when old entries are purged
and removed only by `delete-all`.

Verdicts for unknown domains are cached in memory for `HISN_VERDICT_CACHE_TTL` seconds. The cache is
checked after the whitelist and blacklist, so editing a list always wins over a cached verdict.
It stays empty until the ML model (a later phase) starts storing verdicts in it.

## Prepare the data (Phase 3)

The model learns from public feeds. They are third-party data, so they stay in `data/raw/` and
`data/processed/`, which git ignores.

**1. Benign names (Tranco).** Download `https://tranco-list.eu/top-1m-incl-subdomains.csv.zip` (permanent link, no account)
and save it as `data/raw/tranco.csv.zip`. The subdomain version matches real DNS traffic.

**2. Phishing reports with dates (PhishStats).** Free, read access needs no account:

```bash
python -m ml.fetch_phishstats
```

Without a key the API allows 50 requests a day per IP; one request returns 100 reports, so a run gives about 4,500 reports
(roughly two weeks of data). Run it again on another day: it continues further back in time from where it stopped, and saves
only `id, url, first_seen, score`. A free key raises the limit; if you have one, set the environment variable
`PHISHSTATS_API_KEY` (never put it in a file inside the project). The labels are automatic (a `score` from the site, no human review).

Other sources work too if you save them in `data/raw/` with a name that starts with `phishtank` (PhishTank CSV) or pass
them with `--malicious` (for example URLhaus, which is malware rather than phishing and mostly uses bare IP addresses).

**3. Build the dataset:**

```bash
python -m ml.prepare_data
```

It writes `data/processed/dataset.csv` and prints a cleaning report. On purpose it: skips reports with a score below 5
(`--min-score`), drops IP-address hosts, duplicates and overlap between the two classes, keeps at most 50 hosts per owner or
platform (`--max-per-key`, so one free-hosting service cannot become the whole malicious set), samples the benign list at random
(200,000 by default, `--benign-limit`), and splits by time: the **newest** malicious domains form the test set, and hosts of one
registered domain never end up on both sides. Benign names have no date, so they are split at random with the same ratio.
Read the "Dataset" lines in the output: if the two classes differ a lot on something unrelated to phishing, the model could
learn the data source instead.

PhishStats leaves the `score` empty for most reports (about 80% in our downloads), and the few scored ones are mostly
IP-address URLs, which a DNS filter never sees. Without `--keep-unscored` almost nothing usable is left. With it, reports without
a score are kept (reports with a low score are still dropped). **Their labels were never checked by anyone**; Tranco overlap
removal and the per-owner limit remove most legitimate sites, but some noise remains. This limitation must be stated with any
accuracy figure.

```bash
python -m ml.prepare_data --keep-unscored
```

`ml/features.py` turns a domain into numbers (length, hyphens, digits, subdomain depth, keywords, entropy, TLD, brand similarity,
government impersonation). It needs no network and takes about 60 microseconds per name.

Brands in `data/lists/brands.txt` need their official domain in `data/lists/whitelist.txt`, otherwise the real site looks like
an impersonation. Add them together, and only after checking the domain on the organisation's own pages.

## Run the tests

```bash
python -m pytest
```

## Security notes

- Never commit `.env`, certificates, datasets or databases (see `.gitignore`).
- Run `pip-audit -r requirements.txt` before every release.
