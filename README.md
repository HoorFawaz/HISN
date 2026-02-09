# HISN (حصن)

Network-level protection against phishing and fake websites. HISN acts as the DNS
server of a home network: every domain request is checked, and dangerous domains
are answered with the address of a block page.

> Status: Phase 9 (DNS server with lists, verdict cache and decision log; dataset, domain features, look-alike handling, model training and evaluation; the look-alike rule and the model decide unknown names in the server; the model also uses the domain age when it is known; DNS-over-HTTPS servers get NXDOMAIN so browsers cannot bypass HISN; a block page explains why a site was blocked; a dashboard shows blocked threats, targeted devices and alerts). See the project brief for the full roadmap.

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

### How a name is decided (Phase 5)

The first step that gives an answer wins:

1. whitelist (always allow), then the sites the owner unblocked in the dashboard (allow, see Dashboard),
2. blacklist (always block), 3. verdict cache,
4. look-alike rule: a name that imitates a brand in `brands.txt` is blocked on its own,
5. model: blocked if its probability is at least `HISN_MODEL_THRESHOLD` (default 0.90), otherwise allowed.
   The domain age is one of its inputs when it is already known (Phase 6, below),
6. default: allow.

Only steps 4 and 5 store their verdict in the cache. `HISN_LOOKALIKE_BLOCK` lists the look-alike
techniques that block on their own (default `brand_name,hyphenation,homoglyph,typo`; leave it empty to
turn the rule off). `contains` (the brand inside a longer word) is left to the model by default, because
a bank's own sister companies look like that.

The model is loaded once at startup from `HISN_MODEL_PATH`. If the file is missing or broken, the server
logs a warning and runs without it; if the model fails on a name, that name is allowed and the error is
logged. After retraining, restart the server. The first query for a new name takes some milliseconds
longer (feature extraction and the forest); repeats come from the cache.

The reason of every decision (`whitelist`, `owner`, `blacklist`, `cache`, `lookalike`, `model`, `default`) is in
the log, so you can see why a name was blocked:

```bash
python -c "from storage.db import Database; [print(r.verdict, r.reason, r.domain) for r in Database('data/hisn.db').recent_requests(10)]"
```

### Domain age (Phase 6)

Newly registered domains are riskier. When the model scores a name, the server also asks for the
registration date of its registered domain (`example.com` for `login.example.com`) from RDAP, the
JSON successor of WHOIS that registries serve over HTTPS. The lookup runs in background threads and
**never delays the DNS answer**:

- the first query for a domain is scored on the name alone, and that verdict is not cached;
- once the lookup has finished (usually within a second), the next query is scored with the age and
  that verdict is cached as before;
- a missing age (no RDAP server for the suffix, timeout, error, deleted domain) means "unknown",
  which never blocks on its own.

Registration dates are kept in memory for `HISN_DOMAIN_AGE_CACHE_TTL` seconds (default 7 days);
"no data" answers are retried after a day, failures after an hour. Hosts on shared platforms
(`x.netlify.app`, `x.duckdns.org`) are never looked up and always have an unknown age. Lookups send the registered domain
(never the full host) to the registry of its suffix. Set `HISN_DOMAIN_AGE_LOOKUP=false` to turn them
off; the model then scores names only.

### DNS-over-HTTPS blocking (Phase 7)

Browsers that use DNS-over-HTTPS (DoH) send their lookups straight to a public resolver over HTTPS,
so HISN would never see them. Before using DoH they look up the DoH server's own name through the
normal DNS, and HISN answers that with NXDOMAIN ("no such name"). Most browsers then fall back to
the network's DNS, which is HISN. This step comes before the whitelist and the blacklist.

- The DoH servers are listed in `data/lists/doh_hosts.txt` (Google, Cloudflare, Quad9, OpenDNS,
  NextDNS and others). Subdomains match too, on label boundaries. Edit the file and restart.
- `use-application-dns.net` is always answered NXDOMAIN: it is Firefox's documented signal that the
  network filters DNS on purpose, and Firefox then keeps its automatic DoH off.
- `mask.icloud.com` and `mask-h2.icloud.com` are listed so Apple devices turn iCloud Private Relay
  off on this network (they show the user a notice).
- These answers are logged with the reason `doh`. Set `HISN_DOH_BLOCK=false` to turn it off.

Check it (each should print `status: NXDOMAIN`):

```bash
python -c "import sys; from dnslib import DNSRecord; print(DNSRecord.parse(DNSRecord.question(sys.argv[1]).send('127.0.0.1', 5353, timeout=5)))" dns.google
```

A DoH server set up by its IP address, a browser where the user forced DoH on, and DNS-over-TLS
(port 853) are not stopped by this; see [docs/limitations.md](docs/limitations.md).

## Block page (Phase 8)

A blocked name resolves to `HISN_BLOCK_PAGE_IP`, so the browser lands on the block page instead of
the real site. Run it in a second terminal, next to the DNS server:

```bash
python -m web.block_page.app
```

It listens on `HISN_BLOCK_PAGE_IP` port `HISN_BLOCK_PAGE_PORT` (default `127.0.0.1:80`). Every path
shows the same page, in Arabic and English: "This site was blocked as suspected fraud", the blocked
name, a simple reason, advice, and a "Back to safety" button (goes to `HISN_BLOCK_PAGE_SAFE_URL`,
default `https://www.google.com/`).

The reason comes from the decision log (`data/hisn.db`): reported fraud site (blacklist), impersonates a
known organization (look-alike rule), or resembles known fraud names (model). A name that is not
in the log (purged or deleted) gets a general "classified as unsafe" line.

Check it with a browser at `http://127.0.0.1/` (no name is shown when the page is opened by its
address), or pretend to be a blocked site:

```bash
curl -H "Host: absher-sa.com" http://127.0.0.1/login
```

On Windows PowerShell use `curl.exe` (plain `curl` is a different command there). If port 80 is
taken, set `HISN_BLOCK_PAGE_PORT` to a free port such as 8081; real browsers only use port 80, so that
is for testing.

The Arabic and English text uses IBM Plex Sans Arabic, bundled in `web/block_page/static/fonts/`
(SIL Open Font License, `OFL.txt` next to it), so the page needs no internet.

The page runs no script, is never framed or cached, escapes the host name, and never reads what a
phishing form posts to it. It serves plain HTTP only: an `https://` link shows a browser error instead
of the page. The plan for that is in [docs/https_block_page.md](docs/https_block_page.md).

## Dashboard (Phase 9)

The dashboard shows what HISN blocked: threats blocked over the last 14 days and today, requests per
day and blocks by reason (Chart.js charts), the latest blocks, the most blocked sites, the targeted
devices (most blocked threats first) and DoH bypass attempts stopped. When something new was blocked
since the owner last pressed "OK", an alert banner lists it (the page refreshes every 15 seconds and
the browser tab shows the count). DoH lookups are logged but are not counted as threats.

There is one account, the admin, shared by the people who manage the home network; each device signs
in and out on its own. The pages are in Arabic or English (the ع|E button at the top), in dark or light
mode (the ☾/☀ button next to it); both choices are remembered in the browser.

1. Start the dashboard in another terminal (next to the DNS server and the block page):

   ```bash
   python -m api.app
   ```

2. The first time, open `http://127.0.0.1:8080/` **on the HISN computer itself** and create the account
   (username, then a password of at least 12 characters, twice). For safety this works only from that
   computer and only once, so nobody else on the network can claim the account first.

3. From then on, open the dashboard from any device on the home network and sign in with the username and
   password (the username ignores upper/lower case).
   It works on a phone or a laptop.

Forgotten password: run this on the HISN computer, then restart the dashboard:

```bash
python -m api.set_password
```

Security: it refuses to start on an address that is not loopback or private (`HISN_API_HOST`, default
`127.0.0.1`), and only `HISN_ALLOWED_NETWORKS` clients get an answer. Only a salted scrypt hash of the
password is kept, in the database. Signing in returns a random session token (8 hours, kept in memory,
so a restart signs everyone out); every other `/api/` call needs `Authorization: Bearer <session token>`.
The page keeps the token in the browser tab only (no cookie, so no CSRF) and never stores the password.
Wrong sign-ins are limited to 10 per 10 minutes per client (the answer never says whether the
username or the password was wrong), and all requests to 240 per minute. Domains
are shown with `textContent` only (no HTML), and a strict Content Security Policy allows no inline
script. "Delete logs" wipes the whole log, like `python -m storage.db delete-all --yes`; the account and
the unblocked sites stay.

**Unblocking a site.** If HISN blocked a site by mistake, press "فك الحظر" (Unblock) next to it in
"Most blocked sites". It is then allowed for every device, even if it is on the blacklist or the rule or
the model would block it, and its subdomains too. The DNS server reads the change from the database
within about 2 seconds, with no restart; devices may keep the block for up to 30 seconds more (the
block answer's TTL) and browsers a little longer. The "Unblocked sites" card lists these sites with the
reason they had been blocked, and "إعادة الحجب" (Block again) puts the normal checks back. The list is a
setting, kept when logs are purged or deleted; each unblock and re-block is also logged. DNS-over-HTTPS
hosts cannot be unblocked this way.

API (JSON): `GET /api/setup` says whether the account exists; `POST /api/setup` with
`{"username", "password", "confirm"}` creates it (first start, HISN computer only); `POST /api/login` with
`{"username": "...", "password": "..."}` returns `{"token", "expires_in"}`. With the token: `GET /api/me`,
`GET /api/stats`, `/api/blocked`, `/api/devices`, `/api/recent?after=<id>`, `/api/allowed`,
`POST /api/allowed` and `POST /api/allowed/delete` with `{"domain": "..."}`, `POST /api/logout`,
`POST /api/logs/delete` with `{"confirm": "delete"}`.

Chart.js 4.4.7 is bundled in `web/dashboard/vendor/` (MIT license next to it) and the logo font Aref Ruqaa
in `web/dashboard/fonts/` (SIL Open Font License, `OFL.txt` next to it), so the dashboard needs no internet.
The header art (`web/dashboard/banner.svg`) is an original drawing made for HISN.

## Logs and privacy

Every decision is stored in a local SQLite file (`data/hisn.db`, never committed): time, domain,
verdict, reason and the client address. Nothing else (no URLs, no answers). Invalid queries are not logged.

- Entries older than `HISN_LOG_RETENTION_DAYS` (default 30) are deleted at startup and every hour.
- Delete old entries now: `python -m storage.db purge`
- Delete everything: `python -m storage.db delete-all --yes`

Daily allow/block totals contain no domains or devices, so they are kept when old entries are purged
and removed only by `delete-all`.

Verdicts of the look-alike rule and the model are cached in memory for `HISN_VERDICT_CACHE_TTL` seconds
(default one hour, at most 10,000 names). The cache is checked after the whitelist and blacklist, so
editing a list always wins over a cached verdict.

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
government impersonation, and the look-alike rule's verdict). It needs no network and takes about half a millisecond per name
with the shipped brand list (more brands make it slower).

Brands in `data/lists/brands.txt` need their official domain in `data/lists/whitelist.txt`, otherwise the real site looks like
an impersonation. Add them together, and only after checking the domain on the organisation's own pages.

## Train and evaluate the model (Phase 4)

Phishing feeds are mostly random-looking names, so they teach the model nothing about names that
imitate Saudi brands (`absher-sa.com`, `abhser.com`). Two additions cover that:

- `ml/typosquat.py` generates look-alikes of every brand in `brands.txt` (missing letter, swapped
  letters, look-alike letters and digits including punycode, hyphens, brand plus a word, another
  suffix). Every brand gets the same number of names per technique, so rare tricks (swaps, hyphens)
  weigh as much as common ones. Training adds them as malicious examples, except for the brands held
  out for evaluation.
- `ml/lookalike.py` is a fixed rule that flags a name that looks like a brand but is not on its
  official domain. It needs no training. Its verdict is also a model feature, so the model handles
  swapped letters and hyphens. The server will use it from Phase 5.

Train (needs `data/processed/dataset.csv` from Phase 3):

```bash
python -m ml.train
```

It writes `ml/models/hisn_rf.joblib` (never committed). Only load model files you trained yourself.

Evaluate:

```bash
python -m ml.evaluate
```

It prints separate results: precision, recall and the confusion matrix on the newest phishing
names (the temporal test split, scored on the name alone), the model's recall on look-alikes of held-out brands, by brand and
by technique, and the rule's recall plus how many benign test names it wrongly flags. Accuracy is not
shown: with about 1 malicious name per 43 benign ones it says nothing. `--threshold 0.6` tries another
blocking threshold (default `HISN_MODEL_THRESHOLD`).

To also test a trick the model never saw, hold a technique out of training:

```bash
python -m ml.train --holdout-technique transposition
```

### Domain ages for training (Phase 6)

The model can only learn from the age if some training names have one. Look them up once (no key
needed, about one second per domain on purpose, so the registries are not flooded):

```bash
python -m ml.fetch_domain_age --max-lookups 300
```

It picks registered domains from `dataset.csv` at random, half malicious and half benign, and appends
the answers to `data/processed/domain_age.csv` (never committed). Run it again to add more; domains
already answered are skipped. Failed lookups are marked `failed` and skipped too; add `--retry-failed`
to try them again. Hosts on shared platforms (`x.netlify.app`, `x.duckdns.org`, `pub-….r2.dev`) are never
looked up, because the registry only knows the platform. Then retrain and evaluate:

```bash
python -m ml.train
python -m ml.evaluate
```

`ml.train` uses the file when it exists. A malicious name's age is taken on the day it was reported,
a benign name's on the day it was checked. The age is **not** a forest feature: only a small sample of
names has one, and a mostly empty column teaches the forest the wrong thing. Instead the forest judges
the name alone, and an **age table** (`ml/age_table.py`) learned from the train rows with an age moves
its probability: for each age range (under 7 days, 7-30 days, ... over 10 years) it stores how much more
often that range is malicious than benign, capped at 10x either way. An unknown age changes nothing,
and the cap means a brand-new domain with a clean-looking name is still allowed. `ml.train` prints
the table; `ml.evaluate` adds a fourth result: the age of each class, the table, and the test names
with a known age scored with and without it. Without the file (or with fewer than 30 aged train
rows per class) there is no table and the model scores names only.

The model file format changed in Phase 6, so an older model is refused at startup and the server
runs without a model until you retrain.

**Every number depends on labels nobody reviewed and on generated look-alikes.** Read
[docs/limitations.md](docs/limitations.md) before quoting one. A larger brand list is proposed in
[docs/brand_list_proposal.md](docs/brand_list_proposal.md); its domains must be confirmed first.

## Run the tests

```bash
python -m pytest
```

## Security notes

- Never commit `.env`, certificates, datasets or databases (see `.gitignore`).
- Run `pip-audit -r requirements.txt` before every release.
