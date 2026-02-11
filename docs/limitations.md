# Known limitations

Every result figure HISN reports depends on these points. Quote them next to any number.

## Data

- **Unreviewed labels.** Most malicious names come from PhishStats reports without a score
  (`--keep-unscored`). Nobody checked them. Tranco overlap removal and the per-owner limit remove
  most legitimate sites, but some noise remains in both directions.
- **Benign names have no dates.** Only the malicious side is split by time. Benign names are split
  at random with the same ratio, so the test set does not show how benign traffic changes over time.
- **Class ratio about 1:23** (8,644 malicious, 200,000 benign). Accuracy is meaningless here
  ("allow everything" scores about 96%), so only precision, recall and the confusion matrix are reported.
- **IP-address URLs are out of scope.** A DNS filter only sees names, so feed reports that use a bare
  IP address are dropped.
- **Feed names do not look like Saudi brands.** Phishing feeds are mostly random-looking names, so
  the model cannot learn brand look-alikes from them. That is why synthetic look-alikes and the
  look-alike rule exist (below).

## Synthetic look-alikes (`ml/typosquat.py`)

- They are generated, not observed attacks. Real attackers may use tricks the generator does not
  make (new words, longer combinations, other scripts).
- A generated name could, by chance, be a real legitimate site. Names already in the dataset keep
  their real label, but unregistered or unlisted names are labelled malicious without a check.
- Look-alikes of the held-out brands are never used in training, but the brand features (including
  the look-alike rule's verdict) still read the whole brand list. "Held-out brand" recall therefore
  measures a brand that is *in the list* and whose look-alikes the model never saw, not a brand
  missing from the list. It shows how well the model learned to trust the brand features, and it
  partly measures the rule itself.
- The rule and the generator were written together, so the rule's recall on generated names is a
  sanity check, not an independent measurement. Its false positives on the benign test names are
  the meaningful number.

## Look-alike rule (`ml/lookalike.py`)

- It only knows the brands in `data/lists/brands.txt` and only exempts the domains in
  `data/lists/whitelist.txt`. A brand whose official domain is missing from the whitelist makes the
  real site look like a look-alike (currently nafath and tawakkalna, until their domains are confirmed).
- Fuzzy matches (`typo`, `contains`) can hit real words close to a brand name (for example
  `alinea` for `alinma`, `asher` for `absher`). Exact, hyphenated and homoglyph matches are much stronger
  evidence.
- The Unicode look-alike table covers common Cyrillic and Greek letters only.

## In the DNS server (Phase 5)

- **Fail open.** If the model file is missing, broken, or fails on a name, the name is allowed and the
  problem is logged. Protection then rests on the lists and the look-alike rule only. This is on purpose:
  a broken model must not take the home network offline.
- **The rule blocks on its own.** `typo` matches (one or two letters away from a brand) block without the
  model, so a legitimate name close to a brand (for example `asher.com` for `absher`) is blocked until it
  is added to the whitelist. `contains` matches do not block on their own by default.
- **Blocking threshold.** 0.90 favours precision: on the current model it gives precision 0.933 and
  recall 0.184 on the temporal test split (319 of 1,729 phishing names caught, 23 of 40,000 benign names
  blocked), so most phishing names that only the model could catch are still allowed. The look-alike rule and the blacklist carry most of
  the protection. Re-check the threshold table in `python -m ml.evaluate` after every retraining.
- **Cached verdicts.** A verdict lasts up to one hour. A name that becomes dangerous within that hour, or
  a wrong block, stays as it was until the entry expires or the server restarts. The whitelist and
  blacklist always win over the cache.
- **Speed.** The first query for a new name runs the features and the forest (some milliseconds);
  repeats come from the cache. The domain-age lookup never adds to this (it runs in the background).
- **The model is loaded at startup.** After retraining, restart the server.

## Domain age (Phase 6)

- **Few training ages.** Ages come from `ml.fetch_domain_age`, one registry request per domain, so
  only a sample of the training names has one. Many old phishing domains were deleted after being
  reported (no record any more) or registered again (the date is after the report and is ignored),
  so the malicious side has fewer ages than the benign side.
- **The age table is an approximation.** It multiplies the forest's odds by how much more often an
  age range is malicious, which assumes the age tells something the name does not. Its ratios come
  from a few hundred domains per class and are capped at 10x, so treat them as rough. The forest's
  probabilities are not calibrated either (it weighs the rare class up), so the adjusted value is a
  score for ranking and thresholds, not an exact probability.
- **Benign ages are taken today, malicious ages on the report day.** Benign names have no date, so
  their age is measured when they were looked up. Tranco names are popular sites, which are usually
  old; a brand-new legitimate site (a new shop, a new government service) looks more like phishing
  to the model than an old one.
- **Not every suffix has RDAP.** Suffixes without an RDAP server in the IANA list (some country
  codes, possibly `.sa`) always have an unknown age, so for them the model judges the name alone.
- **Shared platforms have no age.** Phishing on free hosting (`x.netlify.app`, `x.pages.dev`,
  `x.duckdns.org`) is common, but the registry only knows the platform, so these hosts always have an
  unknown age and the model judges the name alone.
- **Some registries fail TLS checks.** A registry whose certificate chain cannot be verified is never
  trusted (checks are never turned off); its domains get an unknown age. The certifi root bundle is
  added to the system store to avoid the common Windows case of missing root certificates.
- **The first query is scored without the age.** The lookup runs in the background; until it
  finishes (and whenever it fails), the name is judged on its own.
- **Privacy.** Each lookup tells the registry of the suffix (for `.com`, Verisign) which registered
  domain someone on the network is visiting, plus the home IP address. Only the registered domain
  is sent, never the full host or the device. `HISN_DOMAIN_AGE_LOOKUP=false` turns lookups off.
- **Ages are cached in memory only.** A restart forgets them, so every domain is looked up again.
  Registries may rate-limit a busy network; a refused lookup simply means "age unknown" for an hour.
- **The age can be faked only by waiting.** Attackers can register domains early and use them later
  ("aged domains"); the age then gives no warning.

## Using HISN on a real network

- **One point of failure.** When every device uses HISN as its only DNS server, the network has no
  internet while the HISN computer is off, asleep or restarting. A second DNS server in the router
  would avoid that but lets devices skip HISN, so none is set.
- **The router must allow it.** Protecting the whole home needs a router whose DHCP settings can hand
  out HISN's address as the DNS server; some internet-provider routers lock this.
- **Devices can opt out.** A device with a manually set DNS server, a VPN, or Android "Private DNS"
  set to a provider's hostname does not ask HISN.

## DNS-over-HTTPS blocking (Phase 7)

- **Only names, not addresses.** HISN can only refuse to resolve a DoH server's *name*. A client
  configured with a DoH server's IP address (for example `https://1.1.1.1/dns-query`) never asks for
  a name and is not stopped. Blocking those addresses needs the router's firewall.
- **A forced setting wins.** If a user (or an app) turns DoH on explicitly, or picks "strict" or
  "max protection" mode, the browser may keep using DoH or stop resolving names instead of falling
  back. The Firefox canary only stops Firefox from turning DoH on *by itself*.
- **DNS-over-TLS** (Android "Private DNS", port 853) is not covered by this list. In "automatic" mode
  Android only tries DNS-over-TLS with the network's own DNS server (HISN, which does not offer it)
  and then uses normal DNS, so it is fine. A provider hostname typed in by the user is out of reach
  without a firewall rule on port 853.
- **The list goes stale.** New DoH providers appear; `doh_hosts.txt` needs occasional updates.
- **Private Relay notice.** Blocking `mask.icloud.com` turns iCloud Private Relay off on this network
  for every Apple device, and the user sees a notice explaining why.

## Block page (Phase 8)

- **HTTPS links show a browser error, not the page.** The block page cannot present a valid
  certificate for a blocked name, so `https://` links end in "site can't be reached". The phishing
  site still does not load. A local CA for the demo device is planned in `docs/https_block_page.md`.
- **Apps are not browsers.** An app that opens a blocked name just fails to connect; only web
  browsers show the page.
- **The reason can be general.** It is read from the decision log, so after the log is purged or
  deleted, or for a name not in it, the page shows a general reason.
- **Development web server.** The page runs on Werkzeug's built-in server, which is fine for a home
  network and the demo, not for exposure to the internet. Keep `HISN_BLOCK_PAGE_IP` on the local
  network.

## Dashboard (Phase 9)

- **The alert lives in the dashboard.** The owner sees new blocks only while the page is open (banner
  and tab count). There is no phone notification or e-mail; a mobile app for alerts is future work.
- **Devices are IP addresses.** A device is shown by its address on the network. With DHCP an address
  can move to another device, and phones with private (random) MAC addresses may get a new address.
- **Daily counts use UTC days.** The chart, the "today" tiles and the 30-day counts start their days at 03:00 Saudi time; the tables show local times.
- **One shared admin account.** Everyone who manages the network uses the same password; there are no
  separate users or permissions yet (possible future work). Only its scrypt hash is in the database.
  Sessions are kept in memory, last 8 hours and end when the dashboard restarts; there is no "remember
  me". A forgotten password is reset with `python -m api.set_password` on the HISN computer.
- **The account is created from the HISN computer.** On the first start, only a browser on that
  computer (127.0.0.1) can create the account, so another device cannot claim it first. If HISN runs on
  a machine with no screen, use `python -m api.set_password` there instead.
- **Plain HTTP on the local network.** The password (at login) and the session token travel unencrypted
  between the browser and the dashboard. That is acceptable on `127.0.0.1`; on a LAN address, anyone
  who can sniff the home network could read them.
- **An unblock trusts the owner.** An unblocked site is allowed for every device, together with its
  subdomains, even when it is on the blacklist. If the site turns malicious later, HISN will not block
  it until the owner presses "Block again". The change reaches devices within about half a minute (DNS
  caching), not instantly.
- **Development web server** (Werkzeug), as for the block page.

## Tiny whitelist

The whitelist holds a handful of official domains. Every brand added to `brands.txt` needs its
official domain confirmed from the organisation's own pages first (see `docs/brand_list_proposal.md`).

`edu.sa` is allowed as a whole zone (Saudi universities and schools), because only Saudi educational
institutions can register under it. A compromised site inside it is not blocked; HISN targets
impersonation, and an official domain that was broken into is out of its scope (the same holds for
every whitelisted domain).

## Optional visual check (Phase 11, not built)

If built, it only sees the homepage of a domain (DNS never sees the full URL), and phishing kits
can show bots a harmless page, so it complements the other checks and never replaces them.
