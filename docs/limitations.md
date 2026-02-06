# Known limitations

Every result figure HISN reports depends on these points. Quote them next to any number.

## Data

- **Unreviewed labels.** Most malicious names come from PhishStats reports without a score
  (`--keep-unscored`). Nobody checked them. Tranco overlap removal and the per-owner limit remove
  most legitimate sites, but some noise remains in both directions.
- **Benign names have no dates.** Only the malicious side is split by time. Benign names are split
  at random with the same ratio, so the test set does not show how benign traffic changes over time.
- **Class ratio about 1:43** (4,606 malicious, 200,000 benign). Accuracy is meaningless here
  ("allow everything" scores over 97%), so only precision, recall and the confusion matrix are reported.
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
- **Blocking threshold.** 0.90 favours precision: on the first Phase 4 run (before the look-alike
  features) it gave precision 0.96 and recall 0.15 on the temporal test split, so most phishing names
  that only the model could catch are still allowed. The look-alike rule and the blacklist carry most of
  the protection. Re-check the threshold table in `python -m ml.evaluate` after every retraining.
- **Cached verdicts.** A verdict lasts up to one hour. A name that becomes dangerous within that hour, or
  a wrong block, stays as it was until the entry expires or the server restarts. The whitelist and
  blacklist always win over the cache.
- **Speed.** The first query for a new name runs the features and the forest (some milliseconds);
  repeats come from the cache.
- **The model is loaded at startup.** After retraining, restart the server.

## Tiny whitelist

The whitelist holds a handful of official domains. Every brand added to `brands.txt` needs its
official domain confirmed from the organisation's own pages first (see `docs/brand_list_proposal.md`).

## Optional visual check (Phase 11, not built)

If built, it only sees the homepage of a domain (DNS never sees the full URL), and phishing kits
can show bots a harmless page, so it complements the other checks and never replaces them.
