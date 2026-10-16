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
- Look-alikes of the held-out brands are never used in training, but the brand features still read
  the whole brand list. "Held-out brand" recall therefore measures a brand that is *in the list* and
  whose look-alikes the model never saw, not a brand missing from the list.
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

## Tiny whitelist

The whitelist holds a handful of official domains. Every brand added to `brands.txt` needs its
official domain confirmed from the organisation's own pages first (see `docs/brand_list_proposal.md`).

## Optional visual check (Phase 11, not built)

If built, it only sees the homepage of a domain (DNS never sees the full URL), and phishing kits
can show bots a harmless page, so it complements the other checks and never replaces them.
