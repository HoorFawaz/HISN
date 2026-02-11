# Demo

A walk-through that shows every part of HISN on one computer in about ten minutes. It uses
"Option A: one computer" from the README ([Use HISN for real](../README.md#use-hisn-for-real)), so
nothing on the home network changes.

## Before the demo

1. The model is trained (`python -m ml.train`) and `python -m ml.evaluate` runs.
2. `.env` has `HISN_DNS_PORT=53`. The other addresses stay at `127.0.0.1`.
3. The dashboard account exists (open `http://127.0.0.1:8080/` once and create it).
4. Pick the names for the model step and write them down:

   ```bash
   python -m ml.demo_names
   ```

   It prints new phishing names that only the model blocks (no list or rule covers them) and benign
   names it allows. They come from unreviewed feeds and may still be live: query them only while HISN
   is running.
5. In the browser settings, turn off "Use secure DNS" if it is set to a fixed provider.

## Start

Open three PowerShell windows **as administrator** (ports 53 and 80 need it). In each, go to the
project folder and activate `.venv`, then run one program per window:

```bash
python -m dns_server.server
```

```bash
python -m web.block_page.app
```

```bash
python -m api.app
```

Then point the computer's DNS at HISN: Settings > Network & internet > Wi-Fi or Ethernet > DNS
server assignment > Edit > Manual, IPv4 on with `127.0.0.1`, IPv6 off. Clear the old answers and
restart the browser:

```bash
ipconfig /flushdns
```

Open the dashboard at `http://127.0.0.1:8080/` in one tab and sign in.

## Show it

Type each name in the address bar as `http://name` (an `https://` link shows the browser's "site
can't be reached" error instead of the block page, which still means it was blocked; see
[https_block_page.md](https_block_page.md)).

| # | Open | What happens | Why (decision step) |
| --- | --- | --- | --- |
| 1 | `google.com` | The site opens | Nothing matches, the model gives a low score: allowed |
| 2 | `absher.sa` | The real site opens | Whitelist: the official domain and its subdomains are always allowed |
| 3 | `absher-sa.com` | HISN block page: reported fraud site | Blacklist (checked before the look-alike rule) |
| 4 | `alrajhi-bank.com` | Block page: impersonates a known organization | Look-alike rule (brand name on a foreign domain) |
| 5 | `a1rajhi.com` | Block page: impersonates a known organization | Look-alike rule (digit `1` for letter `l`) |
| 6 | `abshr.sa` | Block page: impersonates a known organization | Look-alike rule (one letter missing) |
| 7 | a name from `ml.demo_names` | Block page: resembles known fraud names | Model, probability at least 0.90 |
| 8 | `dns.google` | The browser says the site cannot be reached | DoH blocking: answered "no such name" so the browser keeps using HISN |

The DNS server window logs each decision with its reason. Point out that the official site in step 2
contains the brand name too: HISN matches on label boundaries, so `absher.sa.fake-login.com` would
not pass as official.

Then switch to the dashboard tab (it refreshes every 15 seconds):

1. The **alert banner** lists the new blocks; press "OK".
2. **Threats blocked**, **Latest blocks** (site, reason, device, time) and the **reasons** chart now
   show steps 3 to 7. DoH attempts are counted separately, not as threats.
3. Press **Unblock** on `alrajhi-bank.com` and confirm. It moves to **Manually allowed sites**. Run
   `ipconfig /flushdns` and reload it: HISN no longer answers with the block page (the change applies
   within 2 seconds, no restart), so the browser gets the real answer, or "cannot be reached" if the name
   is not registered. Press **Block again** to undo.
4. Switch **ع | E** and the dark/light mode, and show the page on a phone width if there is time.

## Talking points

- **Why DNS:** every device asks DNS before opening a site, so one server protects the whole home
  with nothing installed on the devices. The home network set-up is "Option B" in the README.
- **Decision order:** whitelist, owner's unblocked sites, blacklist, cache, look-alike rule, model,
  allow ([architecture.md](architecture.md)). Lists always win; a broken model never blocks the
  internet (fail open).
- **The numbers:** the README [Results](../README.md#results) table, with its limits: unreviewed
  labels and generated look-alikes ([limitations.md](limitations.md)).
- **Privacy:** decisions and logs stay on this computer. Logs are kept in `data/hisn.db` for 30 days and
  "Delete logs" removes them. Allowed names are forwarded to the upstream DNS (1.1.1.1 by default), as
  any DNS server does, and the domain-age lookup asks public registries in the background.

## After the demo

Set the computer's DNS back to automatic **first**, then stop the three programs with `Ctrl+C`.
Without HISN running, a computer still pointed at `127.0.0.1` has no internet.
