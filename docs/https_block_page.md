# HTTPS and the block page

## The problem

When HISN blocks a domain, the DNS answer points the browser at the block page
(`HISN_BLOCK_PAGE_IP`). That works for `http://` links: the browser connects on port 80 and shows
the page.

Most phishing links are `https://`. The browser then connects on port 443 and expects a
certificate for the blocked name, signed by an authority it trusts. HISN cannot have one: no
public authority will sign `absher-sa.com` for us, and that is exactly what keeps HTTPS safe.
So for an `https://` link the user sees a browser error instead of our message.

What the user sees today (Phase 8 serves plain HTTP only):

| Link | What happens |
| --- | --- |
| `http://absher-sa.com` | The block page. |
| `absher-sa.com` typed in the address bar | Chrome and Edge try HTTPS first; nothing answers on port 443, so they fall back to HTTP and show the block page (sometimes after a "not secure" notice). |
| `https://absher-sa.com/login` | "This site can't be reached" (connection refused). The user is still protected (the phishing site never loads), but the message is unclear. |

If port 443 answered with a self-signed certificate, the user would get a full-page certificate
warning instead. That is worse: it teaches people to click "Proceed anyway", and sites with HSTS
do not offer that button at all. So port 443 stays closed unless the local CA below is set up.

## The plan for the demo: a local certificate authority

1. **Create a local CA** once, on the HISN machine: a private key and a self-signed CA certificate,
   valid for a short time (for example 90 days), with a name that says what it is
   ("HISN demo CA - do not trust elsewhere"). Files go in `web/block_page/certs/` and are never
   committed (`.gitignore` already excludes `certs/`, `*.pem`, `*.key`, `*.crt`).
2. **Install the CA certificate on the demo device only** (the phone or laptop used in the demo),
   as a trusted root. Never install it on anyone else's device.
3. **Serve HTTPS on port 443** with a certificate made on the fly for each blocked name: the TLS
   handshake tells the server which name the browser wants (SNI); the server checks that the name
   was really blocked (the decision log), signs a short-lived certificate for that one name with
   the local CA, caches it, and shows the same block page. A name that was not blocked gets no
   certificate, so the CA cannot be used to impersonate an allowed site through HISN.
4. **Remove the CA from the demo device after the demo** and delete the key.

This needs the `cryptography` package (to sign certificates) and about 100 lines of code. It is not
built yet; it is a separate step after Phase 8 if wanted.

## Why the CA key is dangerous

Whoever has the CA key can create a valid-looking certificate for *any* site, for every device that
trusts the CA (banks included). So:

- The key never leaves the HISN machine, is readable by its owner only, and is never committed or
  shared.
- The CA is trusted on the demo device only, and only for the demo.
- Certificates are signed only for names HISN actually blocked.

## What real products do

Commercial filters either install a root certificate on every managed device (company networks,
parental-control apps) or accept the browser error for HTTPS. Pi-hole, for example, answers blocked
names with `0.0.0.0` and shows no page at all. A home user cannot be asked to install a root
certificate safely, so outside the demo HISN keeps port 443 closed: the phishing site still does
not load, which is what matters.
