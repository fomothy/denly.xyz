# denly.xyz — landing page

One static page plus one serverless function for the waitlist.

```
site/                     published output
├── index.html            the page
├── thanks.html           served at /thanks — where the form lands without JS
├── style.css
├── app.js                in-place form submit (optional; form works without it)
├── denly-fox.png         hero, 350x420
├── denly-fox-mark.png    nav and footer mark, 106x128
├── denly-fox-512.png     favicon and og:image
├── _headers              response headers + CSP
└── _routes.json          keeps static requests off the Functions bill

functions/                NOT inside site/ — see below
└── api/
    └── subscribe.js      POST /api/subscribe → Resend
```

## Why there is a function at all

The Resend API key must never reach the browser. A form posting straight to
`api.resend.com` would have to ship the key in the page, and anyone could then
read the contact list or send mail as the domain. The function is the smallest
thing that keeps the key server-side.

It also means the form degrades properly: it is a real `<form>` that posts and
redirects to `/thanks` with JavaScript disabled, and submits in place when
`app.js` runs.

## Deploy on Cloudflare Pages

The domain is already on Cloudflare, so this is Pages plus a DNS record.

1. **Workers & Pages → Create → Pages → Connect to Git**, pick
   `fomothy/denly.xyz`.
2. Build settings:

   | Setting | Value |
   |---|---|
   | Framework preset | None |
   | Build command | `cp install.sh site/install.sh` |
   | Build output directory | `site` |
   | Root directory | `/` |

   The build command exists for one reason: it publishes the real `install.sh`
   from the repo root at `denly.xyz/install.sh`, so the installer people pipe
   into their shell can never drift from the one CI tests.

3. **Settings → Variables and Secrets**, for both Production and Preview:

   | Name | Type | Value |
   |---|---|---|
   | `RESEND_API_KEY` | Secret (encrypted) | `re_…` from [resend.com/api-keys](https://resend.com/api-keys) — **Sending access is not enough; it needs Contacts write** |
   | `RESEND_SEGMENT_ID` | Plaintext, optional | A segment ID if you want waitlist signups tagged |

   Without `RESEND_API_KEY` the form returns a 500 and logs the reason; it never
   reveals the misconfiguration to visitors.

4. **Custom domains → `denly.xyz`.** Cloudflare creates the DNS records and
   issues the certificate.

Every push to `main` redeploys; pull requests get preview URLs.

### The `functions/` directory lives at the repo root

Not inside `site/`. Cloudflare Pages uses file-based routing from a `functions`
directory at the **project root**, compiled at build time — so
`functions/api/subscribe.js` serves `/api/subscribe`. Moving it into the output
directory silently publishes it as a static JavaScript file instead, which
would expose the source and return 405 for every signup.

`site/_routes.json` restricts Functions invocation to `/api/*`. Without it,
every request for the page and its assets would invoke the function and count
against the Functions quota, even though nothing dynamic happens.

## How Resend is used

Contacts in Resend are **global** — one audience per account, no audience ID in
the path. The function calls:

```
POST https://api.resend.com/contacts
Authorization: Bearer $RESEND_API_KEY

{ "email": "…", "unsubscribed": false, "segments": [{ "id": "…" }] }
```

`segments` is included only when `RESEND_SEGMENT_ID` is set.

An address already on the list returns success rather than an error. Reporting
it differently would leak whether a given address had signed up, and it is not
a failure from the visitor's point of view.

## Testing the function locally

It only runs in the Workers runtime, so `python3 -m http.server` will not
exercise it — `/api/subscribe` would 404. From the repo root:

```sh
cp .dev.vars.example .dev.vars   # then add your Resend key
./dev.sh                          # http://127.0.0.1:8140
```

`.dev.vars` is how Wrangler supplies bindings locally; it is gitignored, and
`dev.sh` refuses to start without it. `dev.sh` also copies `install.sh` into
`site/` the way the Pages build command does, so `/install.sh` resolves locally
too.

**A real key writes to your real contact list.** Every local submission creates
an actual contact in Resend. Either use an address you are happy to see in the
audience, or set `RESEND_CONTACTS_ENDPOINT` in `.dev.vars` to point at a mock —
that override exists for testing only and must stay unset in production.

## Spam

The form carries a honeypot field (`hp_check`) that is clipped, `tabindex="-1"`,
and `aria-hidden`, so no person or screen reader encounters it. Submissions that
fill it get a success response but are never forwarded to Resend, so bots get no
signal. It is deliberately **not** named `company`, `organization`, or anything
else a password manager autofills — that would silently drop real signups.

If bots get past it, add [Turnstile](https://developers.cloudflare.com/turnstile/)
and verify the token at the top of the function.

## Before it goes live

- Set `RESEND_API_KEY` in Pages, or the form will 500.
- Once `v0.1.0` is tagged, drop the `(soon)` from `.hero-install-note` in
  `index.html` and move Phase 0 off the `NOW` badge in the roadmap.
- `denly init` appears in step 2 of "How it works" but does not exist yet — the
  binary has `serve` and `version`. Fine as a roadmap promise, worth revisiting
  before anyone can actually install.
- The X link points at `@denlyhq`; confirm that handle is yours before launch.

## Assets and CSS

All CSS lives in `style.css`, not in a `<style>` block. That is not stylistic:
the CSP is `style-src 'self'` with no `'unsafe-inline'`, so an inline `<style>`
or any `style=""` attribute is **blocked in production** while still rendering
fine from a local `file://` preview. If you paste in markup with inline styles,
move them into `style.css` or the layout will silently break once deployed.

Fox images are resized from the originals: the hero renders at 150px wide and
the nav mark at ~34px tall, so shipping the 682px source would waste about
600KB on every visit to the page every tweet points at.

## Notes

- No external fonts, analytics, or third-party scripts. Nothing on the page
  makes a request to another host, which is both the honest position for this
  product and what lets the CSP stay at `default-src 'none'` with no
  `unsafe-inline`.
- Dark-only, deliberately. A den is somewhere you go into.
