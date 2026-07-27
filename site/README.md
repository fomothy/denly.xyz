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
├── _headers              response headers + CSP (native on Workers)
└── .assetsignore         keeps .DS_Store out of the upload

functions/                NOT inside site/ — see below
└── api/
    └── subscribe.js      POST /api/subscribe → Resend

wrangler.jsonc            Worker config: name, assets dir, ASSETS binding
```

## Why there is a function at all

The Resend API key must never reach the browser. A form posting straight to
`api.resend.com` would have to ship the key in the page, and anyone could then
read the contact list or send mail as the domain. The function is the smallest
thing that keeps the key server-side.

It also means the form degrades properly: it is a real `<form>` that posts and
redirects to `/thanks` with JavaScript disabled, and submits in place when
`app.js` runs.

## Deploy on Cloudflare Workers

Deployed as a Worker with static assets, not as a Pages project. Cloudflare is
consolidating Pages into Workers, and `_headers` plus assets-first routing are
supported natively, so there was no reason to start on the older product.

1. **Workers & Pages → Create application → Connect to Git**, pick
   `fomothy/denly.xyz`.
2. Build settings:

   | Setting | Value |
   |---|---|
   | Project name | `denly` — Worker names allow lowercase alphanumerics and hyphens only, so it cannot be `denly.xyz` |
   | Build command | `cp install.sh site/install.sh && npx wrangler pages functions build --outdir=build/worker` |
   | Deploy command | `npx wrangler deploy` |

   The build command does two things. The copy publishes the real `install.sh`
   from the repo root at `denly.xyz/install.sh`, so the script people pipe into
   their shell can never drift from the one CI tests. The second half compiles
   `functions/` into the single Worker script `wrangler.jsonc` points at —
   Workers has no file-based routing of its own.

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

### Routing and the ASSETS binding

Workers serves a matching static asset first and only runs the Worker script
when nothing matches. That is exactly the routing this site wants, since
`/api/subscribe` is the only dynamic path — which is why there is no
`_routes.json` (a Pages-only file) and why `run_worker_first` stays unset.

`wrangler.jsonc` **must** declare `assets.binding: "ASSETS"`. Pages provided
that binding implicitly; Workers does not. The compiled functions script calls
`env.ASSETS.fetch()` to fall through for anything it does not handle, so
without the binding every unmatched path throws and returns **500 instead of
404** — on every mistyped URL and every bot probe. This was caught in local
testing; it would not have been obvious in production.

`functions/` stays at the repo root, not inside `site/`. Anything inside the
asset directory is published verbatim, so moving it there would serve the
source as a static file.

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
`dev.sh` refuses to start without it. `dev.sh` runs the same two build steps as
the deploy command before starting `wrangler dev`, so local and deployed
behaviour cannot drift.

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
