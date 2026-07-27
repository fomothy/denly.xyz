# Denly — Project Plan

**Name:** Denly — denly.xyz (product + installer), GitHub repo [`fomothy/denly.xyz`](https://github.com/fomothy/denly.xyz)
**Tagline candidates:** "Your corner of the internet, that only you hold the key to." / "Outlive your platforms."
**Date:** 2026-07-27
**Status:** Phase 0 complete — [v0.1.0](https://github.com/fomothy/denly.xyz/releases/tag/v0.1.0) released, denly.xyz live. Phase 1 next

---

## 1. Vision & Goals

### One-liner
A single-binary, self-hostable app that gives any person a censorship-resistant home on the internet: verified identity, presence page, encrypted file drops, publishing backups, and a trustless dead man's switch ("Deadhand") — with keys always in the user's hands.

### Mission fit
- **Decentralization:** identity and data anchored in open protocols (Nostr NIP-05, ATProto DID, IPFS/Arweave), not in any company's server — including ours.
- **Privacy:** all sensitive payloads encrypted client-side; the server (self-hosted or our hosted tier) only ever holds ciphertext. *"We host availability, not secrets."*
- **Useful first, monetization second:** free open-source core; paid hosted tier + storage upsells only after self-hosters demand it.

### Success metrics (first 6 months)
- GitHub stars / HN / Twitter traction on launch posts
- Active self-hosted installs (update-check pings, opt-out telemetry only)
- Waitlist signups for hosted tier (gate: 200 before building Phase 4)
- First 10 paying hosted customers

---

## 2. Product Scope — Full Feature List

### Module 1: Presence Page (v1)
Public home at `you.denly.xyz` or custom domain.
- Page builder: bio, links, embedded content, posts/notes, contact methods. Markdown-first; themes are plain CSS. No account needed to view.
- Identity verification strip: Nostr NIP-05 (`you@denly.xyz`), ATProto handle/DID cross-link, optional Keyoxide-style PGP proofs. Bidirectional proof: page signs a claim with the user's key; the external identity references the page back.
- Custom domains with Caddy auto-TLS.
- Auto-archival: every publish pins to IPFS; optional one-click Arweave permanence.
- Portable export: one-click static HTML + JSON bundle. Anti-lock-in as a feature.
- (Later) Opt-in webring/directory of public Denly pages.

### Module 2: Drops — encrypted file transfer (v1)
- Browser E2EE: files encrypted in the sender's browser; key in URL fragment (`#key`), never sent to server. Server stores ciphertext only.
- Expiring links: time-based (1h–30d), download-count (burn after N), or both.
- **Receive box with approval flow:** a "send me a file" button on your page. Sender requests → receiver approves/denies → only then does transfer proceed. Prevents disk-filling spam and unsolicited content.
- P2P for large files when both parties online (WebRTC, server only signals); relayed ciphertext otherwise. Self-hosters set their own limits.
- First-class CLI: `denly drop ./file.zip` → prints link; pipe-friendly (`tar cz . | denly drop -`).
- Access logs rot after 24h by default; documented and verifiable in source.

### Module 3: Deadhand — the dead man's switch (v2, flagship)
Named after the Cold War Dead Hand system; built-in storytelling.
- Payload: text, files, or full page snapshot. Encrypted client-side to recipient pubkey(s). Server holds ciphertext + metadata only.
- Heartbeat check-ins: signed Nostr note, emailed link click, CLI ping, or wallet signature. Configurable interval + grace period.
- Escalation before release: missed check-in → reminders via email/Nostr DM/nudge to trusted contact before firing. Prevents vacation false-alarms.
- Release:
  - v2.0: ciphertext published to IPFS/Arweave + decryption material released to designated recipients; optional public "switch fired" notice without content.
  - v2.1: Shamir N-of-M guardian threshold release; guardians can veto (proof-of-life).
- Multiple switches per user: different payloads, recipients, timers ("family gets X, lawyer gets Y, public gets Z").
- Liveness dashboard: pinning status, Arweave endowment, next check-in due. Honest about what keeps a switch alive.
- Test/drill mode: fire to a test recipient so users trust the machinery.

### Module 4: Keys & Identity (v1, underpins everything)
- Local keyring: generated in-app, stored in data dir or OS keychain, exportable. Never transmitted.
- Identity bridging: Nostr npub (first), ATProto DID (second), optional Lightning address for tips/paid drops.
- Recovery: mnemonic seed backup; optional social recovery via guardians (reuses Deadhand N-of-M).
- Admin auth: no passwords — localhost trust/token locally; signed-challenge remotely.

### Module 5: Reachability (v3)
- Localhost mode: zero config.
- Tailscale (tsnet) embedded: one toggle → reachable on tailnet with real TLS. No port forwarding.
- Tor onion: one toggle → v3 onion address; presence page + receive box work over Tor.
- Public mode: Caddy auto-TLS on user domain.

### Module 6: Backups & Permanence (v1 basic, v3 full)
- `denly backup` → encrypted tarball of entire data dir.
- IPFS pinning: user-provided pinning token (web3.storage/Pinata) or local Kubo node.
- Arweave one-time-payment permanence for page snapshots + Deadhand payloads; transparent cost; margin only on hosted tier.
- `denly restore` verified in CI; annual "test your restore" nag.

### Module 7: Hosted tier (v4, gated)
- Managed instance per customer (isolated container), `you.denly.xyz` subdomain.
- Included Arweave allowance, larger drop quotas, priority relays.
- Same code, same crypto; export-and-leave anytime is a selling point.

### Platforms
- Desktop: macOS/Linux/Windows binaries.
- **Mobile-web only** (responsive UI). No native apps for the foreseeable future.

### Explicitly NOT building
- Social feeds/comments/follows — not a social network
- Password vault — custody conflicts with "we hold nothing"
- Email service — deliverability hell
- Anything token-gated / NFT

---

## 3. Architecture

### Tech stack
| Layer | Choice | Rationale |
|---|---|---|
| Language | **Go** | Single static binary, cross-compile, ~30–50MB idle RAM, strong Nostr ecosystem |
| DB | **Embedded SQLite (WAL)** | Zero-dep, PocketBase-proven; plain `./data` dir |
| Frontend | Server-rendered + light JS, embedded via `go:embed` | Whole app in the binary; responsive for mobile-web |
| TLS/ingress | **Caddy** (self-host installs) | Auto-TLS, trivial config |
| Reachability | localhost → **tsnet** / **Tor onion** → public domain | Kills the #1 self-hosting pain point |
| Protocols | Nostr NIP-05 (first), ATProto DID (second), IPFS, Arweave | Decentralized anchors |
| Crypto | age-style AEAD, client-side only | Server never sees keys/plaintext |
| Releases | **GoReleaser** + GitHub Actions | Binaries, checksums, signatures, Docker images |
| Billing (later) | Stripe | Hosted tier + storage upsells |

### Repo layout (planned)
```
denly/
├── cmd/denly/main.go        # serve, drop, backup, restore, version
├── internal/
│   ├── server/              # HTTP server, routes, middleware
│   ├── store/               # SQLite access layer
│   ├── identity/            # Nostr NIP-05, ATProto verification
│   ├── drop/                # encrypted drops + receive-box approval flow
│   ├── deadhand/            # dead man's switch (v2)
│   ├── backup/              # IPFS/Arweave pinning
│   ├── reach/               # tsnet / tor
│   └── config/
├── web/                     # frontend (embedded)
├── install.sh
├── docker-compose.yml
├── .goreleaser.yml
└── data/                    # runtime: denly.db + files (gitignored)
```

### Privacy invariant
```
User browser/CLI ──encrypts──▶ ciphertext ──▶ server stores/pins ciphertext
        ▲                                                │
        └── keys NEVER leave the client ◀────────────────┘
```
Operator (self-hoster or us) holds **availability, not secrets**.

### Deployment modes
1. **Local only** — `./denly serve` → localhost; everything works except inbound check-ins/drops from others.
2. **Home server** — install script + tsnet/Tor toggle; reachable with no port forwarding, domain, or TLS setup.
3. **Public instance** — domain + VPS; compose includes Caddy auto-TLS.

---

## 4. Distribution

| Channel | Artifact | Notes |
|---|---|---|
| curl installer | `curl -fsSL https://denly.xyz/install.sh \| sh` | OS/arch detect → GitHub Release binary → data dir → optional systemd/launchd. The tweetable headline. |
| Raw binaries | GitHub Releases (signed, checksummed) | For the verify-everything crowd |
| Docker | `docker compose up -d` (~15 lines, bind-mounted `./data`) | Homelab standard; later: selfh.st, CasaOS, Umbrel listings |
| Hosted tier | Same image, isolated container/customer, Dokploy/Coolify | Phase 4 only |

**CLI is first-class** — `denly` binary is simultaneously server, CLI client, and admin tool.

---

## 5. Monetization (open-core)

| Tier | Price | Includes |
|---|---|---|
| Self-hosted | Free, OSS | Everything, forever |
| Hosted | $5–8/mo | Managed isolated instance; keys stay client-side |
| Permanence upsell | One-time, cost + margin | Arweave permanent storage |
| (Later) API | Usage-based | Cross-protocol identity/verification integrations |

**License: AGPLv3 + CLA** (CLA bot from day one to preserve relicensing options).
- Self-hosters unaffected; a hosted competitor must open their whole stack.
- Reinforces the trust story; dual-licensing is a possible future revenue stream.

---

## 6. Build Plan (phased)

### Phase 0 — Skeleton ✅ **complete (v0.1.0)**
- ~~Go module, `serve` command, embedded SQLite, hello-world embedded UI~~
- ~~GoReleaser CI (binaries + checksums + docker), install.sh, docker-compose.yml~~
- **Exit met:** `curl -fsSL https://denly.xyz/install.sh | sh` installs, verifies
  SHA-256, and serves — proven on macOS locally and on clean Linux and macOS
  runners by the release workflow's own verify job.
- Also shipped beyond the original scope: the denly.xyz landing page (Cloudflare
  Worker + static assets) with a Resend-backed waitlist, cosign keyless
  signatures, SBOMs, and CI across Linux/macOS/Windows.

**Decisions made during Phase 0**
- Pure-Go SQLite (modernc) and `CGO_ENABLED=0` everywhere, so all five targets
  cross-compile from one runner. CI enforces it; adding a cgo dependency fails
  the build.
- Migrations are append-only and transactional; opening a newer schema fails
  loudly rather than risking data the binary cannot represent.
- Data dir in the platform-conventional location at 0700, database 0600.
- Loopback-only bind by default.
- Request logs omit IP, user agent, and referrer — the cheapest way to keep a
  log-retention promise is to never write the identifying fields.
- Site deployed as a Cloudflare Worker, not Pages; the Resend API key lives in
  a Worker secret and never reaches the browser.

### Phase 1 — v1 core (weeks 2–6) ← **next**

**Two decisions due before code:**
- **Key material.** One secp256k1 keypair. NIP-44 for anything encrypted *to an
  identity* (Deadhand payloads, receive-box approvals); a plain random symmetric
  key for drops, which need no identity at all — that is what lets a recipient
  who has never heard of denly open one from a `#key` fragment.
- **Admin auth.** The server is read-only today, so nothing needs protecting.
  The moment a presence page can be edited, it does. No passwords: localhost
  trust locally, signed challenge remotely. Must land *with* the first mutable
  endpoint, not after.

Suggested order: identity → presence page → drops. The page needs identity to
verify against, and the receive box needs keys to approve with.

- Identity: Nostr NIP-05 verification; presence page rendering
- Drops: browser E2EE, expiring links, receive box with approval flow
- CLI: `drop`, `backup`, `restore`
- IPFS backup of presence page
- **Launch:** build-in-public thread + Show HN + Nostr community

### Phase 2 — Deadhand (weeks 7–12)
- Client-side payload encryption to recipient pubkeys
- Heartbeat engine + escalation reminders + drill mode
- v2.0 release: time-based + designated recipients; v2.1: Shamir N-of-M guardians
- Arweave permanence option
- **Launch:** dedicated announcement; privacy/activist/estate-planning communities

### Phase 3 — Reachability & polish (weeks 13–16)
- tsnet + Tor onion modes
- ATProto DID bridging (second identity protocol)
- Docs site, demo videos, selfh.st / app-store listings

### Phase 4 — Hosted tier (gated on 200 waitlist)
- Per-customer containers, wildcard TLS (`you.denly.xyz`), Stripe
- First pricing experiments

---

## 7. Marketing / Twitter strategy

- **Build in public** from day one: architecture decisions, single-binary tricks, crypto tradeoffs.
- Every feature ships with a **30-second demo video**. Signature demos:
  - Drops: "I sent myself a file through my own server and the server admin (also me) can't read it."
  - Deadhand drill: "I just simulated my own death and my friend got the file."
- Two recurring storytelling hooks: the Cold War Dead Hand lore (Deadhand), and the **den** — a private space that's yours, that you retreat to, that outlives the neighborhood.
- Ride deplatforming/instance-death news cycles (non-opportunistically).
- Seed communities: Nostr devs, r/selfhosted, privacyguides, ATProto dev scene, HN.

---

## 8. Risks & Open Questions

| Risk / Question | Mitigation / When |
|---|---|
| ~~License~~ | **Decided: AGPLv3 + CLA** |
| ~~Name~~ | **Decided: Denly — denly.xyz registered. Hosted tier uses `you.denly.xyz` (one domain, wildcard TLS), so no second domain required.** |
| ~~GitHub org~~ | **Decided: repo is `fomothy/denly.xyz`** (module path `github.com/fomothy/denly.xyz`) |
| X handle | Site footer links `@denlyhq`; the plan originally said `@denlydev`. Confirm which is actually yours before the first public post |
| `denly init` on the site | "How it works" step 2 advertises `denly init`, which does not exist — the binary has `serve` and `version`. Phase 1 should make it real, and use that exact name for key generation |
| Deadhand liveness (decades-long pinning) | Arweave pay-once; liveness dashboard honesty. Phase 2 |
| Threshold crypto complexity | v2.0 time-based first; Shamir in v2.1 |
| Abuse (hosted tier storing harmful ciphertext; receive-box spam) | Ciphertext-only + rate limits + approval flow + ToS/reporting. Phase 2/4 |
| Support burden of hosted tier | Waitlist gate; per-customer isolation limits blast radius |
| Scope creep across protocols | Nostr first, ATProto in Phase 3, nothing else until v3 |
| Big-company AGPL aversion | Acceptable for consumer/privacy tool; CLA preserves options |

---

## 9. Immediate next actions

1. ~~Register domain~~ — **denly.xyz registered; it is the only domain.** The installer headline is `curl -fsSL https://denly.xyz/install.sh | sh`. Do not advertise a `denly.sh` shortcut: it is unregistered, so anyone could claim it and serve their own script to everyone who copies that line. ~~Create GitHub repo~~ — [`fomothy/denly.xyz`](https://github.com/fomothy/denly.xyz). Still to do: verify/claim the X handle
2. Scaffold repo per Phase 0 (Go module + GoReleaser + install.sh + embedded UI skeleton)
3. First build-in-public post: the name, the why, the AGPL choice
