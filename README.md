# denly

**Your corner of the internet, that only you hold the key to.**

A single-binary, self-hostable app that gives any person a censorship-resistant
home on the internet: verified identity, a presence page, encrypted file drops,
publishing backups, and a trustless dead man's switch — with keys that never
leave your machine.

> **Status: Phase 0.** The skeleton is real and working — it builds, serves,
> stores, and upgrades itself cleanly. The features listed below are not built
> yet. See [the roadmap](#roadmap).

---

## Install

```sh
curl -fsSL https://denly.xyz/install.sh | sh
```

Then:

```sh
denly serve
```

and open <http://localhost:8737>.

The installer detects your OS and architecture, downloads the matching release
from GitHub, **verifies its SHA-256 against the published checksums**, and
installs the binary. It never executes anything from the archive before
verifying it.

<details>
<summary>Other ways to install</summary>

**Run as a background service** (systemd user unit on Linux, launchd agent on
macOS):

```sh
curl -fsSL https://denly.xyz/install.sh | sh -s -- --service
```

**Pick a version or location:**

```sh
curl -fsSL https://denly.xyz/install.sh | sh -s -- --version v0.1.0 --bin-dir ~/.local/bin
```

**Docker:**

```sh
docker compose up -d
```

**From source:**

```sh
git clone https://github.com/fomothy/denly.xyz
cd denly.xyz
go build -o denly ./cmd/denly
```

**Verify a release yourself** — releases are signed with [cosign](https://github.com/sigstore/cosign)
using GitHub's OIDC identity, so no long-lived key has to be trusted:

```sh
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/fomothy/denly.xyz/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

</details>

---

## What it is

denly runs on your own machine — a laptop, a Raspberry Pi, a $5 VPS — and gives
you:

| | |
|---|---|
| **Presence page** | A public home at your own domain. Markdown-first, plain-CSS themes, exportable to static HTML at any time. |
| **Verified identity** | Nostr NIP-05 and ATProto DID cross-links, so your identity is anchored in open protocols rather than any company's database. |
| **Encrypted drops** | Send and receive files end-to-end encrypted in the browser. The key lives in the URL fragment and never reaches the server. |
| **Deadhand** | A dead man's switch. Miss your check-ins and an encrypted payload is released to the recipients you chose. |
| **Permanence** | Every publish pins to IPFS; one click puts it on Arweave forever. |

### The privacy invariant

```
 your browser --encrypts--> ciphertext --> server stores/pins it
 ^                                                             |
 +--------------- keys never leave your machine ---------------+
```

Whoever operates the server — you, or us on the hosted tier — holds
**availability, not secrets**. This is the constraint every feature is designed
around, not a policy that could be changed later.

---

## What works today (Phase 0)

- Single static binary, no runtime dependencies, no interpreter, no libc
- Embedded SQLite in WAL mode with versioned, transactional migrations
- Frontend compiled into the binary — no CDN, no external fonts, no asset
  directory to lose on upgrade
- Data directory in the platform-conventional location, `0700`, database `0600`
- Loopback-only by default; exposing the instance is a deliberate act
- Graceful shutdown on SIGTERM, so systemd restarts are clean
- Reproducible cross-compiled releases with checksums, SBOMs, and cosign
  signatures

## Roadmap

| Phase | Scope |
|---|---|
| **0** ✅ | Skeleton: binary, storage, embedded UI, release pipeline, installer |
| **1** | Nostr NIP-05 identity, presence page, encrypted drops, receive box, `drop`/`backup`/`restore` CLI, IPFS pinning |
| **2** | Deadhand: client-side payload encryption, heartbeat engine, escalation, drill mode, then Shamir N-of-M guardians |
| **3** | Tailscale (tsnet) and Tor onion reachability, ATProto DID bridging, docs site |
| **4** | Hosted tier (gated on demand) |

### Explicitly not building

Social feeds, a password vault, an email service, or anything token-gated.

---

## Usage

```
denly <command> [flags]

Commands:
  serve      Run the denly server
  version    Print version information
  help       Show usage
```

### `denly serve`

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `127.0.0.1:8737` | Listen address |
| `-data-dir` | platform-specific | Where the database and files live |
| `-log-json` | off | Structured JSON logs |
| `-v` | off | Debug logging |

Environment: `DENLY_DATA_DIR`, `DENLY_ADDR`. Flags win over environment
variables, which win over defaults.

### Where your data lives

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/denly` |
| Linux | `$XDG_DATA_HOME/denly`, else `~/.local/share/denly` |
| Windows | `%LOCALAPPDATA%\denly` |
| Docker | `/data` (bind-mounted to `./data`) |

Back up that directory and you have backed up everything. Copy it to another
machine and denly picks up exactly where it left off.

---

## Development

```sh
go test ./...              # unit tests
go test -race ./...        # what CI runs
go vet ./...
go build -o denly ./cmd/denly
./denly serve
```

Architecture notes:

- **Go, `CGO_ENABLED=0` everywhere.** The SQLite driver is
  [modernc.org/sqlite](https://modernc.org/sqlite), a pure-Go translation. It
  is slower than the cgo driver, but every target cross-compiles from one
  machine with no C toolchain and the result is genuinely static. CI enforces
  this — adding a cgo dependency fails the build.
- **Migrations are append-only.** Once a migration has shipped in a release its
  SQL is frozen. Self-hosters upgrade on their own schedule, sometimes across
  many versions at once.
- **Opening a database from a newer denly fails loudly** rather than risking
  data the running binary cannot represent.
- **Request logs omit IP, user agent, and referrer.** The cheapest way to keep
  a promise about log retention is to never write the identifying fields.

---

## License

[AGPL-3.0-only](LICENSE).

Self-hosters are unaffected: run it, modify it, keep your changes private if
you never offer it to others over a network. Anyone offering denly as a hosted
service must publish their whole stack under the same terms.

Contributions require a CLA so that relicensing stays possible.

---

<sub>[denly.xyz](https://denly.xyz)</sub>
