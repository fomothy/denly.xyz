#!/bin/sh
#
# denly installer.
#
#   curl -fsSL https://denly.xyz/install.sh | sh
#
# Downloads the appropriate release binary from GitHub, verifies its SHA-256
# against the signed checksums file, and installs it. Nothing is executed from
# the archive before verification.
#
# Written for POSIX sh, not bash: this has to run on Alpine, on a minimal
# Debian container, and on macOS, where /bin/sh is not bash. No arrays, no
# [[ ]], no `local`.
#
# Flags:
#   --version <tag>    Install a specific release (default: latest)
#   --bin-dir <dir>    Install location (default: /usr/local/bin, or
#                      ~/.local/bin when that is not writable)
#   --data-dir <dir>   Data directory to configure the service with
#   --service          Install and start a systemd/launchd service
#   --no-service       Explicitly skip service setup (the default)
#   --help             Show this message

set -eu

REPO="fomothy/denly.xyz"
BINARY="denly"
SITE="https://denly.xyz"

VERSION=""
BIN_DIR=""
DATA_DIR=""
WANT_SERVICE="no"
TMP_DIR=""

# ---------------------------------------------------------------- output ----

# Colour only when stdout is a terminal. Piped into a log, the escape codes
# would be noise.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	C_RESET="$(printf '\033[0m')"
	C_BOLD="$(printf '\033[1m')"
	C_DIM="$(printf '\033[2m')"
	C_RED="$(printf '\033[31m')"
	C_AMBER="$(printf '\033[33m')"
else
	C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_AMBER=""
fi

say() { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$C_AMBER" "$C_RESET" "$*"; }
dim() { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }

err() {
	printf '%serror:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2
	exit 1
}

# Usage text is embedded rather than extracted from these comments: under
# `curl … | sh` there is no script file to read, "$0" is just "sh", and a
# --help that only works for downloaded copies is a trap.
usage() {
	cat <<'USAGE'
denly installer.

  curl -fsSL https://denly.xyz/install.sh | sh

Downloads the appropriate release binary from GitHub, verifies its SHA-256
against the signed checksums file, and installs it. Nothing from the archive
is executed before verification.

Flags:
  --version <tag>    Install a specific release (default: latest)
  --bin-dir <dir>    Install location (default: /usr/local/bin, or
                     ~/.local/bin when that is not writable)
  --data-dir <dir>   Data directory to configure the service with
  --service          Install and start a systemd/launchd service
  --no-service       Explicitly skip service setup (the default)
  --help             Show this message

Environment:
  NO_COLOR           Set to disable coloured output

Docs: https://denly.xyz
USAGE
	exit 0
}

cleanup() {
	if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
		rm -rf "$TMP_DIR"
	fi
}
trap cleanup EXIT INT TERM

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		err "required command not found: $1"
	fi
}

# ------------------------------------------------------------------ args ----

while [ $# -gt 0 ]; do
	case "$1" in
		--version)
			[ $# -ge 2 ] || err "--version requires an argument"
			VERSION="$2"; shift 2 ;;
		--version=*)
			VERSION="${1#*=}"; shift ;;
		--bin-dir)
			[ $# -ge 2 ] || err "--bin-dir requires an argument"
			BIN_DIR="$2"; shift 2 ;;
		--bin-dir=*)
			BIN_DIR="${1#*=}"; shift ;;
		--data-dir)
			[ $# -ge 2 ] || err "--data-dir requires an argument"
			DATA_DIR="$2"; shift 2 ;;
		--data-dir=*)
			DATA_DIR="${1#*=}"; shift ;;
		--service)    WANT_SERVICE="yes"; shift ;;
		--no-service) WANT_SERVICE="no"; shift ;;
		-h|--help)    usage ;;
		*)            err "unknown option: $1 (try --help)" ;;
	esac
done

# ---------------------------------------------------------------- detect ----

detect_platform() {
	os_raw="$(uname -s)"
	arch_raw="$(uname -m)"

	case "$os_raw" in
		Linux)   OS="linux" ;;
		Darwin)  OS="darwin" ;;
		# Git Bash / MSYS on Windows. Native PowerShell users take the .zip.
		MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
		*)       err "unsupported operating system: $os_raw" ;;
	esac

	case "$arch_raw" in
		x86_64|amd64)   ARCH="amd64" ;;
		aarch64|arm64)  ARCH="arm64" ;;
		# 32-bit and RISC-V are not release targets yet. Fail clearly rather
		# than downloading an archive that does not exist.
		*)              err "unsupported architecture: $arch_raw" ;;
	esac

	if [ "$OS" = "windows" ] && [ "$ARCH" = "arm64" ]; then
		err "windows/arm64 is not a release target; build from source instead"
	fi
}

# download URL OUTPUT — fetch a URL to a file, failing on HTTP errors.
download() {
	if command -v curl >/dev/null 2>&1; then
		# --fail turns a 404 into a non-zero exit instead of saving an HTML
		# error page as if it were a binary.
		curl -fsSL --retry 3 --retry-delay 1 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		err "need curl or wget to download files"
	fi
}

# Resolve the newest release tag by following the /releases/latest redirect.
# This avoids the GitHub API, which rate-limits unauthenticated requests to 60
# per hour per IP — shared NAT and CI runners hit that ceiling regularly.
resolve_latest_version() {
	redirect_url=""
	if command -v curl >/dev/null 2>&1; then
		redirect_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
			"https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
	elif command -v wget >/dev/null 2>&1; then
		redirect_url="$(wget -qS --max-redirect=5 --spider \
			"https://github.com/${REPO}/releases/latest" 2>&1 \
			| awk '/^  Location: /{print $2}' | tail -1 || true)"
	fi

	case "$redirect_url" in
		*/releases/tag/*) printf '%s\n' "${redirect_url##*/tag/}" ;;
		*) err "could not determine the latest version; pass --version <tag>" ;;
	esac
}

# sha256_of FILE — print the hex digest, using whichever tool exists.
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		err "need sha256sum, shasum, or openssl to verify the download"
	fi
}

# Pick an install directory, preferring a system location but never requiring
# root. A curl|sh that demands sudo and then fails halfway is worse than one
# that quietly installs to ~/.local/bin and says so.
choose_bin_dir() {
	if [ -n "$BIN_DIR" ]; then
		return
	fi
	if [ -w /usr/local/bin ] 2>/dev/null; then
		BIN_DIR="/usr/local/bin"
	elif [ "$(id -u)" = "0" ]; then
		BIN_DIR="/usr/local/bin"
	else
		BIN_DIR="${HOME}/.local/bin"
	fi
}

# ----------------------------------------------------------------- main -----

main() {
	need_cmd uname
	need_cmd tar
	need_cmd awk

	detect_platform

	if [ -z "$VERSION" ]; then
		step "Finding the latest release"
		VERSION="$(resolve_latest_version)"
	fi
	# GoReleaser strips the leading "v" from archive names but the git tag
	# keeps it, so both spellings are needed below.
	TAG="$VERSION"
	case "$TAG" in
		v*) BARE_VERSION="${TAG#v}" ;;
		*)  BARE_VERSION="$TAG"; TAG="v${TAG}" ;;
	esac

	if [ "$OS" = "windows" ]; then
		ARCHIVE="${BINARY}_${BARE_VERSION}_${OS}_${ARCH}.zip"
	else
		ARCHIVE="${BINARY}_${BARE_VERSION}_${OS}_${ARCH}.tar.gz"
	fi
	# DENLY_DOWNLOAD_BASE points the installer at a mirror or a local artifact
	# server instead of GitHub. Useful behind a restrictive firewall, for
	# air-gapped installs, and for testing this script against a fake release.
	# Checksum verification still applies — a mirror is not trusted, only used.
	BASE_URL="${DENLY_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download/${TAG}}"

	step "Installing ${C_BOLD}${BINARY} ${TAG}${C_RESET} for ${OS}/${ARCH}"

	TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t denly)"
	[ -d "$TMP_DIR" ] || err "could not create a temporary directory"

	step "Downloading ${ARCHIVE}"
	download "${BASE_URL}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}" \
		|| err "download failed — is ${TAG} a published release?"

	step "Verifying checksum"
	download "${BASE_URL}/checksums.txt" "${TMP_DIR}/checksums.txt" \
		|| err "could not download checksums.txt"

	expected="$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*"f {print $1}' \
		"${TMP_DIR}/checksums.txt" | head -1)"
	[ -n "$expected" ] || err "no checksum listed for ${ARCHIVE}"

	actual="$(sha256_of "${TMP_DIR}/${ARCHIVE}")"
	if [ "$expected" != "$actual" ]; then
		err "checksum mismatch for ${ARCHIVE}
  expected: ${expected}
  actual:   ${actual}
The download was corrupted or tampered with. Nothing has been installed."
	fi
	dim "    sha256 ${actual}"

	step "Extracting"
	if [ "$OS" = "windows" ]; then
		need_cmd unzip
		unzip -q "${TMP_DIR}/${ARCHIVE}" -d "$TMP_DIR"
	else
		tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
	fi

	binary_name="$BINARY"
	[ "$OS" = "windows" ] && binary_name="${BINARY}.exe"
	[ -f "${TMP_DIR}/${binary_name}" ] || err "archive did not contain ${binary_name}"
	chmod +x "${TMP_DIR}/${binary_name}"

	choose_bin_dir
	step "Installing to ${BIN_DIR}"
	install_binary "${TMP_DIR}/${binary_name}" "${BIN_DIR}/${binary_name}"

	if [ "$WANT_SERVICE" = "yes" ]; then
		install_service "${BIN_DIR}/${binary_name}"
	fi

	report "${BIN_DIR}/${binary_name}"
}

# install_binary SRC DEST — copy into place, escalating only if necessary.
install_binary() {
	install_src="$1"
	install_dest="$2"
	install_dir="$(dirname "$install_dest")"

	if [ -d "$install_dir" ] && [ -w "$install_dir" ]; then
		# Install to a temporary name in the same directory and rename, so an
		# upgrade cannot leave a half-written binary if the disk fills. rename
		# within a filesystem is atomic; a running instance keeps its open
		# inode and is unaffected until restarted.
		cp "$install_src" "${install_dest}.new"
		chmod 755 "${install_dest}.new"
		mv -f "${install_dest}.new" "$install_dest"
		return
	fi

	if [ ! -d "$install_dir" ]; then
		if mkdir -p "$install_dir" 2>/dev/null; then
			cp "$install_src" "$install_dest"
			chmod 755 "$install_dest"
			return
		fi
	fi

	if command -v sudo >/dev/null 2>&1; then
		say ""
		say "${BIN_DIR} is not writable; requesting elevated permissions."
		sudo mkdir -p "$install_dir"
		sudo cp "$install_src" "${install_dest}.new"
		sudo chmod 755 "${install_dest}.new"
		sudo mv -f "${install_dest}.new" "$install_dest"
		return
	fi

	err "cannot write to ${install_dir} and sudo is unavailable.
Re-run with --bin-dir \$HOME/.local/bin to install without root."
}

# ------------------------------------------------------------- service ------

install_service() {
	service_bin="$1"

	case "$OS" in
		linux)  install_systemd_service "$service_bin" ;;
		darwin) install_launchd_service "$service_bin" ;;
		*)      say "Service installation is not supported on ${OS}; skipping." ;;
	esac
}

install_systemd_service() {
	svc_bin="$1"

	if ! command -v systemctl >/dev/null 2>&1; then
		say "systemd not found; skipping service setup."
		return
	fi

	# A user unit needs no root and keeps denly's files owned by the person who
	# actually uses them, which matches a single-user personal server.
	unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
	unit_file="${unit_dir}/denly.service"
	mkdir -p "$unit_dir"

	svc_env=""
	if [ -n "$DATA_DIR" ]; then
		svc_env="Environment=DENLY_DATA_DIR=${DATA_DIR}"
	fi

	step "Writing ${unit_file}"
	cat > "$unit_file" <<EOF
[Unit]
Description=denly — your own corner of the internet
Documentation=${SITE}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${svc_bin} serve
${svc_env}
Restart=on-failure
RestartSec=5s

# denly needs no privileges beyond its own data directory.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/denly
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=default.target
EOF

	systemctl --user daemon-reload
	systemctl --user enable --now denly.service || {
		say "Could not start the user service automatically."
		say "Start it manually with: systemctl --user start denly"
		return
	}

	# Without lingering, a user unit stops when the last session ends, which
	# makes a "server" that dies on logout. Tell the user plainly.
	if command -v loginctl >/dev/null 2>&1; then
		if ! loginctl show-user "$(id -un)" -p Linger 2>/dev/null | grep -q 'Linger=yes'; then
			say ""
			say "${C_BOLD}To keep denly running after you log out:${C_RESET}"
			say "    sudo loginctl enable-linger $(id -un)"
		fi
	fi
}

install_launchd_service() {
	svc_bin="$1"

	label="xyz.denly.denly"
	plist_dir="${HOME}/Library/LaunchAgents"
	plist="${plist_dir}/${label}.plist"
	log_dir="${HOME}/Library/Logs/denly"
	mkdir -p "$plist_dir" "$log_dir"

	svc_env_block=""
	if [ -n "$DATA_DIR" ]; then
		svc_env_block="	<key>EnvironmentVariables</key>
	<dict>
		<key>DENLY_DATA_DIR</key>
		<string>${DATA_DIR}</string>
	</dict>"
	fi

	step "Writing ${plist}"
	cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
	"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>${svc_bin}</string>
		<string>serve</string>
	</array>
${svc_env_block}
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardOutPath</key>
	<string>${log_dir}/denly.log</string>
	<key>StandardErrorPath</key>
	<string>${log_dir}/denly.err.log</string>
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
EOF

	# bootout first so re-running the installer reloads a changed plist rather
	# than silently keeping the old definition.
	launchctl bootout "gui/$(id -u)/${label}" 2>/dev/null || true
	if launchctl bootstrap "gui/$(id -u)" "$plist" 2>/dev/null; then
		say "    launchd agent loaded"
	else
		say "Could not load the launchd agent automatically."
		say "Load it manually with: launchctl bootstrap gui/$(id -u) ${plist}"
	fi
}

# -------------------------------------------------------------- report ------

report() {
	installed="$1"
	say ""
	say "${C_BOLD}denly is installed.${C_RESET}"
	say ""
	dim "    $("$installed" version 2>/dev/null || echo "${installed}")"
	say ""

	# A binary in a directory that is not on PATH is the single most common
	# way a curl|sh install appears to have failed. Check and say so.
	case ":${PATH}:" in
		*":${BIN_DIR}:"*) ;;
		*)
			say "${C_AMBER}${BIN_DIR} is not on your PATH.${C_RESET}"
			say "Add it with:"
			say ""
			say "    echo 'export PATH=\"${BIN_DIR}:\$PATH\"' >> ~/.profile"
			say "    export PATH=\"${BIN_DIR}:\$PATH\""
			say ""
			;;
	esac

	if [ "$WANT_SERVICE" = "yes" ]; then
		say "Running as a background service. Open ${C_BOLD}http://localhost:8737${C_RESET}"
	else
		say "Start it with:"
		say ""
		say "    ${C_BOLD}denly serve${C_RESET}"
		say ""
		say "then open ${C_BOLD}http://localhost:8737${C_RESET}"
		say ""
		say "To run it in the background at login, re-run this installer with --service."
	fi
	say ""
	dim "Docs: ${SITE}"
}

main
