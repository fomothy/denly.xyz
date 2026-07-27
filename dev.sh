#!/bin/sh
#
# Run the denly.xyz landing page locally, with the waitlist function working.
#
#   ./dev.sh
#
# Reads bindings from .dev.vars (see .dev.vars.example). Plain `python3 -m
# http.server` will not do: /api/subscribe is a Cloudflare Pages Function and
# only runs in the Workers runtime.

set -eu

PORT="${PORT:-8140}"

cd "$(dirname "$0")"

if [ ! -f .dev.vars ]; then
	echo "No .dev.vars found. Create one with:"
	echo
	echo "    cp .dev.vars.example .dev.vars"
	echo
	echo "then add your Resend API key. Without it the form returns a 500."
	exit 1
fi

# The published site serves install.sh from the repo root; the Pages build
# command does this copy, so local dev has to as well or /install.sh 404s.
cp install.sh site/install.sh

echo "denly.xyz → http://127.0.0.1:${PORT}"
echo

exec npx --yes wrangler@latest pages dev site \
	--port "$PORT" \
	--ip 127.0.0.1 \
	--compatibility-date=2026-07-27
