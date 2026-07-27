#!/bin/sh
#
# Run denly.xyz locally — the static page plus the waitlist endpoint.
#
#   ./dev.sh
#
# Reads bindings from .dev.vars (see .dev.vars.example). A plain static file
# server will not do: /api/subscribe is a Worker route and only runs in the
# Workers runtime.

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

# Both steps mirror what the Cloudflare build command does, so local and
# deployed behaviour cannot drift.

# The published site serves install.sh from the repo root; without this copy
# /install.sh 404s locally.
cp install.sh site/install.sh

# functions/ uses file-based routing, which Workers does not read directly —
# it has to be compiled into the single script wrangler.jsonc points at.
npx --yes wrangler@latest pages functions build --outdir=build/worker >/dev/null

echo "denly.xyz → http://127.0.0.1:${PORT}"
echo

exec npx --yes wrangler@latest dev --port "$PORT" --ip 127.0.0.1
