#!/usr/bin/env bash
# Build the pinned external libraries into a private prefix, for host or target CC.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/config/build-deps.py" "$@"
