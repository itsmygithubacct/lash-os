#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
exec python3 "$HERE/config/build-python.py" "$@"
