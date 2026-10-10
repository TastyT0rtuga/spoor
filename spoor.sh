#!/usr/bin/env bash
# Spoor on Linux / WSL (needs python3 3.10 or newer; everything else is bundled).
#   ./spoor.sh            start the dashboard
#   ./spoor.sh selftest   run the built-in self-test
#   ./spoor.sh status "My case"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$DIR/app:$DIR/vendor"
exec python3 -S -m spoor "$@"
