#!/usr/bin/env bash
# find_unreferenced_files.sh
# Emit Python files not directly imported by any other Python file in the project.
# Excludes: .venv, __pycache__, test files, __init__.py, archive/

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "# Potentially unreferenced Python files"
echo "# (Not imported by any other .py outside archive/)"
echo ""

find . -name "*.py" \
    -not -path "./.venv/*" \
    -not -path "./*__pycache__*" \
    -not -path "./archive/*" \
    | sort \
    | while IFS= read -r f; do
        mod_base
        mod_base="$(basename "$f" .py)"

        # Skip __init__, test files, conftest, top-level scripts
        case "$mod_base" in
            __init__|conftest|test_*|*_test|technieum|scheduler|query|state_manager|event_emitter) continue ;;
        esac

        # Derive dot-notation module path
        mod="${f#./}"
        mod="${mod%.py}"
        mod_dot="${mod//\//.}"

        if ! grep -qr --include="*.py" \
            -e "from ${mod_dot}" \
            -e "import ${mod_dot}" \
            . --exclude-dir=.venv --exclude-dir=archive --exclude-dir=__pycache__ 2>/dev/null; then
            echo "$f"
        fi
    done
