#!/usr/bin/env bash
set +e
set -o pipefail

OUT_DIR="${1:-./output/tool_smoke}"
mkdir -p "$OUT_DIR"

check_tool() {
  if command -v "$1" >/dev/null 2>&1; then
      echo "[OK] $1 found"
      return 0
  else
      echo "[WARN] $1 missing — skipping"
      return 1
  fi
}

run_safe() {
  local label="$1"
  shift
  local err_file="$OUT_DIR/${label}.err"
  if timeout 30 "$@" >"$OUT_DIR/${label}.out" 2>"$err_file"; then
    echo "[OK] $label executed"
  else
    local ec=$?
    echo "[WARN] $label failed (exit=$ec) — continuing"
  fi
}

# Minimal input fixtures for safe smoke execution.
ALIVE="$OUT_DIR/alive.txt"
DOMAINS="$OUT_DIR/domains.txt"
KEYWORDS="$OUT_DIR/keywords.txt"
echo "https://example.com" > "$ALIVE"
echo "example.com" > "$DOMAINS"
echo "example" > "$KEYWORDS"

if check_tool gospider; then
  run_safe gospider gospider -S "$ALIVE" -c 10 -d 3 -o "$OUT_DIR/gospider_output"
fi

if check_tool spideyx; then
  run_safe spideyx spideyx -l "$ALIVE" -o "$OUT_DIR/spideyx_output.txt"
fi

if check_tool arjun; then
  run_safe arjun arjun -i "$ALIVE" -t 10 --stable -o "$OUT_DIR/arjun_params.txt"
fi

if check_tool GCPBucketBrute; then
  run_safe GCPBucketBrute GCPBucketBrute -k "$KEYWORDS" -o "$OUT_DIR/gcp_buckets.txt"
elif check_tool gcpbucketbrute; then
  run_safe gcpbucketbrute gcpbucketbrute -k "$KEYWORDS" -o "$OUT_DIR/gcp_buckets.txt"
fi

if check_tool goblob; then
  run_safe goblob goblob scan "$DOMAINS"
fi

if check_tool s3scanner; then
  run_safe s3scanner s3scanner scan -l "$DOMAINS"
fi

if check_tool nuclei; then
  run_safe nuclei nuclei -l "$ALIVE" -severity medium,high,critical -o "$OUT_DIR/nuclei.txt"
fi

echo "Done. Outputs in: $OUT_DIR"
