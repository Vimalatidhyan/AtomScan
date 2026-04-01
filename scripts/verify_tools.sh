#!/usr/bin/env bash
set +e
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/output"
REPORT="${OUT_DIR}/tool_status_report.txt"

mkdir -p "$OUT_DIR"
: > "$REPORT"

echo "===== TOOL STATUS =====" | tee -a "$REPORT"

check_tool() {
  if command -v "$1" >/dev/null 2>&1; then
      echo "[OK] $1 found" | tee -a "$REPORT"
      return 0
  else
      echo "[WARN] $1 missing — skipping" | tee -a "$REPORT"
      return 1
  fi
}

status_ok(){ echo "[OK] $1" | tee -a "$REPORT"; }
status_warn(){ echo "[WARN] $1" | tee -a "$REPORT"; }
status_err(){ echo "[ERROR] $1" | tee -a "$REPORT"; }

run_help() {
  local bin="$1"
  timeout 12 "$bin" --help >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    return 0
  fi
  timeout 12 "$bin" -h >/dev/null 2>&1
}

tool_version() {
  local bin="$1"
  "$bin" --version 2>/dev/null | head -n 1
  if [ ${PIPESTATUS[0]} -eq 0 ]; then
    return 0
  fi
  "$bin" version 2>/dev/null | head -n 1
  if [ ${PIPESTATUS[0]} -eq 0 ]; then
    return 0
  fi
  "$bin" -V 2>/dev/null | head -n 1
  if [ ${PIPESTATUS[0]} -eq 0 ]; then
    return 0
  fi
  "$bin" -v 2>/dev/null | head -n 1
}

verify_tool() {
  local label="$1"
  local bin="$2"

  if ! command -v "$bin" >/dev/null 2>&1; then
    status_warn "$label missing"
    return 1
  fi

  if run_help "$bin"; then
    local ver
    ver="$(tool_version "$bin")"
    if [ -n "$ver" ]; then
      status_ok "$label working (${ver})"
    else
      status_ok "$label working"
    fi
    return 0
  fi

  status_err "$label exists but failed"
  return 2
}

# Primary tools
verify_tool "gospider" "gospider"
verify_tool "spideyx" "spideyx"
verify_tool "arjun" "arjun"
verify_tool "GCPBucketBrute" "GCPBucketBrute"
verify_tool "gcpbucketbrute" "gcpbucketbrute"
verify_tool "goblob" "goblob"
verify_tool "s3scanner" "s3scanner"

# Previously failed tools
verify_tool "nuclei" "nuclei"
verify_tool "rustscan" "rustscan"
verify_tool "subjack" "subjack"
verify_tool "asnmap" "asnmap"
verify_tool "gitleaks" "gitleaks"
verify_tool "trufflehog" "trufflehog"

# Vulnerability scanners
verify_tool "skipfish" "skipfish"
verify_tool "nikto" "nikto"
verify_tool "dalfox" "dalfox"
verify_tool "sqlmap" "sqlmap"
verify_tool "wpscan" "wpscan"
verify_tool "gowitness" "gowitness"
verify_tool "testssl.sh" "testssl.sh"

echo "" | tee -a "$REPORT"
echo "===== SPECIAL CHECKS =====" | tee -a "$REPORT"

# Nuclei special checks
if command -v nuclei >/dev/null 2>&1; then
  _nuclei_tmpl_found=false
  for _tdir in "$HOME/nuclei-templates" "$HOME/.local/nuclei-templates" "/opt/nuclei-templates" "/usr/share/nuclei-templates" "$HOME/.config/nuclei/templates"; do
    if [ -d "$_tdir" ]; then
      status_ok "nuclei templates exist at $_tdir"
      _nuclei_tmpl_found=true
      break
    fi
  done
  [ "$_nuclei_tmpl_found" = "false" ] && status_warn "nuclei templates not found (run: nuclei -update-templates)"
  # Nuclei v3.7+ uses -jsonl (or -j) for NDJSON output; -json was removed
  nuclei -h 2>/dev/null | grep -qiE '\-j,|\-jsonl' && status_ok "nuclei JSONL output supported (-jsonl flag)" || status_warn "nuclei JSONL output flag not found"
fi

# Skipfish special checks
if command -v skipfish >/dev/null 2>&1; then
  [ -f "/usr/share/skipfish/dictionaries/minimal.wl" ] && status_ok "skipfish dictionary present (minimal.wl)" \
    || { [ -f "/usr/share/skipfish/dictionaries/complete.wl" ] && status_ok "skipfish dictionary present (complete.wl)" \
    || status_warn "skipfish dictionary not found at /usr/share/skipfish/dictionaries/"; }
fi

# Rustscan special check
if command -v rustscan >/dev/null 2>&1; then
  timeout 10 rustscan -h >/dev/null 2>&1
  [ $? -eq 0 ] && status_ok "rustscan executable OK" || status_err "rustscan failed to execute"
fi

# Subjack fingerprints
if command -v subjack >/dev/null 2>&1; then
  [ -f "/usr/share/subjack/fingerprints.json" ] && status_ok "subjack fingerprints file present" || status_warn "subjack fingerprints missing (/usr/share/subjack/fingerprints.json)"
fi

# ASNMAP non-interactive + PDCP fallback signal
if command -v asnmap >/dev/null 2>&1; then
  timeout 15 bash -lc "asnmap -silent -d example.com </dev/null >/tmp/asnmap_check.out 2>/tmp/asnmap_check.err"
  if grep -Eqi "invalid api key|enter pdcp api key|recheck or recreate your api key|could not read input from terminal" /tmp/asnmap_check.err 2>/dev/null; then
    status_warn "asnmap requires API key (fallback required)"
  else
    status_ok "asnmap non-interactive execution OK"
  fi
fi

# Gitleaks/TruffleHog config sanity
if command -v gitleaks >/dev/null 2>&1; then
  timeout 10 gitleaks --help >/dev/null 2>/tmp/gitleaks_check.err
  [ $? -eq 0 ] && status_ok "gitleaks executes without config error" || status_err "gitleaks help/config error"
fi

if command -v trufflehog >/dev/null 2>&1; then
  timeout 10 trufflehog --help >/dev/null 2>/tmp/trufflehog_check.err
  [ $? -eq 0 ] && status_ok "trufflehog executes without config error" || status_err "trufflehog help/config error"
fi

echo "" | tee -a "$REPORT"
echo "Report written: $REPORT"
