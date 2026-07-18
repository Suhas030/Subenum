#!/bin/bash
#
# subenum.sh — multi-source subdomain enumeration + httpx status sorting
#
# Usage: ./subenum.sh <domain> [output_dir]
#
# Sources:  subfinder, assetfinder, findomain, sublist3r (each auto-detected), crt.sh (via curl+jq)
# Probing:  httpx (status code, title, tech, resolvers)
# Output:   <output_dir>/<domain>/live_by_status.txt   (grouped by status code)
#           <output_dir>/<domain>/live_full.txt        (tsv: url/status/title/tech)
#           <output_dir>/<domain>/all_subdomains.txt   (raw merged, pre-httpx)
#           <output_dir>/<domain>/*.raw                (per-source raw output, for debugging)
#
# All tool output is suppressed — only this script's own status lines print.

set -uo pipefail

# ---------- colors ----------
C_RESET='\033[0m'; C_BLUE='\033[1;34m'; C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'; C_RED='\033[1;31m'; C_CYAN='\033[1;36m'; C_BOLD='\033[1m'

info()  { echo -e "${C_BLUE}[*]${C_RESET} $1"; }
ok()    { echo -e "${C_GREEN}[✔]${C_RESET} $1"; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $1"; }
err()   { echo -e "${C_RED}[✘]${C_RESET} $1"; }
title() { echo -e "${C_CYAN}${C_BOLD}$1${C_RESET}"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------- args ----------
DOMAIN="${1:-}"
OUTBASE="${2:-.}"
HTTPX_THREADS="${HTTPX_THREADS:-40}"     # kept modest for low-RAM boxes
HTTPX_RATE="${HTTPX_RATE:-150}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [output_dir]"
    echo "Env overrides: HTTPX_THREADS=40 HTTPX_RATE=150"
    exit 1
fi

# ---------- validate domain format ----------
if ! [[ "$DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
    err "'$DOMAIN' doesn't look like a valid domain (e.g. example.com). Aborting."
    exit 1
fi

title "=============================================="
title " Subdomain Recon — $DOMAIN"
title "=============================================="

# ---------- hard dependency check (required for the script to function at all) ----------
MISSING_HARD=0
for dep in curl jq; do
    if ! have "$dep"; then
        err "Required dependency '$dep' not found. Install it and re-run (e.g. sudo apt install $dep)."
        MISSING_HARD=1
    fi
done
if [ "$MISSING_HARD" -eq 1 ]; then
    exit 1
fi

# ---------- tool availability check ----------
declare -A TOOLS=( [subfinder]=0 [assetfinder]=0 [findomain]=0 [sublist3r]=0 [httpx]=0 )
for t in "${!TOOLS[@]}"; do
    if have "$t"; then
        TOOLS[$t]=1
    fi
done

title "------------------------------------------------"
title " Tool availability check"
title "------------------------------------------------"
ANY_ENUM_TOOL=0
for t in subfinder assetfinder findomain sublist3r httpx; do
    label=$(printf "%-12s" "$t")
    if [ "${TOOLS[$t]}" -eq 1 ]; then
        echo -e "  $label : ${C_GREEN}Yes${C_RESET}"
        [ "$t" != "httpx" ] && ANY_ENUM_TOOL=1
    else
        echo -e "  $label : ${C_RED}NO${C_RESET}"
    fi
done
echo -e "  crt.sh       : ${C_GREEN}Yes${C_RESET} (always available via API)"
title "------------------------------------------------"

MISSING_LIST=()
for t in subfinder assetfinder findomain sublist3r httpx; do
    [ "${TOOLS[$t]}" -eq 0 ] && MISSING_LIST+=("$t")
done
if [ "${#MISSING_LIST[@]}" -gt 0 ]; then
    warn "The script will use only the available tools for this scan."
    warn "Kindly install the missing tools for better/more complete results: ${MISSING_LIST[*]}"
fi

if [ "$ANY_ENUM_TOOL" -eq 0 ]; then
    warn "No enumeration tool (subfinder/assetfinder/findomain/sublist3r) is installed — relying on crt.sh only."
fi

if [ "${TOOLS[httpx]}" -eq 0 ]; then
    warn "httpx is missing — subdomains will be collected but NOT probed for liveness/status codes."
fi
echo

# ---------- output dir ----------
OUTDIR="$OUTBASE/$DOMAIN"
mkdir -p "$OUTDIR" 2>/dev/null
if [ ! -d "$OUTDIR" ] || [ ! -w "$OUTDIR" ]; then
    err "Cannot create/write to output directory: $OUTDIR (permissions?)"
    exit 1
fi
cd "$OUTDIR" || { err "Failed to cd into $OUTDIR"; exit 1; }

ALL_RAW="all_subdomains.txt"
LIVE_JSON="live_httpx.json"
LIVE_FULL="live_full.txt"
STATUS_FILE="live_by_status.txt"

: > "$ALL_RAW.tmp"

# ---------- connectivity check ----------
if ! curl -s --max-time 8 -o /dev/null -w '%{http_code}' https://crt.sh >/dev/null 2>&1; then
    warn "Could not reach the internet / crt.sh in a quick check — sources needing network may fail silently below."
fi

# ---------- subfinder ----------
if [ "${TOOLS[subfinder]}" -eq 1 ]; then
    info "Running subfinder..."
    if timeout 300 subfinder -d "$DOMAIN" -silent -all -o subfinder.raw >/dev/null 2>&1; then
        cat subfinder.raw >> "$ALL_RAW.tmp" 2>/dev/null
        ok "subfinder done ($(wc -l < subfinder.raw 2>/dev/null || echo 0) found)"
    else
        warn "subfinder exited with an error or timed out — continuing without it"
    fi
fi

# ---------- assetfinder ----------
if [ "${TOOLS[assetfinder]}" -eq 1 ]; then
    info "Running assetfinder..."
    if timeout 300 assetfinder --subs-only "$DOMAIN" > assetfinder.raw 2>/dev/null; then
        cat assetfinder.raw >> "$ALL_RAW.tmp" 2>/dev/null
        ok "assetfinder done ($(wc -l < assetfinder.raw 2>/dev/null || echo 0) found)"
    else
        warn "assetfinder exited with an error or timed out — continuing without it"
    fi
fi

# ---------- findomain ----------
if [ "${TOOLS[findomain]}" -eq 1 ]; then
    info "Running findomain..."
    if timeout 300 findomain -t "$DOMAIN" -q > findomain.raw 2>/dev/null; then
        cat findomain.raw >> "$ALL_RAW.tmp" 2>/dev/null
        ok "findomain done ($(wc -l < findomain.raw 2>/dev/null || echo 0) found)"
    else
        warn "findomain exited with an error or timed out — continuing without it"
    fi
fi

# ---------- sublist3r ----------
if [ "${TOOLS[sublist3r]}" -eq 1 ]; then
    info "Running sublist3r..."
    if timeout 300 sublist3r -d "$DOMAIN" -o sublist3r.raw > /dev/null 2>&1; then
        cat sublist3r.raw >> "$ALL_RAW.tmp" 2>/dev/null
        ok "sublist3r done ($(wc -l < sublist3r.raw 2>/dev/null || echo 0) found)"
    else
        warn "sublist3r exited with an error or timed out — continuing without it"
    fi
fi

# ---------- crt.sh (direct API, no external repo dependency) ----------
info "Querying crt.sh..."
CRT_JSON=$(curl -s --max-time 30 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null)
if [ -n "$CRT_JSON" ] && echo "$CRT_JSON" | jq -e . >/dev/null 2>&1; then
    echo "$CRT_JSON" \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | tr 'A-Z' 'a-z' \
        | grep -F ".$DOMAIN" \
        | sort -u > crtsh.raw
    cat crtsh.raw >> "$ALL_RAW.tmp"
    ok "crt.sh done ($(wc -l < crtsh.raw 2>/dev/null || echo 0) found)"
else
    warn "crt.sh returned nothing usable (rate-limited, down, or invalid JSON) — skipping"
fi

# ---------- merge & dedupe ----------
info "Merging & deduping results..."
grep -E "^[a-zA-Z0-9._-]+\.$DOMAIN$" "$ALL_RAW.tmp" 2>/dev/null \
    | sort -u > "$ALL_RAW"
rm -f "$ALL_RAW.tmp"

TOTAL=$(wc -l < "$ALL_RAW" 2>/dev/null || echo 0)
if [ "$TOTAL" -eq 0 ]; then
    err "No subdomains found from any source. Nothing to probe. Exiting."
    exit 1
fi
ok "Total unique subdomains: $TOTAL  -> $ALL_RAW"
echo

# ---------- httpx probing ----------
if [ "${TOOLS[httpx]}" -eq 0 ]; then
    warn "httpx not installed — skipping liveness probing."
    warn "Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    title "=============================================="
    title " Recon Completed (enumeration only)"
    title " Subdomains file: $OUTDIR/$ALL_RAW"
    title "=============================================="
    exit 0
fi

info "Probing with httpx (threads=$HTTPX_THREADS, rate=$HTTPX_RATE)..."
if ! timeout 600 httpx -l "$ALL_RAW" \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -follow-redirects \
    -threads "$HTTPX_THREADS" \
    -rate-limit "$HTTPX_RATE" \
    -json \
    -o "$LIVE_JSON" >/dev/null 2>&1; then
    warn "httpx exited with a non-zero status (possibly a timeout) — checking partial results anyway."
fi

if [ ! -s "$LIVE_JSON" ]; then
    warn "No live hosts resolved (empty httpx output)."
    title "=============================================="
    title " Recon Completed — $TOTAL subdomains collected, 0 confirmed live"
    title "=============================================="
    exit 0
fi

LIVE_COUNT=$(wc -l < "$LIVE_JSON" 2>/dev/null || echo 0)
ok "httpx done. Live hosts: $LIVE_COUNT"

# ---------- build human-readable full list ----------
info "Building structured status report..."
jq -r '[.url, (.status_code|tostring), (.title // "-"), ((.tech // []) | join(","))] | @tsv' \
    "$LIVE_JSON" 2>/dev/null | sort -u > "$LIVE_FULL"

# ---------- group by status code ----------
: > "$STATUS_FILE"
{
    echo "=============================================="
    echo " Live Subdomains for $DOMAIN — grouped by status"
    echo " Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo " Total live: $LIVE_COUNT"
    echo "=============================================="
    echo
} >> "$STATUS_FILE"

for code in $(jq -r 'select(.status_code != null) | .status_code' "$LIVE_JSON" 2>/dev/null | sort -un); do
    {
        echo "$code :"
        echo "----------------------------------------------"
        jq -r --argjson c "$code" 'select(.status_code == $c) | "\(.url)  [\(.title // "-")]"' "$LIVE_JSON" 2>/dev/null | sort -u
        echo
    } >> "$STATUS_FILE"
done

ok "Status-grouped report saved to: $STATUS_FILE"
echo

# ---------- summary ----------
title "=============================================="
title " Summary for $DOMAIN"
title "=============================================="
echo -e "  Subdomains collected : ${C_BOLD}$TOTAL${C_RESET}"
echo -e "  Live (httpx)          : ${C_BOLD}$LIVE_COUNT${C_RESET}"
echo
jq -r 'select(.status_code != null) | .status_code' "$LIVE_JSON" 2>/dev/null | sort -n | uniq -c | sort -rn | \
    while read -r count code; do
        printf "  %-6s : %s\n" "$code" "$count"
    done
echo
title " Files:"
echo "  $OUTDIR/$ALL_RAW"
echo "  $OUTDIR/$LIVE_FULL"
echo "  $OUTDIR/$STATUS_FILE"
title "=============================================="
title " Recon Completed"
title "=============================================="
