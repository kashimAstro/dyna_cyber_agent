#!/usr/bin/env bash
# dyna_cyber_agent - acceptance run.
# Runs the agent's checks in a fixed order and gathers the output in one archive you can send back.
#
# By default it is conservative: nothing leaves this machine except what the agent itself does for a
# normal `--once` run (SSH to the configured targets, if any). Optional steps that contact other services
# or send mail are OFF unless you ask for them with a flag.
#
# NOTE: `--once` also runs the `vulns` collector. With the default configuration (vuln.enabled and vuln.osv true)
# that asks osv.dev about the NAMES AND VERSIONS of the installed source packages. If that must not happen,
# set `vuln: { osv: false }` (or `enabled: false`) in the configuration BEFORE running this script.
#
#   scripts/collaudo.sh --config /etc/dyna_cyber_agent/agent.yaml [options]
#
# Options:
#   --bin PATH          agent binary (default: dyna_cyber_agent from PATH, or ./build/dyna_cyber_agent)
#   --out DIR           where to put the results (default: ./collaudo-<host>-<date>)
#   --with-llm          also run `--llm-ping` and `--analyze` (contacts llama-server)
#   --with-vuln-sync    also run `--vuln-sync all` (downloads CVE / KEV / CWE feeds from the public services)
#   --with-vuln-check   also run `--vuln-check` (asks osv.dev about the PACKAGE NAMES AND VERSIONS of the targets)
#   --with-mail-test    also run `--send-test-mail` (sends ONE mail to the configured recipients)
#   --redact            replace IPv4 addresses and e-mail addresses in the saved output
#   --skip-once         do not run the collectors (only configuration and connectivity checks)
#   -h, --help          this text
set -u

CONFIG=""
BIN=""
OUT=""
WITH_LLM=0; WITH_VSYNC=0; WITH_VCHECK=0; WITH_MAIL=0; REDACT=0; SKIP_ONCE=0

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --config) CONFIG="${2:-}"; shift 2 ;;
    --bin) BIN="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --with-llm) WITH_LLM=1; shift ;;
    --with-vuln-sync) WITH_VSYNC=1; shift ;;
    --with-vuln-check) WITH_VCHECK=1; shift ;;
    --with-mail-test) WITH_MAIL=1; shift ;;
    --redact) REDACT=1; shift ;;
    --skip-once) SKIP_ONCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$CONFIG" ] || { echo "--config is required" >&2; usage >&2; exit 2; }
[ -r "$CONFIG" ] || { echo "cannot read config: $CONFIG" >&2; exit 2; }
if [ -z "$BIN" ]; then
  if command -v dyna_cyber_agent >/dev/null 2>&1; then BIN="$(command -v dyna_cyber_agent)"
  elif [ -x ./build/dyna_cyber_agent ]; then BIN="./build/dyna_cyber_agent"
  else echo "dyna_cyber_agent not found: pass --bin" >&2; exit 2; fi
fi
[ -x "$BIN" ] || { echo "not executable: $BIN" >&2; exit 2; }

HOST="$(hostname 2>/dev/null || echo host)"
STAMP="$(date +%Y%m%d-%H%M%S)"
[ -n "$OUT" ] || OUT="./collaudo-$HOST-$STAMP"
mkdir -p "$OUT" || exit 2
SUMMARY="$OUT/SUMMARY.txt"
A=("$BIN" --config "$CONFIG")

has_ssh_target() { grep -Eq '^[[:space:]]*(-[[:space:]]*)?transport:[[:space:]]*ssh|transport:[[:space:]]*ssh' "$CONFIG"; }

STEP=0
FAILED=0
: > "$SUMMARY"

# run <name> <timeout-seconds> <command...>
run() {
  local name="$1" to="$2"; shift 2
  STEP=$((STEP + 1))
  local f; f="$(printf '%s/%02d-%s.txt' "$OUT" "$STEP" "$name")"
  local t0 rc
  t0=$(date +%s)
  echo "### \$ $*" > "$f"
  timeout --foreground -s TERM "$to" "$@" >> "$f" 2>&1
  rc=$?
  local dt=$(( $(date +%s) - t0 ))
  local verdict="OK"
  [ "$rc" -eq 124 ] && verdict="TIMEOUT"
  [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && verdict="FAILED(exit $rc)"
  [ "$verdict" != "OK" ] && FAILED=$((FAILED + 1))
  printf '%-28s %-18s %4ss   %s\n' "$name" "$verdict" "$dt" "$(basename "$f")" | tee -a "$SUMMARY"
}

skip() { printf '%-28s %-18s\n' "$1" "SKIPPED ($2)" | tee -a "$SUMMARY"; }

echo "NOTE: with vuln.enabled and vuln.osv on (the default), --once also queries osv.dev with package names and versions."
echo "dyna_cyber_agent acceptance run - $(date -u '+%Y-%m-%d %H:%M:%S UTC') - output in $OUT"
echo "------------------------------------------------------------------------------" | tee -a "$SUMMARY"

# 0. environment (no secrets)
{
  echo "date      : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "host      : $HOST"
  echo "kernel    : $(uname -sr)"
  echo "os        : $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  echo "cpus/mem  : $(nproc 2>/dev/null) cpu, $(awk '/MemTotal/ {printf "%d MiB", $2/1024}' /proc/meminfo 2>/dev/null)"
  echo "user      : $(id -un) (uid $(id -u), groups: $(id -Gn | tr ' ' ','))"
  echo "agent     : $("$BIN" --version 2>&1)"
  echo "ssh       : $(ssh -V 2>&1)"
  echo "config    : $CONFIG (contents NOT collected)"
  echo "options   : llm=$WITH_LLM vuln_sync=$WITH_VSYNC vuln_check=$WITH_VCHECK mail=$WITH_MAIL redact=$REDACT skip_once=$SKIP_ONCE"
} > "$OUT/00-environment.txt"
STEP=0
printf '%-28s %-18s\n' "environment" "OK" | tee -a "$SUMMARY"

run version-and-check 60 "${A[@]}" --check
run baseline-status 30 "${A[@]}" --baseline-status

if has_ssh_target; then run ssh-test 300 "${A[@]}" --ssh-test all; else skip ssh-test "no ssh target in the config"; fi

if [ "$WITH_LLM" -eq 1 ]; then
  run llm-ping 30 "${A[@]}" --llm-ping
else
  skip llm-ping "use --with-llm"
fi

run vuln-status 30 "${A[@]}" --vuln-status
if [ "$WITH_VSYNC" -eq 1 ]; then run vuln-sync 3600 "${A[@]}" --vuln-sync all; else skip vuln-sync "use --with-vuln-sync"; fi

if [ "$SKIP_ONCE" -eq 0 ]; then
  run collect-once 1800 "${A[@]}" --once
  run events 60 "${A[@]}" --events --all
else
  skip collect-once "--skip-once"
fi

if [ "$WITH_VCHECK" -eq 1 ]; then run vuln-check 900 "${A[@]}" --vuln-check; else skip vuln-check "use --with-vuln-check"; fi
if [ "$WITH_LLM" -eq 1 ] && [ "$SKIP_ONCE" -eq 0 ]; then run llm-analyze 1800 "${A[@]}" --analyze; else skip llm-analyze "use --with-llm"; fi

# report previews are written to files: keep the plain-text ones
PREV="$OUT/previews"; mkdir -p "$PREV"
run report-preview-digest 60 "${A[@]}" --report-preview digest --out "$PREV"
run report-preview-alert 60 "${A[@]}" --report-preview alert --out "$PREV"

if [ "$WITH_MAIL" -eq 1 ]; then run send-test-mail 120 "${A[@]}" --send-test-mail; else skip send-test-mail "use --with-mail-test"; fi
run notifications 30 "${A[@]}" --notifications

# optional redaction
if [ "$REDACT" -eq 1 ]; then
  find "$OUT" -type f \( -name '*.txt' -o -name '*.html' \) -print0 | xargs -0 sed -i -E \
    -e 's/\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/A.B.C.D/g' \
    -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/user@example.invalid/g'
fi

echo "------------------------------------------------------------------------------" | tee -a "$SUMMARY"
echo "steps failed or timed out: $FAILED" | tee -a "$SUMMARY"

ARCHIVE="$OUT.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUT")" "$(basename "$OUT")" && NOTE="process command lines and host names are in there"
[ "$REDACT" -eq 1 ] && NOTE="$NOTE; --redact only masks IPv4 and e-mail addresses"
echo "archive: $ARCHIVE  (review it before sending: $NOTE)"
exit 0
