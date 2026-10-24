#include "transport/gate.h"

#include "transport/scan_presets.h"

namespace agent {
namespace {

// @@RUN_CASES@@ is replaced with the generated whitelist so there is a single source of truth.
const char* kScript = R"GATE(#!/bin/sh
# dyna_cyber_agent read-only gate, protocol v2.
# Reads one request per line on stdin, writes one reply line per request:
#   OK <base64>   or   ER <base64 message>
# Nothing here writes to the machine: files are only read, `run` only executes whitelisted command lines.
LC_ALL=C; export LC_ALL
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
umask 077
MAXREAD=134217728

ok() { printf 'OK %s\n' "$1"; }
er() { printf 'ER %s\n' "$(printf '%s' "$1" | base64 -w0)"; }
b64() { base64 -w0; }
dec() { printf '%s' "$1" | base64 -d 2>/dev/null; }
isnum() { case $1 in ''|*[!0-9]*) return 1;; esac; [ ${#1} -le 12 ]; }
abs() { case $1 in /*) return 0;; esac; return 1; }
# heavy reads must never compete with the machine's real work
lowprio() {
  if command -v ionice >/dev/null 2>&1; then ionice -c3 nice -n 19 "$@"
  elif command -v nice >/dev/null 2>&1; then nice -n 19 "$@"
  else "$@"; fi
}

printf 'AGENT-GATE 2 %s\n' "$(hostname 2>/dev/null | tr -d ' \r\n')"

while IFS=' ' read -r verb a1 a2 rest; do
  case $verb in
    '') continue ;;
    ping) ok "" ;;
    caps)
      c=""
      for t in base64 find stat sha256sum head grep cut readlink hostname tr id; do
        if command -v "$t" >/dev/null 2>&1; then c="$c $t=ok"; else c="$c $t=MISSING"; fi
      done
      if find /proc/self -maxdepth 0 -printf '%y' >/dev/null 2>&1; then c="$c find_printf=ok"; else c="$c find_printf=MISSING"; fi
      if stat -c '%f' /proc/self >/dev/null 2>&1; then c="$c stat_c=ok"; else c="$c stat_c=MISSING"; fi
      c="$c uid=$(id -u 2>/dev/null)"
      ok "$(printf '%s' "$c" | b64)" ;;
    read)
      isnum "$a1" || { er "bad size"; continue; }
      [ "$a1" -le "$MAXREAD" ] || a1=$MAXREAD
      p=$(dec "$a2")
      abs "$p" || { er "path must be absolute"; continue; }
      [ -f "$p" ] || { er "not a regular file: $p"; continue; }
      [ -r "$p" ] || { er "permission denied: $p"; continue; }
      ok "$(head -c "$a1" -- "$p" 2>/dev/null | b64)" ;;
    tail)
      isnum "$a1" && isnum "$a2" || { er "bad numbers"; continue; }
      [ "$a2" -le "$MAXREAD" ] || a2=$MAXREAD
      p=$(dec "$rest")
      abs "$p" || { er "path must be absolute"; continue; }
      [ -f "$p" ] && [ -r "$p" ] || { er "cannot read: $p"; continue; }
      meta=$(stat -L -c '%s %i %Y' -- "$p" 2>/dev/null) || { er "stat failed: $p"; continue; }
      sz=${meta%% *}
      if [ "$a1" -lt "$sz" ]; then
        ok "$( { printf '%s\n' "$meta"; tail -c +"$((a1 + 1))" -- "$p" 2>/dev/null | head -c "$a2"; } | b64)"
      else
        ok "$(printf '%s\n' "$meta" | b64)"
      fi ;;
    readlink)
      p=$(dec "$a1")
      abs "$p" || { er "path must be absolute"; continue; }
      t=$(readlink -- "$p" 2>/dev/null) || { er "readlink failed: $p"; continue; }
      ok "$(printf '%s' "$t" | b64)" ;;
    ls)
      p=$(dec "$a1")
      abs "$p" || { er "path must be absolute"; continue; }
      if [ -d "$p" ] && [ -r "$p" ] && [ -x "$p" ]; then
        ok "$(find "$p" -mindepth 1 -maxdepth 1 -printf '%y%f\0' 2>/dev/null | b64)"
      else
        er "cannot list: $p"
      fi ;;
    stat)
      p=$(dec "$a1")
      abs "$p" || { er "path must be absolute"; continue; }
      s=$(stat -c '%f %u %g %s %X %Y %Z' -- "$p" 2>/dev/null) || { er "stat failed: $p"; continue; }
      ok "$(printf '%s' "$s" | b64)" ;;
    sha256)
      isnum "$a1" || { er "bad size"; continue; }
      p=$(dec "$a2")
      abs "$p" || { er "path must be absolute"; continue; }
      [ -f "$p" ] && [ -r "$p" ] || { er "cannot read: $p"; continue; }
      sz=$(stat -L -c %s -- "$p" 2>/dev/null)
      isnum "$sz" || sz=0
      [ "$sz" -le "$a1" ] || { er "file too large to hash: $p"; continue; }
      h=$(sha256sum -- "$p" 2>/dev/null | cut -d' ' -f1)
      [ ${#h} -eq 64 ] || { er "sha256sum failed: $p"; continue; }
      ok "$(printf '%s' "$h" | b64)" ;;
    rwx)
      p=$(dec "$a1")
      case $p in *..*) er "bad path"; continue ;; /proc/[0-9]*/maps) ;; *) er "not a maps path"; continue ;; esac
      [ -r "$p" ] || { er "permission denied: $p"; continue; }
      n=$(grep -c -E '^[^ ]+ rwx' -- "$p" 2>/dev/null)
      ok "$(printf '%s' "${n:-0}" | b64)" ;;
    sockets)
      p=$(dec "$a1")
      case $p in *..*) er "bad path"; continue ;; /proc/[0-9]*/fd) ;; *) er "not an fd path"; continue ;; esac
      if [ -r "$p" ] && [ -x "$p" ]; then
        ok "$(find "$p" -maxdepth 1 -type l -lname 'socket:*' -printf '%l\n' 2>/dev/null | b64)"
      else
        er "permission denied: $p"
      fi ;;
    journal)
      case $a1 in sys|kernel) ;; *) er "bad scope"; continue ;; esac
      isnum "$a2" || { er "bad count"; continue; }
      [ "$a2" -le 20000 ] || a2=20000
      cur=$(dec "$rest")
      [ "$cur" = "-" ] && cur=""
      case $cur in *[!A-Za-z0-9=\;_.:+/-]*) er "bad cursor"; continue ;; esac
      command -v journalctl >/dev/null 2>&1 || { er "journalctl not found"; continue; }
      set -- journalctl -q --no-pager -o short-iso --show-cursor -n "$a2"
      [ "$a1" = kernel ] && set -- "$@" -k
      [ -n "$cur" ] && set -- "$@" "--after-cursor=$cur"
      out=$(lowprio "$@" 2>&1 </dev/null) || { er "journalctl failed: $(printf '%s' "$out" | head -c 200)"; continue; }
      case $out in *"insufficient permissions"*) er "journal not readable (insufficient permissions)"; continue ;; esac
      ok "$(printf '%s' "$out" | head -c 16777216 | b64)" ;;
    scan)
      case $a1 in
@@SCAN_CASES@@
        *) er "unknown scan preset"; continue ;;
      esac ;;
    run)
      set --
      for t in $a1 $a2 $rest; do set -- "$@" "$(dec "$t")"; done
      case "$*" in
@@RUN_CASES@@
        *) er "command not allowed by gate: $*"; continue ;;
      esac
      out=$("$@" 2>&1 </dev/null; echo "~$?")
      rc=${out##*~}
      body=${out%~*}
      ok "$( { printf '%s\n' "$rc"; printf '%s' "$body" | head -c 8388608; } | b64)" ;;
    *) er "unknown verb: $verb" ;;
  esac
done
)GATE";

}  // namespace

const std::vector<std::string>& Gate::commands() {
  static const std::vector<std::string> c = {
      "uname -a",
      "uname -sr",
      "uptime",
      "id",
      "who -u",
      "last -n 50 -F",
      "lsmod",
      "ss -tunap",
      "ss -tulpn",
      "ip -j addr",
      "ip -j route",
      "ip -j neigh",
      "systemctl list-timers --all --no-pager",
      "systemctl list-unit-files --no-pager",
      "systemctl list-units --type=service --state=running --no-pager",
      "systemctl list-sockets --all --no-pager",
      "dpkg -V",
      "rpm -Va",
      "rpm -qa",
  };
  return c;
}

std::string Gate::script() {
  std::string cases = "        ";
  bool first = true;
  for (const auto& c : commands()) {
    if (!first) cases += "|";
    cases += "\"" + c + "\"";
    first = false;
  }
  cases += ") ;;";

  // One branch per scan preset, generated from the very same find command lines the local transport uses.
  std::string scans;
  for (const auto& p : scanPresets()) {
    scans += "        " + p.name + ") ok \"$(lowprio find";
    for (const auto& a : p.find_args) scans += " " + shellQuote(a);
    scans += " 2>/dev/null | head -c 33554432 | b64)\" ;;\n";
  }
  if (!scans.empty()) scans.pop_back();

  std::string s = kScript;
  auto replace = [&](const std::string& tag, const std::string& value) { s.replace(s.find(tag), tag.size(), value); };
  replace("@@RUN_CASES@@", cases);
  replace("@@SCAN_CASES@@", scans);
  return s;
}

}  // namespace agent
