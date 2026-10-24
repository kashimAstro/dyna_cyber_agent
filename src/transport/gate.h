#pragma once
#include <string>
#include <vector>

namespace agent {

// The remote side of the SSH transport: a small POSIX sh program that answers read-only requests.
//
// Protocol (line based, everything binary-safe thanks to base64):
//   server -> "AGENT-GATE 2 <hostname>"                       once, at start
//   client -> "<verb> <args...>"                              one request per line
//   server -> "OK <base64 payload>"  or  "ER <base64 message>" exactly one line per request
// Verbs: read, tail, readlink, ls, stat, sha256, rwx, sockets, journal, scan, run, caps, ping. None of them can modify the
// machine: files are only opened for reading, `scan` only runs the fixed find presets, `run` only executes the
// exact command lines listed below.
//
// The script is embedded in the binary, so the agent needs nothing installed on the target ("stream"
// mode). For hardening it can be installed (`dyna_cyber_agent --print-gate`) and pinned in authorized_keys with
// command="...", so that even a stolen key can do nothing but these read-only verbs.
class Gate {
 public:
  static constexpr int kProtocolVersion = 2;

  // Full script text.
  static std::string script();

  // Command lines `run` accepts, verbatim (the whitelist baked into the script).
  static const std::vector<std::string>& commands();
};

}  // namespace agent
