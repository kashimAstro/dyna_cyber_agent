#pragma once
#include <string>
#include <vector>

#include "transport/transport.h"

namespace agent {

// The only filesystem scans the agent can request. Each one is a fixed `find` command line, defined once
// here and used both by the local transport and by the generated remote gate, so both sides behave the same.
// They only read metadata (never file contents) and run at the lowest CPU/IO priority.
struct ScanPreset {
  std::string name;
  std::vector<std::string> find_args;  // everything after "find"
};

const std::vector<ScanPreset>& scanPresets();
const ScanPreset* findScanPreset(const std::string& name);

// Presets:
//   suid       setuid/setgid regular files on every real filesystem
//   volatile   files, links, sockets, fifos in /tmp, /var/tmp, /dev/shm (depth <= 6)
//   writable   world-writable files and non-sticky world-writable dirs in system directories
//   localexec  executable files in /usr/local, /opt, /srv and /root/bin style locations (depth <= 4)

// find's -printf format: "%y\t%m\t%u\t%g\t%s\t%T@\t%p\0"
extern const char* const kScanFormat;

// Parses the NUL-separated records produced with kScanFormat.
std::vector<ScanEntry> parseScanOutput(const std::string& raw);

// Single-quotes a word for POSIX sh.
std::string shellQuote(const std::string& s);

// Characters allowed in a journal cursor (anything else is refused: it ends up on a command line).
bool validJournalCursor(const std::string& c);

// Splits `journalctl --show-cursor` output into text and the trailing "-- cursor: ..." value.
JournalResult parseJournalOutput(const std::string& raw);

}  // namespace agent
