#pragma once
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "core/result.h"

namespace agent {

struct FileContent {
  std::string data;
  bool truncated = false;
};

struct DirEntry {
  std::string name;
  bool is_dir = false;
  bool is_symlink = false;
};

struct FileInfo {
  uint32_t mode = 0;  // st_mode (type + permission bits)
  uint32_t uid = 0;
  uint32_t gid = 0;
  uint64_t size = 0;
  int64_t atime = 0;
  int64_t mtime = 0;
  int64_t ctime = 0;
  bool is_symlink = false;
};

struct CommandResult {
  int exit_code = -1;
  std::string out;
  std::string err;
  bool timed_out = false;
  bool truncated = false;
};

struct RunLimits {
  std::chrono::seconds timeout{20};
  size_t max_output = 8 * 1024 * 1024;
};

// Result of reading a file from a given offset (log tailing). `inode` and `size` let the caller tell
// "more data" from "the log was rotated".
struct TailResult {
  std::string data;
  uint64_t size = 0;
  uint64_t inode = 0;
  int64_t mtime = 0;
};

struct JournalResult {
  std::string text;    // journalctl -o short-iso lines (without the cursor trailer)
  std::string cursor;  // pass it back to continue where this read stopped
};

// A file found by one of the fixed filesystem scans (see scan_presets.h).
struct ScanEntry {
  char type = 'f';     // find's %y: f file, d dir, l link, s socket, p fifo
  uint32_t mode = 0;   // permission bits including setuid/setgid/sticky, from find's %m (octal)
  std::string user, group;
  uint64_t size = 0;
  int64_t mtime = 0;
  std::string path;
};

// One read-only request of a batch. Batches exist because over SSH every round trip costs milliseconds:
// scanning /proc one file at a time would take minutes, one batch takes a fraction of a second.
struct ReadOp {
  enum class Kind {
    ReadFile,      // content, capped at `limit` bytes
    ReadLink,
    ListDir,
    Stat,
    Sha256,        // of the file content, fails above `limit` bytes
    RwxMapCount,   // number of rwx mappings in a /proc/<pid>/maps file (counted at the source: maps can be MBs)
    SocketInodes,  // inodes of the sockets held by a /proc/<pid>/fd directory
    Tail,          // bytes of a file from `offset` (at most `limit`), plus size and inode
    Journal,       // systemd journal: `path` = scope (sys|kernel), `arg` = cursor, `limit` = max lines
    Scan,          // fixed filesystem scan: `path` = preset name (suid, volatile, ...)
  };
  Kind kind = Kind::ReadFile;
  std::string path;
  uint64_t limit = 0;
  uint64_t offset = 0;
  std::string arg;

  static ReadOp file(std::string p, uint64_t max) { return {Kind::ReadFile, std::move(p), max}; }
  static ReadOp link(std::string p) { return {Kind::ReadLink, std::move(p), 0}; }
  static ReadOp list(std::string p) { return {Kind::ListDir, std::move(p), 0}; }
  static ReadOp stat(std::string p) { return {Kind::Stat, std::move(p), 0}; }
  static ReadOp sha256(std::string p, uint64_t max) { return {Kind::Sha256, std::move(p), max}; }
  static ReadOp rwxMaps(std::string p) { return {Kind::RwxMapCount, std::move(p), 0}; }
  static ReadOp socketInodes(std::string p) { return {Kind::SocketInodes, std::move(p), 0}; }
  static ReadOp tail(std::string p, uint64_t offset, uint64_t max) { return {Kind::Tail, std::move(p), max, offset, {}}; }
  static ReadOp journal(std::string scope, std::string cursor, uint64_t max_lines) { return {Kind::Journal, std::move(scope), max_lines, 0, std::move(cursor)}; }
  static ReadOp scan(std::string preset) { return {Kind::Scan, std::move(preset), 0, 0, {}}; }
};

struct OpResult {
  bool ok = false;
  std::string error;
  FileContent file;                // ReadFile
  std::string text;                // ReadLink, Sha256
  std::vector<DirEntry> entries;   // ListDir
  FileInfo info;                   // Stat
  int64_t count = 0;               // RwxMapCount
  std::vector<uint64_t> inodes;    // SocketInodes
  TailResult tail;                 // Tail
  JournalResult journal;           // Journal
  std::vector<ScanEntry> scan;     // Scan
};

// Read-only access to the machine under analysis. The interface deliberately
// exposes no write primitive: implementations MUST NOT modify the target.
class ITransport {
 public:
  virtual ~ITransport() = default;

  virtual std::string name() const = 0;

  virtual Result<FileContent> readFile(const std::string& path, size_t max_bytes) = 0;
  virtual Result<std::string> readLink(const std::string& path) = 0;
  virtual Result<std::vector<DirEntry>> listDir(const std::string& path) = 0;
  virtual Result<FileInfo> stat(const std::string& path) = 0;

  // SHA-256 (hex) of a file's content, streamed so large binaries do not need to fit in memory.
  // Fails when the file is larger than `max_bytes`.
  virtual Result<std::string> sha256File(const std::string& path, uint64_t max_bytes) = 0;

  // Incremental reading (log files). Default: not supported.
  virtual Result<TailResult> tailFile(const std::string& path, uint64_t offset, uint64_t max_bytes);
  // systemd journal since `after_cursor` ("" = the most recent `max_lines`). scope: "sys" or "kernel".
  virtual Result<JournalResult> journal(const std::string& scope, const std::string& after_cursor, uint64_t max_lines);
  // Runs one of the fixed, read-only filesystem scans (see scan_presets.h).
  virtual Result<std::vector<ScanEntry>> scan(const std::string& preset);

  // Executes many read requests together; results are in request order. The default implementation
  // runs them one by one, SSH sends the whole batch in a single round trip.
  virtual std::vector<OpResult> bulk(const std::vector<ReadOp>& ops);

  // Runs a command from the built-in read-only whitelist (see CommandPolicy).
  // argv[0] is the bare command name; there is no shell involved.
  virtual Result<CommandResult> run(const std::vector<std::string>& argv, const RunLimits& limits = {}) = 0;
};

}  // namespace agent
