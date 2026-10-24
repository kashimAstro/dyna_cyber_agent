#pragma once
#include <map>

#include "transport/transport.h"

namespace agent {

// In-memory target used to test collectors deterministically.
class FakeTransport final : public ITransport {
 public:
  std::map<std::string, std::string> files;
  std::map<std::string, std::string> links;
  std::map<std::string, std::vector<std::string>> dirs;
  std::map<std::string, std::string> hashes;  // path -> sha256
  int hash_calls = 0;
  std::map<std::string, std::vector<ScanEntry>> scans;      // preset -> entries
  std::map<std::string, uint64_t> inodes;                    // path -> inode (for tail)
  std::string journal_text, journal_cursor;                  // what journal() returns
  bool journal_fails = false;
  std::map<std::string, FileInfo> infos;                     // path -> stat result (default: zeroed FileInfo)
  std::map<std::string, CommandResult> commands;             // "dpkg -V" -> result

  std::string name() const override { return "fake"; }

  Result<FileContent> readFile(const std::string& p, size_t max) override {
    auto it = files.find(p);
    if (it == files.end()) return err("ENOENT " + p);
    FileContent c;
    c.data = it->second.substr(0, max);
    c.truncated = it->second.size() > max;
    return c;
  }
  Result<std::string> readLink(const std::string& p) override {
    auto it = links.find(p);
    if (it == links.end()) return err("ENOENT " + p);
    return it->second;
  }
  Result<std::vector<DirEntry>> listDir(const std::string& p) override {
    auto it = dirs.find(p);
    if (it == dirs.end()) return err("ENOENT " + p);
    std::vector<DirEntry> out;
    for (const auto& n : it->second) {
      const std::string full = p + "/" + n;
      out.push_back({n, dirs.count(full) > 0, links.count(full) > 0});  // known sub-dirs and links are reported as such
    }
    return out;
  }
  Result<FileInfo> stat(const std::string& p) override {
    if (auto it = infos.find(p); it != infos.end()) return it->second;
    if (!files.count(p) && !dirs.count(p)) return err("ENOENT " + p);
    return FileInfo{};
  }
  Result<std::string> sha256File(const std::string& p, uint64_t) override {
    ++hash_calls;
    auto it = hashes.find(p);
    if (it == hashes.end()) return err("ENOENT " + p);
    return it->second;
  }
  Result<TailResult> tailFile(const std::string& p, uint64_t offset, uint64_t max) override {
    auto it = files.find(p);
    if (it == files.end()) return err("ENOENT " + p);
    TailResult t;
    t.size = it->second.size();
    t.inode = inodes.count(p) ? inodes[p] : 1;
    t.mtime = 1000;
    if (offset < t.size) t.data = it->second.substr(offset, max);
    return t;
  }
  Result<JournalResult> journal(const std::string&, const std::string&, uint64_t) override {
    if (journal_fails) return err("journal not readable");
    return JournalResult{journal_text, journal_cursor};
  }
  Result<std::vector<ScanEntry>> scan(const std::string& preset) override {
    auto it = scans.find(preset);
    if (it == scans.end()) return err("scan not available: " + preset);
    return it->second;
  }
  Result<CommandResult> run(const std::vector<std::string>& argv, const RunLimits&) override {
    std::string joined;
    for (const auto& a : argv) joined += (joined.empty() ? "" : " ") + a;
    auto it = commands.find(joined);
    if (it == commands.end()) return err("no commands in fake: " + joined);
    return it->second;
  }
};

}  // namespace agent
