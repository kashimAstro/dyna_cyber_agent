#pragma once
#include <functional>
#include <map>

#include "collectors/collector.h"
#include "collectors/log_analyzer.h"

namespace agent {

// Reads authentication, web and kernel logs incrementally (only what is new since the previous run), plus the
// systemd journal when the classic files are missing. Offsets live in the agent's database, so a restart
// neither loses nor repeats lines. Rotation is detected by inode, by size and by a fingerprint of the first
// bytes (inodes get reused), and the tail of the rotated file is still read.
class LogCollector final : public ICollector {
 public:
  explicit LogCollector(LogAnalyzerOptions o = {}) : analyzer_(o) {}

  std::string name() const override { return "logs"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::seconds(30); }
  void configure(const CollectorOptions& o) override {
    opts_ = o;
    analyzer_.setTemplates(o.log_templates, o.log_templates_per_cycle);
    analyzer_.attachState(o.state, "logtpl|" + o.target);
  }
  Result<CollectOutput> collect(ITransport& t) override;

  void setClock(std::function<int64_t()> c) { clock_ = std::move(c); }

  static constexpr uint64_t kChunk = 4u << 20;  // most data read from one file per run

 private:
  enum class Kind { Auth, Web, Kernel, Syslog };
  struct Source {
    std::string path;
    Kind kind = Kind::Syslog;
    bool parse_auth = false, parse_kernel = false;
  };
  struct FileState {
    uint64_t inode = 0, offset = 0, head_len = 0;
    std::string head_hash;
  };

  void detect(ITransport& t, std::vector<std::string>& warnings);
  std::vector<std::string> expand(ITransport& t, const std::string& pattern);
  std::optional<FileState> loadState(const std::string& path);
  void saveState(const std::string& path, const FileState& s);
  void feed(const Source& s, const std::string& data, int64_t now);

  CollectorOptions opts_;
  LogAnalyzer analyzer_;
  std::function<int64_t()> clock_;
  std::vector<Source> sources_;
  bool use_journal_ = false, journal_auth_ = false, journal_kernel_ = false;
  int runs_ = 0;
  int64_t journal_probe_run_ = -100;
  std::map<std::string, FileState> mem_state_;  // used when no persistent store is attached
};

}  // namespace agent
