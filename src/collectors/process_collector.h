#pragma once
#include <map>
#include <optional>

#include "collectors/collector.h"

namespace agent {

struct ProcStat {
  std::string comm;
  char state = '?';
  int64_t ppid = 0;
  uint64_t start_ticks = 0;  // since boot, in clock ticks
};

struct ProcStatus {
  std::string name;
  int64_t uid = -1;
  int64_t gid = -1;
};

// Pure parsers (exposed for tests).
std::optional<ProcStat> parseProcStat(const std::string& text);
ProcStatus parseProcStatus(const std::string& text);
std::vector<std::string> splitCmdline(const std::string& raw);
int countRwxMappings(const std::string& maps);
std::vector<std::string> processTags(const std::string& comm, const std::optional<std::string>& exe, bool kernel_thread,
                                     int rwx_maps);

class ProcessCollector final : public ICollector {
 public:
  std::string name() const override { return "processes"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::seconds(30); }
  Result<CollectOutput> collect(ITransport& t) override;

 private:
  std::map<std::string, std::string> hash_cache_;  // "path|size|mtime" -> sha256 ("" = known unhashable)
  bool warned_too_large_ = false;
};

}  // namespace agent
