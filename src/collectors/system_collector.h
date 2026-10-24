#pragma once
#include <map>
#include <optional>

#include "collectors/collector.h"

namespace agent {

struct ModuleInfo {
  std::string name, state, taint;
  uint64_t size = 0;
  int64_t refcount = 0;
  std::vector<std::string> used_by;
};
struct MountInfo {
  std::string device, mountpoint, fstype;
  std::vector<std::string> options;
};
struct SshdOption {
  std::string name, value;
};

// Pure parsers (exposed for tests).
std::vector<ModuleInfo> parseModules(const std::string& proc_modules);
std::string taintLetters(uint64_t value);  // kernel taint bits as letters, e.g. "OE"
std::vector<MountInfo> parseMounts(const std::string& proc_mounts);
// Global (pre-`Match`) options in file order; a `Match` line is reported as option "match".
std::vector<SshdOption> parseSshdConfig(const std::string& text);

// State of the machine itself: kernel modules and taint, security-relevant sysctl values, mounts, resolver and
// hosts file, sshd configuration, network interface modes, device nodes.
class SystemCollector final : public ICollector {
 public:
  std::string name() const override { return "system"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::minutes(10); }
  Result<CollectOutput> collect(ITransport& t) override;
};

}  // namespace agent
