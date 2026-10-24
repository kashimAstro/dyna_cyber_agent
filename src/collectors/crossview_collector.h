#pragma once
#include <set>
#include <string>

#include "collectors/collector.h"

namespace agent {

// Looks at the same thing through two independent windows and reports what only one of them shows. A rootkit can
// edit the answer of one kernel interface; editing every interface consistently is much harder, and signatures are
// not needed, so new rootkits are caught as well:
//   processes  /proc directory listing        vs  the cgroup membership lists (cgroup.procs)
//   modules    /proc/modules                  vs  /sys/module/*/initstate
//   ports      /proc/net/tcp (listening)      vs  `ss` (netlink)
// A mismatch must be seen on two consecutive runs before it is reported: processes start and stop, and the two
// reads cannot be exactly simultaneous. It also lists the eBPF programs the kernel JIT-compiled (a favourite
// hiding place for modern rootkits) and the objects pinned in /sys/fs/bpf, so a new one shows up as drift.
class CrossViewCollector final : public ICollector {
 public:
  std::string name() const override { return "crossview"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::minutes(10); }
  Result<CollectOutput> collect(ITransport& t) override;

  // Pure helpers (exposed for tests).
  static std::set<int> parsePidList(const std::string& cgroup_procs);
  static std::set<int> listeningTcpPorts(const std::string& proc_net_tcp);        // state 0A in /proc/net/tcp or tcp6
  static std::set<int> ssListeningTcpPorts(const std::string& ss_output);         // `ss -tulpn`
  struct BpfProgram { std::string tag, name; };
  static std::vector<BpfProgram> bpfPrograms(const std::string& kallsyms);

 private:
  std::set<std::string> previous_;  // mismatches seen in the previous run
  std::vector<Observation> bpf_cache_;  // /proc/kallsyms is megabytes: read it hourly, report the same programs in between
  int runs_ = 0;
};

}  // namespace agent
