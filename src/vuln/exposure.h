#pragma once
#include <map>
#include <set>
#include <string>
#include <vector>

#include "collectors/collector.h"
#include "store/store.h"

namespace agent {

// Can the vulnerable software actually be reached? A flaw in a service that listens on the network is not the same
// as one in a package nobody runs. The answer comes from what the agent already knows about the target: which
// package owns the program behind each listening socket and each running process.
struct Exposure {
  std::map<std::string, std::vector<std::string>> listening_external;  // package -> "tcp/0.0.0.0:22"
  std::map<std::string, std::vector<std::string>> listening_local;     // loopback only
  std::set<std::string> running;
  bool ownership_known = false;  // the packages collector has recorded file lists for this target
  bool reboot_pending = false;
};

Exposure computeExposure(Store& store, const std::string& target);

// 0..100: CVSS, active exploitation (KEV), EPSS and reachability folded into one number to sort by.
int vulnPriority(const nlohmann::json& match_data, const std::vector<std::string>& tags);

// Adds exposure, ports, `priority` and the tags `listening`, `listening_local`, `running`, `reboot_pending` to every
// vuln.match, plus `exposed_likely_exploited` (a service on the network whose flaw has a high EPSS).
void annotateMatches(std::vector<Observation>& observations, const Exposure& ex);

}  // namespace agent
