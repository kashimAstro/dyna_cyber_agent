#include "collectors/collector.h"

#include <chrono>

#include "collectors/crossview_collector.h"
#include "collectors/file_collector.h"
#include "collectors/integrity_collector.h"
#include "collectors/log_collector.h"
#include "collectors/netflow_collector.h"
#include "collectors/network_collector.h"
#include "collectors/packages_collector.h"
#include "collectors/peer_collector.h"
#include "collectors/persistence_collector.h"
#include "collectors/process_collector.h"
#include "collectors/system_collector.h"
#include "collectors/vuln_collector.h"
#include "collectors/user_collector.h"

namespace agent {

std::unique_ptr<ICollector> makeCollector(const std::string& name) {
  if (name == "processes") return std::make_unique<ProcessCollector>();
  if (name == "network") return std::make_unique<NetworkCollector>();
  if (name == "users") return std::make_unique<UserCollector>();
  if (name == "logs") return std::make_unique<LogCollector>();
  if (name == "persistence") return std::make_unique<PersistenceCollector>();
  if (name == "system") return std::make_unique<SystemCollector>();
  if (name == "files") return std::make_unique<FileCollector>();
  if (name == "integrity") return std::make_unique<IntegrityCollector>();
  if (name == "packages") return std::make_unique<PackagesCollector>();
  if (name == "vulns") return std::make_unique<VulnCollector>();
  if (name == "peers") return std::make_unique<PeerCollector>();
  if (name == "crossview") return std::make_unique<CrossViewCollector>();
  if (name == "netflow") return std::make_unique<NetflowCollector>();
  return nullptr;
}

std::vector<std::string> collectorNames() { return {"processes", "network", "users", "logs", "persistence", "system", "files", "integrity", "packages", "vulns", "peers", "crossview", "netflow"}; }

Snapshot runCollector(ICollector& collector, ITransport& transport, const std::string& target) {
  Snapshot s;
  s.target = target;
  s.collector = collector.name();
  s.ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  const auto t0 = std::chrono::steady_clock::now();
  auto r = collector.collect(transport);
  s.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  if (r) {
    s.observations = std::move(r.value().observations);
    s.warnings = std::move(r.value().warnings);
  } else {
    s.error = r.error();
  }
  return s;
}

}  // namespace agent
