#include "collectors/peer_collector.h"

#include <algorithm>
#include <chrono>
#include <map>

#include "analysis/identity.h"
#include "core/util.h"
#include "store/store.h"

namespace agent {
namespace {

constexpr int64_t kMaxSnapshotAge = 2 * 86400;
constexpr size_t kMaxDeviations = 100;

// Security-sensitive items are normally identical across a fleet: a difference there is more than curiosity.
bool sensitiveFacet(const std::string& f) {
  return f == "user.account" || f == "user.privgroup" || f == "ssh.key" || f == "sudo.rule" || f == "kernel.module" || f == "cron.entry";
}

bool systemProgram(const std::string& exe) {
  for (const char* p : {"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/", "/usr/libexec/", "/lib64/"}) if (util::startsWith(exe, p)) return true;
  return false;
}

}  // namespace

std::set<std::string> PeerCollector::comparableItems(const Snapshot& s) {
  static const std::set<std::string> facets = {"process.exe", "net.listen", "user.account", "user.privgroup", "systemd.enabled", "kernel.module", "cron.entry", "ssh.key", "sudo.rule"};
  std::set<std::string> out;
  for (const auto& o : s.observations) {
    for (const auto& id : identitiesOf(o)) {
      if (!facets.count(id.facet)) continue;
      std::string key = id.key;
      if (id.facet == "user.account") key = key.substr(0, key.find('|'));                    // the uid and shell differ between machines without meaning anything
      if (id.facet == "process.exe" && (systemProgram(key) || util::endsWith(key, " (deleted)"))) continue;  // system tools come and go
      if (id.facet == "net.listen" && key.find(":eph|") != std::string::npos) continue;      // ephemeral ports are not a service
      out.insert(id.facet + "|" + key);
    }
  }
  return out;
}

Result<CollectOutput> PeerCollector::collect(ITransport&) {
  if (!opts_.store) return err("peer analysis needs the agent database");
  CollectOutput out;
  if (opts_.group.empty()) return out;
  const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  // what every member looks like now, from the snapshots already stored
  static const char* kCollectors[] = {"processes", "network", "users", "persistence", "system"};
  std::map<std::string, std::set<std::string>> items;  // target -> comparable items
  std::vector<std::string> usable;
  for (const auto& member : opts_.group_members) {
    std::set<std::string> all;
    size_t got = 0;
    for (const char* c : kCollectors) {
      auto snap = opts_.store->latest(member, c);
      if (!snap || !snap.value() || now - snap.value()->ts > kMaxSnapshotAge) continue;
      ++got;
      const auto part = comparableItems(*snap.value());
      all.insert(part.begin(), part.end());
    }
    if (got >= 3) {  // too little data would make everything look unique
      items[member] = std::move(all);
      usable.push_back(member);
    }
  }
  if (!items.count(opts_.target)) {
    out.warnings.push_back("peer analysis: this target has too little recent data yet");
    return out;
  }
  if (usable.size() < opts_.peer_min_group) {
    out.warnings.push_back("peer analysis waits for data from " + std::to_string(opts_.peer_min_group - usable.size()) + " more member(s) of group '" + opts_.group + "'");
    return out;
  }

  const auto& mine = items[opts_.target];
  const size_t peers = usable.size() - 1;
  std::map<std::string, size_t> count;  // item -> how many of the OTHER members have it
  for (const auto& m : usable) {
    if (m == opts_.target) continue;
    for (const auto& it : items[m]) ++count[it];
  }
  const double need = opts_.peer_min_share;
  struct Dev { std::string kind, item; size_t with; bool sensitive; };
  std::vector<Dev> devs;
  for (const auto& it : mine) {
    const size_t with = count.count(it) ? count[it] : 0;
    if (static_cast<double>(peers - with) / static_cast<double>(peers) >= need) devs.push_back({"unique", it, with, sensitiveFacet(it.substr(0, it.find('|')))});
  }
  for (const auto& [it, with] : count) {
    if (mine.count(it)) continue;
    if (static_cast<double>(with) / static_cast<double>(peers) >= need) devs.push_back({"missing", it, with, false});
  }
  std::stable_sort(devs.begin(), devs.end(), [](const Dev& a, const Dev& b) {
    if (a.kind != b.kind) return a.kind == "unique";
    return a.sensitive > b.sensitive;
  });
  if (devs.size() > kMaxDeviations) {
    out.warnings.push_back(std::to_string(devs.size() - kMaxDeviations) + " more difference(s) from the group not listed");
    devs.resize(kMaxDeviations);
  }
  for (const auto& d : devs) {
    const size_t bar = d.item.find('|');
    Observation o;
    o.type = "peer.deviation";
    o.key = "peer|" + d.kind + "|" + d.item;
    o.tags.push_back(d.kind == "unique" ? "peer_unique" : "peer_missing");
    if (d.sensitive) o.tags.push_back("sensitive");
    o.data = {{"group", opts_.group}, {"kind", d.kind}, {"facet", d.item.substr(0, bar)}, {"item", d.item.substr(bar + 1)}, {"peers", peers}, {"peers_with_it", d.with}};
    out.observations.push_back(std::move(o));
  }
  return out;
}

}  // namespace agent
