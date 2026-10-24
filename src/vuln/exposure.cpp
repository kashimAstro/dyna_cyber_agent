#include "vuln/exposure.h"

#include <algorithm>

#include "core/util.h"

namespace agent {
namespace {

bool loopback(const std::string& a) { return a == "::1" || util::startsWith(a, "127."); }

bool hasTag(const std::vector<std::string>& t, const char* x) { return std::find(t.begin(), t.end(), x) != t.end(); }

std::string stripDeleted(std::string s) {
  if (util::endsWith(s, " (deleted)")) s.resize(s.size() - 10);
  return s;
}

}  // namespace

Exposure computeExposure(Store& store, const std::string& target) {
  Exposure ex;
  if (auto n = store.packageFileCount(target); n && n.value() > 0) ex.ownership_known = true;
  if (!ex.ownership_known) return ex;
  std::map<std::string, std::string> owner_cache;  // exe path -> package ("" = unowned)
  auto ownerOf = [&](const std::string& exe) -> std::string {
    auto it = owner_cache.find(exe);
    if (it != owner_cache.end()) return it->second;
    std::string pkg;
    if (auto o = store.packageOwning(target, exe); o && o.value()) pkg = o.value()->package;
    owner_cache[exe] = pkg;
    return pkg;
  };

  if (auto net = store.latest(target, "network"); net && net.value()) {
    for (const auto& o : net.value()->observations) {
      if (o.type != "socket.inet" || !hasTag(o.tags, "listening")) continue;
      const std::string addr = o.data.value("local_addr", std::string());
      const std::string label = o.data.value("proto", std::string()) + "/" + addr + ":" + std::to_string(o.data.value("local_port", 0));
      if (!o.data.contains("owners") || !o.data["owners"].is_array()) continue;
      for (const auto& ow : o.data["owners"]) {
        if (!ow.is_object() || !ow.contains("exe") || !ow["exe"].is_string()) continue;
        const std::string pkg = ownerOf(stripDeleted(ow["exe"].get<std::string>()));
        if (pkg.empty()) continue;
        auto& dst = loopback(addr) ? ex.listening_local[pkg] : ex.listening_external[pkg];
        if (dst.size() < 8 && std::find(dst.begin(), dst.end(), label) == dst.end()) dst.push_back(label);
      }
    }
  }
  if (auto procs = store.latest(target, "processes"); procs && procs.value()) {
    for (const auto& o : procs.value()->observations) {
      if (o.type != "process" || o.data.value("kernel_thread", false) || !o.data.contains("exe") || !o.data["exe"].is_string()) continue;
      const std::string pkg = ownerOf(stripDeleted(o.data["exe"].get<std::string>()));
      if (!pkg.empty()) ex.running.insert(pkg);
    }
  }
  if (auto pk = store.latest(target, "packages"); pk && pk.value()) {
    for (const auto& o : pk.value()->observations) if (o.type == "os.reboot_required" && o.data.value("required", false)) ex.reboot_pending = true;
  }
  return ex;
}

int vulnPriority(const nlohmann::json& d, const std::vector<std::string>& tags) {
  double s = 0;
  const bool scored = d.contains("cvss") && d["cvss"].is_number();
  s += scored ? d["cvss"].get<double>() * 5.0 : 25.0;  // an unscored CVE is neither harmless nor critical
  if (hasTag(tags, "kev")) s += 25;
  const double epss = d.contains("epss") && d["epss"].is_number() ? d["epss"].get<double>() : 0.0;
  s += epss >= 0.5 ? 15 : epss >= 0.1 ? 10 : epss >= 0.01 ? 4 : 0;
  if (hasTag(tags, "listening")) s += 15;
  else if (hasTag(tags, "listening_local")) s += 8;
  else if (hasTag(tags, "running")) s += 5;
  if (hasTag(tags, "recent")) s += 3;
  if (hasTag(tags, "upstream_version_match")) s -= 10;  // might be a false positive (backported fix)
  return static_cast<int>(std::clamp(s, 0.0, 100.0) + 0.5);
}

void annotateMatches(std::vector<Observation>& observations, const Exposure& ex) {
  for (auto& o : observations) {
    if (o.type != "vuln.match") continue;
    std::vector<std::string> names;
    if (o.data.contains("package") && o.data["package"].is_string()) names.push_back(o.data["package"].get<std::string>());
    if (o.data.contains("binaries") && o.data["binaries"].is_array()) for (const auto& b : o.data["binaries"]) if (b.is_string()) names.push_back(b.get<std::string>());

    std::string exposure = "unknown";
    std::vector<std::string> ports;
    if (ex.ownership_known) {
      for (const auto& n : names) {
        if (auto it = ex.listening_external.find(n); it != ex.listening_external.end()) { exposure = "listening"; ports = it->second; break; }
      }
      if (exposure == "unknown") {
        for (const auto& n : names) {
          if (auto it = ex.listening_local.find(n); it != ex.listening_local.end()) { exposure = "listening_local"; ports = it->second; break; }
        }
      }
      if (exposure == "unknown" && std::any_of(names.begin(), names.end(), [&](const std::string& n) { return ex.running.count(n) > 0; })) exposure = "running";
    }
    o.data["exposure"] = exposure;
    if (!ports.empty()) o.data["ports"] = ports;
    if (exposure != "unknown") o.tags.push_back(exposure);
    if (ex.reboot_pending && hasTag(o.tags, "kernel")) o.tags.push_back("reboot_pending");
    o.data["exposed_likely_exploited"] = exposure == "listening" && hasTag(o.tags, "epss_high");
    o.data["priority"] = vulnPriority(o.data, o.tags);
  }
}

}  // namespace agent
