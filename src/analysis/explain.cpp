#include "analysis/explain.h"

#include <algorithm>
#include <set>

#include "core/util.h"

namespace agent {
namespace {

constexpr size_t kMaxPaths = 30;
constexpr int64_t kSkew = 300;

void gather(const nlohmann::json& j, std::set<std::string>& out, int depth) {
  if (out.size() >= kMaxPaths || depth > 6) return;
  if (j.is_string()) {
    std::string s = j.get<std::string>();
    if (util::endsWith(s, " (deleted)")) s.resize(s.size() - 10);
    if (s.size() > 1 && s.size() < 512 && s[0] == '/' && s.find('\n') == std::string::npos && !util::startsWith(s, "/memfd:") && !util::startsWith(s, "/proc/")) out.insert(s);
  } else if (j.is_array()) {
    for (const auto& e : j) gather(e, out, depth + 1);
  } else if (j.is_object()) {
    for (const auto& [k, v] : j.items()) {
      if (k == "explained_by") continue;  // our own earlier annotation
      gather(v, out, depth + 1);
    }
  }
}

}  // namespace

std::vector<std::string> evidencePaths(const nlohmann::json& evidence) {
  std::set<std::string> s;
  gather(evidence, s, 0);
  return {s.begin(), s.end()};
}

std::optional<Explanation> explainByUpdate(Store& store, const std::string& target, const nlohmann::json& evidence, int64_t first_seen,
                                           std::chrono::seconds window) {
  std::optional<Explanation> best;
  for (const auto& path : evidencePaths(evidence)) {
    auto owner = store.packageOwning(target, path);
    if (!owner || !owner.value() || owner.value()->changed_at <= 0) continue;
    const int64_t at = owner.value()->changed_at;
    if (first_seen + kSkew < at || first_seen - at > window.count()) continue;
    if (best && best->changed_at >= at) continue;
    if (auto tampered = store.integrityFlagged(target, path); !tampered || tampered.value()) continue;
    Explanation e;
    e.package = owner.value()->package;
    e.path = path;
    e.changed_at = at;
    e.kind = "upgraded";
    if (auto ev = store.lastPackageEvent(target, e.package); ev && ev.value()) {
      e.kind = ev.value()->kind;
      e.old_version = ev.value()->old_version;
      e.new_version = ev.value()->new_version;
    }
    best = std::move(e);
  }
  return best;
}

void applyExplanation(Finding& f, const Explanation& e) {
  if (std::find(f.tags.begin(), f.tags.end(), "explained_by_update") == f.tags.end()) f.tags.push_back("explained_by_update");
  if (!f.evidence.is_object()) f.evidence = nlohmann::json::object();
  f.evidence["explained_by"] = {{"package", e.package}, {"kind", e.kind}, {"old_version", e.old_version}, {"new_version", e.new_version}, {"changed_at", e.changed_at}, {"path", e.path}};
}

}  // namespace agent
