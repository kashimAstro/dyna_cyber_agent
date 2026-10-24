#include "analysis/incident.h"

#include <algorithm>
#include <functional>
#include <map>
#include <numeric>
#include <set>

#include "analysis/explain.h"
#include "collectors/log_parsers.h"
#include "core/util.h"
#include "report/mitre_names.h"

namespace agent {
namespace {

const std::set<std::string> kGenericUsers = {"root", "nobody", "daemon", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data",
                                            "backup", "list", "irc", "gnats", "systemd-network", "systemd-resolve", "messagebus", "sshd", "?", "unknown"};

bool genericUser(const std::string& u) { return u.empty() || u.size() > 64 || kGenericUsers.count(u) || u[0] == '_' || util::startsWith(u, "systemd-"); }

// Paths of the operating system itself appear in unrelated findings (every shell is /bin/bash).
bool systemPath(const std::string& p) {
  for (const char* pre : {"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/", "/lib64/", "/usr/libexec/", "/usr/share/", "/proc/", "/sys/", "/dev/null",
                          "/dev/tty", "/dev/pts", "/run/", "/var/lib/dpkg/", "/var/log/"}) {
    if (util::startsWith(p, pre)) return true;
  }
  return false;
}

void addIp(std::set<Entity>& out, const nlohmann::json& v) {
  if (!v.is_string()) return;
  const std::string ip = v.get<std::string>();
  if (!looksLikeIp(ip) || isPrivateIp(ip) || ip == "0.0.0.0" || ip == "::") return;
  out.insert({"ip", ip});
}

void addUser(std::set<Entity>& out, const nlohmann::json& v) {
  if (!v.is_string()) return;
  const std::string u = v.get<std::string>();
  if (!genericUser(u)) out.insert({"user", u});
}

}  // namespace

std::vector<Entity> entitiesOf(const Finding& f) {
  std::set<Entity> out;
  const auto& e = f.evidence;
  if (e.is_object()) {
    for (const char* k : {"src_ip", "remote_addr", "ip", "dest_ip"}) if (e.contains(k)) addIp(out, e[k]);
    for (const char* k : {"user", "success_user", "name", "from", "to", "target_user"}) if (e.contains(k)) addUser(out, e[k]);
    if (e.contains("owners") && e["owners"].is_array()) {
      for (const auto& o : e["owners"]) {
        if (o.is_object() && o.contains("exe") && o["exe"].is_string()) {
          const std::string p = o["exe"].get<std::string>();
          if (!systemPath(p)) out.insert({"path", p});
        }
      }
    }
  }
  for (const auto& p : evidencePaths(e)) {
    if (!systemPath(p)) out.insert({"path", p});
  }
  return {out.begin(), out.end()};
}

std::string stageOf(const Finding& f) {
  // Initial access techniques win: "login that worked after failures" is T1110 + T1078 and is the entry, not the guessing.
  for (const auto& m : f.mitre) {
    const std::string base = m.substr(0, m.find('.'));
    if (base == "T1078" || base == "T1190" || base == "T1133") return "initial-access";
  }
  for (const auto& m : f.mitre) {
    const std::string t = mitreTactic(m);
    if (!t.empty()) return t;
  }
  if (f.obs_type == "log.auth.bruteforce") return "credential-access";
  if (f.obs_type == "log.auth.scan" || f.obs_type == "log.web.scan") return "reconnaissance";
  if (util::startsWith(f.obs_type, "log.web")) return "initial-access";
  if (f.collector == "persistence" || f.collector == "files" || f.collector == "users") return "persistence";
  if (f.collector == "network") return "command-and-control";
  if (f.collector == "processes") return "execution";
  if (f.collector == "system") return "defense-evasion";
  return "other";
}

Severity incidentSeverity(const std::vector<Finding>& members, size_t stage_count) {
  Severity top = Severity::Info;
  for (const auto& f : members) top = std::max(top, f.severity);
  if (stage_count >= 3 && top >= Severity::Medium && top < Severity::Critical) top = static_cast<Severity>(static_cast<int>(top) + 1);
  return top;
}

std::string incidentTitle(const nlohmann::json& stages, const nlohmann::json& targets, const std::string& lang) {
  std::string t;
  for (const auto& s : stages) t += (t.empty() ? "" : " -> ") + tacticName(s.get<std::string>(), lang);
  std::string where;
  for (const auto& x : targets) where += (where.empty() ? "" : ", ") + x.get<std::string>();
  return t + (where.empty() ? "" : (lang == "en" ? " on " : " su ") + where);
}

Result<size_t> IncidentEngine::update(int64_t now) {
  auto open = store_.listFindings("open", 20000);
  if (!open) return err(open.error());
  std::vector<Finding> fs;
  for (auto& f : open.value()) {
    if (f.collector == "vulns" || std::find(f.tags.begin(), f.tags.end(), "explained_by_update") != f.tags.end()) continue;
    fs.push_back(std::move(f));
  }

  // union-find over findings that share an entity and appeared within the window of each other
  std::vector<size_t> parent(fs.size());
  std::iota(parent.begin(), parent.end(), size_t(0));
  std::function<size_t(size_t)> find = [&](size_t x) { return parent[x] == x ? x : parent[x] = find(parent[x]); };
  std::map<Entity, std::vector<size_t>> by_entity;
  for (size_t i = 0; i < fs.size(); ++i) for (const auto& e : entitiesOf(fs[i])) by_entity[e].push_back(i);
  for (auto& [e, idx] : by_entity) {
    if (idx.size() < 2) continue;
    std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return fs[a].first_seen < fs[b].first_seen; });
    for (size_t k = 1; k < idx.size(); ++k) {
      if (fs[idx[k]].first_seen - fs[idx[k - 1]].first_seen <= opts_.window.count()) parent[find(idx[k])] = find(idx[k - 1]);
    }
  }
  std::map<size_t, std::vector<size_t>> comps;
  for (size_t i = 0; i < fs.size(); ++i) comps[find(i)].push_back(i);

  auto existing = store_.listIncidents("open", 5000);
  if (!existing) return err(existing.error());
  std::map<int64_t, int64_t> incident_of;  // finding id -> incident id
  for (const auto& inc : existing.value()) for (int64_t f : inc.finding_ids) incident_of[f] = inc.id;

  std::set<int64_t> kept;
  size_t open_count = 0;
  for (auto& [root, idx] : comps) {
    if (idx.size() < opts_.min_findings) continue;
    std::set<std::string> rules;
    for (size_t i : idx) rules.insert(fs[i].rule_id);
    if (rules.size() < 2) continue;  // the same rule firing repeatedly is one problem, not a chain

    std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return std::tie(fs[a].first_seen, fs[a].id) < std::tie(fs[b].first_seen, fs[b].id); });
    std::vector<Finding> members;
    std::vector<std::string> stage_order;
    std::set<std::string> targets;
    std::map<Entity, size_t> shared;
    int64_t first = INT64_MAX, last = 0;
    std::set<int64_t> old_ids;
    for (size_t i : idx) {
      const Finding& f = fs[i];
      members.push_back(f);
      const std::string st = stageOf(f);
      if (std::find(stage_order.begin(), stage_order.end(), st) == stage_order.end()) stage_order.push_back(st);
      targets.insert(f.target);
      first = std::min(first, f.first_seen);
      last = std::max(last, f.last_seen);
      for (const auto& e : entitiesOf(f)) ++shared[e];
      if (auto it = incident_of.find(f.id); it != incident_of.end()) old_ids.insert(it->second);
    }
    Store::IncidentRow row;
    row.id = old_ids.empty() ? 0 : *old_ids.begin();  // two incidents joined by a new finding: the older one survives
    if (row.id != 0) {
      for (const auto& inc : existing.value()) if (inc.id == row.id) row.created_at = inc.created_at;
    }
    if (row.created_at == 0) row.created_at = now;
    row.updated_at = now;
    row.first_ts = first;
    row.last_ts = last;
    row.status = "open";
    for (const auto& s : stage_order) row.stages.push_back(s);
    for (const auto& t : targets) row.targets.push_back(t);
    std::vector<std::pair<Entity, size_t>> ents(shared.begin(), shared.end());
    std::stable_sort(ents.begin(), ents.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    for (const auto& [e, n] : ents) if (n >= 2 && row.entities.size() < 6) row.entities.push_back({{"kind", e.kind}, {"value", e.value}, {"findings", n}});
    row.severity = incidentSeverity(members, stage_order.size());
    row.title = incidentTitle(row.stages, row.targets, "en");
    for (const auto& f : members) row.finding_ids.push_back(f.id);
    std::sort(row.finding_ids.begin(), row.finding_ids.end());

    auto saved = store_.saveIncident(row);
    if (!saved) return err(saved.error());
    kept.insert(saved.value());
    for (int64_t o : old_ids) {
      if (o != saved.value()) {
        if (auto d = store_.deleteIncident(o); !d) return err(d.error());
      }
    }
    ++open_count;
  }

  // incidents that no longer hold together (a member was resolved, accepted or aged out) are closed, not deleted
  for (const auto& inc : existing.value()) {
    if (kept.count(inc.id)) continue;
    auto still = store_.getIncident(inc.id);
    if (!still || !still.value()) continue;
    Store::IncidentRow row = *still.value();
    row.status = "resolved";
    row.updated_at = now;
    if (auto s = store_.saveIncident(row); !s) return err(s.error());
  }
  return open_count;
}

}  // namespace agent
