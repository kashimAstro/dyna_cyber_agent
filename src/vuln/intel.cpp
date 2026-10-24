#include "vuln/intel.h"

#include <algorithm>
#include <map>

#include "report/text_util.h"
#include "vuln/cwe_names.h"

namespace agent {

std::function<std::string(const std::string&)> makeCweNameProvider(VulnDb& db) {
  return [&db](const std::string& id) {
    auto c = db.getCwe(id);
    return c && c.value() ? c.value()->name : std::string();
  };
}

std::function<std::vector<std::string>(int64_t, int64_t)> makeIntelProvider(VulnDb& db, Store& store, const std::string& lang) {
  const bool en = lang == "en";
  return [&db, &store, en](int64_t from, int64_t to) {
    (void)to;
    std::vector<std::string> out;
    auto when = [&](const char* key) {
      auto m = db.getMeta(key);
      return m && m.value() && !m.value()->empty() ? report::fmtTime(std::stoll(*m.value())) : std::string(en ? "never" : "mai");
    };
    if (auto st = db.stats()) {
      out.push_back(std::string(en ? "CVE database: " : "Database CVE: ") + std::to_string(st.value().cves) + (en ? " records, " : " voci, ") + std::to_string(st.value().kev) +
                    (en ? " actively exploited (CISA KEV), " : " sfruttate attivamente (CISA KEV), ") + std::to_string(st.value().cwes) + (en ? " weakness descriptions (CWE). " : " descrizioni di debolezze (CWE). ") +
                    (en ? "Updated: NVD " : "Aggiornato: NVD ") + when("nvd_last_sync") + ", KEV " + when("kev_last_sync") + ", CWE " + when("cwe_last_sync"));
    }

    // what the monitored systems have
    std::vector<Finding> mine;
    if (auto all = store.listFindings("", 100000)) {
      for (auto& f : all.value()) if (f.collector == "vulns") mine.push_back(std::move(f));
    }
    auto has = [](const Finding& f, const char* tag) { return std::find(f.tags.begin(), f.tags.end(), tag) != f.tags.end(); };

    if (auto added = db.kevAddedSince(from); added && !added.value().empty()) {
      std::string ids;
      for (size_t i = 0; i < added.value().size() && i < 8; ++i) ids += (i ? ", " : "") + added.value()[i];
      if (added.value().size() > 8) ids += ", ...";
      out.push_back(std::string(en ? "Newly exploited vulnerabilities in the CISA KEV catalog during the period: " : "Nuove vulnerabilita' sfruttate attivamente (CISA KEV) nel periodo: ") +
                    std::to_string(added.value().size()) + " (" + ids + ")");
    }
    size_t kev_open = 0;
    for (const auto& f : mine) kev_open += f.status == "open" && has(f, "kev");
    if (kev_open) {
      out.push_back(std::string(en ? "Actively exploited vulnerabilities currently present on your systems: " : "Vulnerabilita' sfruttate attivamente attualmente presenti sui tuoi sistemi: ") + std::to_string(kev_open));
    }

    size_t fresh = 0, fresh_crit = 0;
    std::map<std::string, size_t> cwe_count;
    for (const auto& f : mine) {
      if (f.first_seen < from) continue;
      ++fresh;
      if (f.severity >= Severity::High) ++fresh_crit;
      for (const auto& c : f.cwe) ++cwe_count[c];
    }
    if (fresh) {
      out.push_back(std::string(en ? "New vulnerabilities found on your systems in the period: " : "Nuove vulnerabilita' trovate sui tuoi sistemi nel periodo: ") + std::to_string(fresh) +
                    (en ? " (of which high or critical: " : " (di cui alte o critiche: ") + std::to_string(fresh_crit) + ")");
    }
    if (!cwe_count.empty()) {
      std::vector<std::pair<std::string, size_t>> top(cwe_count.begin(), cwe_count.end());
      std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) { return a.second != b.second ? a.second > b.second : a.first < b.first; });
      std::string line = en ? "Most frequent weakness classes among them: " : "Classi di debolezza (CWE) piu' frequenti tra queste: ";
      for (size_t i = 0; i < top.size() && i < 5; ++i) {
        std::string name;
        if (auto c = db.getCwe(top[i].first); c && c.value()) name = c.value()->name;
        if (name.empty()) name = builtinCweName(top[i].first);
        line += (i ? "; " : "") + top[i].first + (name.empty() ? "" : " " + name) + " (" + std::to_string(top[i].second) + ")";
      }
      out.push_back(line);
    }
    return out;
  };
}

}  // namespace agent
