#include "vuln/feed_parsers.h"

#include <algorithm>
#include <ctime>
#include <nlohmann/json.hpp>
#include <set>

#include "core/util.h"
#include "vuln/cvss.h"
#include "vuln/version.h"

namespace agent {
namespace {

using nlohmann::json;

std::string str(const json& j, const char* k) {
  const auto it = j.find(k);
  return it != j.end() && it->is_string() ? it->get<std::string>() : std::string();
}

bool isCweId(const std::string& s) {
  if (!util::startsWith(s, "CWE-") || s.size() < 5) return false;
  return util::allDigits(s.substr(4));
}

}  // namespace

int64_t parseIsoTime(const std::string& s) {
  int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
  if (s.size() < 10 || std::sscanf(s.c_str(), "%4d-%2d-%2d", &y, &mo, &d) != 3) return 0;
  if (s.size() >= 19 && (s[10] == 'T' || s[10] == ' ')) std::sscanf(s.c_str() + 11, "%2d:%2d:%2d", &h, &mi, &se);
  std::tm tm{};
  tm.tm_year = y - 1900;
  tm.tm_mon = mo - 1;
  tm.tm_mday = d;
  tm.tm_hour = h;
  tm.tm_min = mi;
  tm.tm_sec = se;
  return static_cast<int64_t>(timegm(&tm));
}

std::string formatNvdTime(int64_t epoch) {
  const std::time_t t = static_cast<std::time_t>(epoch);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char b[40];
  std::strftime(b, sizeof(b), "%Y-%m-%dT%H:%M:%S.000", &tm);
  return b;
}

std::optional<CpeName> parseCpe23(const std::string& c) {
  if (!util::startsWith(c, "cpe:2.3:")) return std::nullopt;
  std::vector<std::string> f;
  std::string cur;
  for (size_t i = 8; i < c.size(); ++i) {
    if (c[i] == '\\' && i + 1 < c.size()) {
      cur += c[++i];
    } else if (c[i] == ':') {
      f.push_back(cur);
      cur.clear();
    } else {
      cur += c[i];
    }
  }
  f.push_back(cur);
  if (f.size() < 4) return std::nullopt;
  return CpeName{f[0], f[1], f[2], f[3]};
}

Result<std::vector<KevEntry>> parseKev(const std::string& text) {
  const json j = json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object() || !j.contains("vulnerabilities") || !j["vulnerabilities"].is_array()) return err("not a KEV catalog");
  std::vector<KevEntry> out;
  for (const auto& e : j["vulnerabilities"]) {
    if (!e.is_object()) continue;
    KevEntry k;
    k.cve = str(e, "cveID");
    if (!util::startsWith(k.cve, "CVE-")) continue;
    k.vendor = str(e, "vendorProject");
    k.product = str(e, "product");
    k.name = str(e, "vulnerabilityName");
    k.description = str(e, "shortDescription");
    k.action = str(e, "requiredAction");
    k.added = parseIsoTime(str(e, "dateAdded"));
    k.due = parseIsoTime(str(e, "dueDate"));
    k.ransomware = str(e, "knownRansomwareCampaignUse") == "Known";
    if (e.contains("cwes") && e["cwes"].is_array()) for (const auto& c : e["cwes"]) if (c.is_string() && isCweId(c.get<std::string>())) k.cwes.push_back(c.get<std::string>());
    out.push_back(std::move(k));
  }
  return out;
}

Result<NvdPage> parseNvdPage(const std::string& text) {
  const json j = json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object() || !j.contains("vulnerabilities") || !j["vulnerabilities"].is_array()) return err("not an NVD CVE 2.0 response");
  NvdPage page;
  page.total = j.value("totalResults", static_cast<int64_t>(0));
  page.start_index = j.value("startIndex", static_cast<int64_t>(0));
  page.per_page = j.value("resultsPerPage", static_cast<int64_t>(0));
  for (const auto& v : j["vulnerabilities"]) {
    if (!v.is_object() || !v.contains("cve") || !v["cve"].is_object()) continue;
    const json& c = v["cve"];
    CveRecord r;
    r.id = str(c, "id");
    if (!util::startsWith(r.id, "CVE-")) continue;
    r.status = str(c, "vulnStatus");
    r.published = parseIsoTime(str(c, "published"));
    r.modified = parseIsoTime(str(c, "lastModified"));
    if (c.contains("descriptions") && c["descriptions"].is_array()) {
      for (const auto& d : c["descriptions"]) {
        if (str(d, "lang") == "en") {
          r.summary = str(d, "value");
          break;
        }
      }
    }
    // Scores: prefer CVSS 3.1, then 3.0, then 4.0, then 2.0; inside a version the NVD ("Primary") entry first.
    if (c.contains("metrics") && c["metrics"].is_object()) {
      for (const char* key : {"cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"}) {
        const auto it = c["metrics"].find(key);
        if (it == c["metrics"].end() || !it->is_array() || it->empty()) continue;
        const json* best = &(*it)[0];
        for (const auto& m : *it) if (str(m, "type") == "Primary") { best = &m; break; }
        if (!best->contains("cvssData")) continue;
        const json& d = (*best)["cvssData"];
        if (d.contains("baseScore") && d["baseScore"].is_number()) {
          r.cvss = d["baseScore"].get<double>();
          r.vector = str(d, "vectorString");
          r.severity = cvssSeverity(*r.cvss);
          break;
        }
      }
    }
    std::set<std::string> cwes;
    if (c.contains("weaknesses") && c["weaknesses"].is_array()) {
      for (const auto& w : c["weaknesses"]) {
        if (!w.contains("description") || !w["description"].is_array()) continue;
        for (const auto& d : w["description"]) if (isCweId(str(d, "value"))) cwes.insert(str(d, "value"));
      }
    }
    r.cwes.assign(cwes.begin(), cwes.end());
    if (c.contains("configurations") && c["configurations"].is_array()) {
      for (const auto& cfg : c["configurations"]) {
        if (!cfg.contains("nodes") || !cfg["nodes"].is_array()) continue;
        for (const auto& node : cfg["nodes"]) {
          if (!node.contains("cpeMatch") || !node["cpeMatch"].is_array()) continue;
          for (const auto& m : node["cpeMatch"]) {
            if (!m.value("vulnerable", false)) continue;
            const auto cpe = parseCpe23(str(m, "criteria"));
            if (!cpe || (cpe->part != "a" && cpe->part != "o")) continue;
            CpeMatch cm;
            cm.vendor = cpe->vendor;
            cm.product = cpe->product;
            cm.version = cpe->version;
            cm.start_incl = str(m, "versionStartIncluding");
            cm.start_excl = str(m, "versionStartExcluding");
            cm.end_incl = str(m, "versionEndIncluding");
            cm.end_excl = str(m, "versionEndExcluding");
            r.cpes.push_back(std::move(cm));
          }
        }
      }
    }
    page.cves.push_back(std::move(r));
  }
  return page;
}

Result<std::vector<CweRecord>> parseCweResponse(const std::string& text) {
  const json j = json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object() || !j.contains("Weaknesses") || !j["Weaknesses"].is_array()) return err("not a CWE API response");
  std::vector<CweRecord> out;
  for (const auto& w : j["Weaknesses"]) {
    if (!w.is_object()) continue;
    std::string id = w.contains("ID") ? (w["ID"].is_string() ? w["ID"].get<std::string>() : w["ID"].dump()) : "";
    if (id.empty() || !util::allDigits(id)) continue;
    CweRecord r;
    r.id = "CWE-" + id;
    r.name = str(w, "Name");
    r.description = str(w, "Description");
    r.status = str(w, "Status");
    r.likelihood = str(w, "LikelihoodOfExploit");
    out.push_back(std::move(r));
  }
  return out;
}

Result<std::vector<OsvBatchResult>> parseOsvBatch(const std::string& text) {
  const json j = json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object() || !j.contains("results") || !j["results"].is_array()) return err("not an OSV querybatch response");
  std::vector<OsvBatchResult> out;
  for (const auto& r : j["results"]) {
    OsvBatchResult b;
    if (r.is_object()) {
      if (r.contains("vulns") && r["vulns"].is_array()) for (const auto& v : r["vulns"]) if (!str(v, "id").empty()) b.vulns.emplace_back(str(v, "id"), str(v, "modified"));
      b.next_page_token = str(r, "next_page_token");
    }
    out.push_back(std::move(b));
  }
  return out;
}

Result<OsvVuln> parseOsvVuln(const std::string& text, const std::string& eco_prefix) {
  const json j = json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object() || str(j, "id").empty()) return err("not an OSV vulnerability record");
  OsvVuln v;
  v.id = str(j, "id");
  v.modified = str(j, "modified");
  v.published = parseIsoTime(str(j, "published"));
  v.withdrawn = j.contains("withdrawn");
  v.summary = str(j, "summary");
  if (v.summary.empty()) v.summary = str(j, "details").substr(0, 300);
  if (j.contains("aliases") && j["aliases"].is_array()) for (const auto& a : j["aliases"]) if (a.is_string()) v.aliases.push_back(a.get<std::string>());
  auto take_severity = [&](const json& arr) {
    if (!arr.is_array()) return;
    for (const auto& s : arr) {
      const std::string type = str(s, "type"), score = str(s, "score");
      if (type == "CVSS_V3" && v.cvss_vector.empty()) v.cvss_vector = score;
      else if (type == "Ubuntu" && v.severity_text.empty()) v.severity_text = score;
    }
  };
  if (j.contains("severity")) take_severity(j["severity"]);
  if (j.contains("affected") && j["affected"].is_array()) {
    for (const auto& a : j["affected"]) {
      if (!a.contains("package") || !a["package"].is_object()) continue;
      const std::string eco = str(a["package"], "ecosystem"), name = str(a["package"], "name");
      if (name.empty() || !util::startsWith(eco, eco_prefix)) continue;
      if (a.contains("severity")) take_severity(a["severity"]);
      std::string fixed;
      if (a.contains("ranges") && a["ranges"].is_array()) {
        for (const auto& r : a["ranges"]) {
          if (!r.contains("events") || !r["events"].is_array()) continue;
          for (const auto& e : r["events"]) {
            const std::string f = str(e, "fixed");
            if (!f.empty() && (fixed.empty() || compareDebVersion(f, fixed) > 0)) fixed = f;  // the last fix that closes it
          }
        }
      }
      auto it = v.fixed.find(name);
      if (it == v.fixed.end() || (!fixed.empty() && (it->second.empty() || compareDebVersion(fixed, it->second) > 0))) v.fixed[name] = fixed;
    }
  }
  return v;
}

Result<EpssFile> parseEpssCsv(const std::string& csv) {
  EpssFile f;
  bool header = false;
  size_t pos = 0;
  while (pos < csv.size()) {
    size_t nl = csv.find('\n', pos);
    if (nl == std::string::npos) nl = csv.size();
    std::string line = csv.substr(pos, nl - pos);
    pos = nl + 1;
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    if (line.empty()) continue;
    if (line[0] == '#') {
      const size_t d = line.find("score_date:");
      if (d != std::string::npos) f.score_date = line.substr(d + 11, 10);
      continue;
    }
    if (!header) {
      if (line.rfind("cve,", 0) != 0) return err("not an EPSS file (unexpected header)");
      header = true;
      continue;
    }
    const size_t c1 = line.find(','), c2 = c1 == std::string::npos ? c1 : line.find(',', c1 + 1);
    if (c1 == std::string::npos || c2 == std::string::npos) continue;
    EpssRow r;
    r.cve = line.substr(0, c1);
    if (r.cve.rfind("CVE-", 0) != 0) continue;
    try {
      r.score = std::stod(line.substr(c1 + 1, c2 - c1 - 1));
      r.percentile = std::stod(line.substr(c2 + 1));
    } catch (...) {
      continue;
    }
    f.rows.push_back(std::move(r));
  }
  if (!header) return err("not an EPSS file (no header)");
  if (f.rows.empty()) return err("the EPSS file has no scores");
  return f;
}

}  // namespace agent
