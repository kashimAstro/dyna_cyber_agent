#include "report/view.h"

#include <map>

#include "report/text_util.h"

namespace agent::report {

std::vector<VulnPackage> groupVulns(const Report& r) {
  std::vector<VulnPackage> out;
  std::map<std::string, size_t> index;
  for (const auto& it : r.vuln_items) {
    const std::string pkg = it.finding.evidence.value("package", std::string("?"));
    const std::string inst = it.finding.evidence.value("installed_version", std::string());
    const std::string key = it.finding.target + "|" + pkg + "|" + inst;
    auto [pos, added] = index.emplace(key, out.size());
    if (added) out.push_back({sanitize(it.finding.target, 80), sanitize(pkg, 80), sanitize(inst, 60), {}});
    out[pos->second].cves.push_back(&it);
  }
  return out;
}

CveView cveView(const ReportItem& it, const Report&) {
  const Finding& f = it.finding;
  CveView v;
  v.cve = sanitize(f.evidence.value("cve", std::string("?")), 30);
  v.fixed = sanitize(f.evidence.value("fixed_version", std::string()), 60);
  v.published = sanitize(f.evidence.value("published", std::string()), 12);
  if (f.evidence.contains("cvss") && f.evidence["cvss"].is_number()) v.cvss = f.evidence["cvss"].get<double>();
  if (f.evidence.contains("epss") && f.evidence["epss"].is_number()) v.epss = f.evidence["epss"].get<double>();
  if (f.evidence.contains("priority") && f.evidence["priority"].is_number()) v.priority = f.evidence["priority"].get<int>();
  v.exposure = sanitize(f.evidence.value("exposure", std::string("unknown")), 20);
  if (f.evidence.contains("ports") && f.evidence["ports"].is_array()) {
    for (const auto& p : f.evidence["ports"]) if (p.is_string() && v.ports.size() < 120) v.ports += (v.ports.empty() ? "" : ", ") + sanitize(p.get<std::string>(), 40);
  }
  v.reboot_pending = hasTag(f, "reboot_pending");
  v.kev = hasTag(f, "kev");
  v.recent = hasTag(f, "recent");
  v.ransomware = hasTag(f, "ransomware");
  v.low_confidence = hasTag(f, "upstream_version_match");
  for (const auto& id : f.cwe) {
    v.cwe_text += (v.cwe_text.empty() ? "" : ", ") + sanitize(id, 16);  // names are listed once, in the references
  }
  return v;
}

}  // namespace agent::report
