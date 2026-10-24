#pragma once
#include <string>
#include <vector>

#include "report/report.h"

namespace agent::report {

// The vulnerability section groups CVEs by target and package, in the order of the (already sorted) items.
struct VulnPackage {
  std::string target, package, installed;
  std::vector<const ReportItem*> cves;
};
std::vector<VulnPackage> groupVulns(const Report& r);

// Short, sanitised facts about one CVE finding.
struct CveView {
  std::string cve, fixed, published, cwe_text;
  double cvss = -1, epss = -1;
  int priority = -1;
  std::string exposure, ports;  // listening | listening_local | running | unknown
  bool reboot_pending = false;
  bool kev = false, recent = false, low_confidence = false, ransomware = false;
};
CveView cveView(const ReportItem& it, const Report& r);

inline bool en(const Report& r) { return r.lang == "en"; }

}  // namespace agent::report
