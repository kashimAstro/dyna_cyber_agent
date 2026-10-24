#pragma once
#include <string>
#include <utility>
#include <vector>

#include "core/result.h"
#include "vuln/vuln_types.h"

namespace agent {

// Epoch seconds (UTC) from "2021-12-10T10:15:09.143", "2023-01-01T00:00:00Z", "2023-01-01"; 0 on failure.
int64_t parseIsoTime(const std::string& s);
std::string formatNvdTime(int64_t epoch);  // "2026-10-22T20:04:33.000" (what the NVD API takes)

// CISA Known Exploited Vulnerabilities catalog.
Result<std::vector<KevEntry>> parseKev(const std::string& json);

// NVD CVE API 2.0 page.
struct NvdPage {
  int64_t total = 0, start_index = 0, per_page = 0;
  std::vector<CveRecord> cves;
};
Result<NvdPage> parseNvdPage(const std::string& json);

// MITRE CWE REST API: {"Weaknesses":[{"ID":"79","Name":...}]}
Result<std::vector<CweRecord>> parseCweResponse(const std::string& json);

// EPSS daily file: "#model_version:...,score_date:2026-10-23T12:00:28Z" then "cve,epss,percentile" rows.
struct EpssFile {
  std::string score_date;  // "2026-10-23"
  std::vector<EpssRow> rows;
};
Result<EpssFile> parseEpssCsv(const std::string& csv);

// OSV
struct OsvBatchResult {
  std::vector<std::pair<std::string, std::string>> vulns;  // (id, modified)
  std::string next_page_token;
};
Result<std::vector<OsvBatchResult>> parseOsvBatch(const std::string& json);
// `ecosystem_prefix`: only `affected` entries of this ecosystem family count ("Debian", "Ubuntu"...).
Result<OsvVuln> parseOsvVuln(const std::string& json, const std::string& ecosystem_prefix);

// "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" -> (part, vendor, product, version); handles "\:" escapes.
struct CpeName {
  std::string part, vendor, product, version;
};
std::optional<CpeName> parseCpe23(const std::string& criteria);

}  // namespace agent
