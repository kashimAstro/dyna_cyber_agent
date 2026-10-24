#pragma once
#include <array>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "analysis/finding.h"
#include "llm/analysis.h"
#include "llm/synthesis.h"
#include "store/store.h"

namespace agent {

struct ReportItem {
  Finding finding;
  std::optional<Assessment> assessment;
  Severity effective = Severity::Info;  // max(rule severity, LLM risk): the model can raise a finding, never lower it
  bool is_new = false;                  // first seen inside the report period
  int64_t incident_id = 0;              // the incident this finding belongs to (0 = none)
};

// Findings chained into one story (see analysis/incident.h); the timeline holds every member, oldest first.
struct IncidentView {
  Store::IncidentRow row;
  std::string title;                // in the language of the report
  std::vector<ReportItem> timeline;
};

struct HealthRow {
  std::string target, collector;
  int64_t last_ok = 0, last_error_ts = 0;
  std::string last_error;
  int64_t ok_count = 0, error_count = 0;
  bool stale = false;  // no successful collection for much longer than its interval
};

struct Report {
  enum class Kind { Alert, Digest, Test };
  Kind kind = Kind::Alert;
  std::string lang = "it";
  std::string host_label;      // machine running the agent
  std::string subject_prefix;
  int64_t generated_at = 0, period_from = 0, period_to = 0;
  Severity top = Severity::Info;
  std::vector<IncidentView> incidents;  // chains of related findings, most severe first; their minor members live in the timeline only
  std::vector<ReportItem> items;       // security findings, most severe first (vulnerabilities are kept apart)
  size_t omitted_items = 0;            // matching but not shown (mail size cap)
  size_t in_incident_timelines = 0;    // findings that appear only as a timeline line of an incident (not as a full card)
  std::vector<ReportItem> carry_over;  // digest: open security findings already reported before this period (compact)
  size_t omitted_carry = 0;
  std::vector<ReportItem> vuln_items;  // vulnerabilities (collector "vulns"), KEV first, then by score
  size_t omitted_vulns = 0;
  struct VulnPosture {
    size_t total = 0, kev = 0, with_fix = 0, packages = 0, new_in_period = 0;
    std::array<size_t, 5> by_severity{};  // by CVSS band: 0 unscored/info .. 4 critical
  } vuln_posture;                          // all open vulnerabilities, not just the listed ones
  std::vector<std::pair<std::string, size_t>> mitre_refs, cwe_refs;  // technique / weakness -> number of findings, most frequent first
  std::optional<Synthesis> synthesis;  // the single AI report of this mail; absent when the model is off or unreachable
  size_t open_total = 0, new_in_period = 0, resolved_in_period = 0;
  std::array<size_t, 5> open_by_severity{};
  std::vector<HealthRow> health;
  std::vector<std::string> intel_lines;               // vulnerability intelligence (digest): feeds, new KEV entries, weakness trends
  std::map<std::string, std::string> cwe_names;       // "CWE-79" -> name, for the CWE ids of the featured findings
  bool llm_enabled = false;
};

struct ReportContext {
  std::string host_label;
  std::string subject_prefix = "[dyna_cyber_agent]";
  std::string lang = "it";
  bool llm_enabled = false;
  size_t max_items = 30;
  size_t max_vuln_items = 60;
  size_t max_carry_over = 40;
  std::map<std::string, int64_t> intervals;  // "target|collector" -> expected seconds between snapshots
  std::function<std::string(const std::string&)> cwe_name;                // optional: richer than the built-in table (downloaded catalog)
  std::function<std::vector<std::string>(int64_t, int64_t)> intel;        // optional: lines for the digest's intelligence section
};

// Findings of the "vulns" collector, shown in their own section.
inline bool isVulnFinding(const Finding& f) { return f.collector == "vulns"; }
inline bool hasTag(const Finding& f, const char* tag) {
  for (const auto& t : f.tags) if (t == tag) return true;
  return false;
}

// max(rule severity, LLM risk): the model can raise a finding, never lower it. Vulnerabilities keep the rule's
// severity: the model has nothing to add to a CVE score and used to promote old CVEs into alerts.
Severity effectiveSeverity(const Finding& f, const std::optional<Assessment>& a);

// Alert: exactly the given findings. Digest: open findings >= min_severity plus period statistics.
Result<Report> buildAlertReport(Store& store, const std::vector<Finding>& findings, const ReportContext& ctx, int64_t now);
Result<Report> buildDigestReport(Store& store, int64_t from, int64_t to, Severity min_severity, const ReportContext& ctx);
Report buildTestReport(const ReportContext& ctx, int64_t now);

std::string reportSubject(const Report& r);
std::string renderText(const Report& r);
std::string renderHtml(const Report& r);

}  // namespace agent
