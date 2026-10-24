#include "app/synthesis.h"

#include <spdlog/spdlog.h>

#include <chrono>

#include "report/text_util.h"

namespace agent {
namespace {

constexpr int64_t kLookback = 7 * 86400;  // mails older than this are not "what the administrator just read"
constexpr size_t kPreviousMails = 3;
constexpr size_t kTopVulns = 12;

int64_t nowTs() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

SynthesisItem toItem(const ReportItem& it) {
  SynthesisItem s;
  s.finding = it.finding;
  s.assessment = it.assessment;
  s.effective = it.effective;
  s.is_new = it.is_new;
  return s;
}

}  // namespace

SynthesisInput makeSynthesisInput(const Report& r, const std::vector<std::string>& previous) {
  SynthesisInput in;
  in.kind = r.kind == Report::Kind::Digest ? "digest" : "alert";
  in.host = r.host_label;
  for (const auto& it : r.items) in.items.push_back(toItem(it));
  for (const auto& inc : r.incidents) {
    if (in.incidents.size() >= 6) break;  // the prompt has a budget: the worst incidents come first
    nlohmann::json tl = nlohmann::json::array();
    for (const auto& it : inc.timeline) {
      if (tl.size() >= 12) break;
      tl.push_back({{"finding_id", it.finding.id}, {"time", report::fmtTime(it.finding.first_seen)}, {"rule", it.finding.rule_id}, {"title", it.finding.title},
                    {"severity", toString(it.effective)}, {"target", it.finding.target}});
    }
    in.incidents.push_back({{"incident_id", inc.row.id}, {"title", inc.title}, {"severity", toString(inc.row.severity)}, {"stages", inc.row.stages},
                            {"targets", inc.row.targets}, {"shared", inc.row.entities}, {"timeline", tl}});
  }
  in.items_omitted = r.omitted_items;
  in.carry_over = r.carry_over.size() + r.omitted_carry;
  in.previous = previous;

  const auto& p = r.vuln_posture;
  nlohmann::json v = nlohmann::json::object();
  v["open_total"] = p.total;
  v["packages"] = p.packages;
  v["actively_exploited"] = p.kev;
  v["with_fix_available"] = p.with_fix;
  v["new_in_period"] = p.new_in_period;
  v["by_severity"] = {{"critical", p.by_severity[4]}, {"high", p.by_severity[3]}, {"medium", p.by_severity[2]}, {"low", p.by_severity[1]}};
  nlohmann::json top = nlohmann::json::array();
  for (const auto& it : r.vuln_items) {
    if (top.size() >= kTopVulns) break;
    if (!hasTag(it.finding, "kev") && !it.is_new) continue;  // only what is exploited or new is worth a mention
    top.push_back({{"cve", it.finding.evidence.value("cve", std::string())},
                   {"package", it.finding.evidence.value("package", std::string())},
                   {"cvss", it.finding.evidence.value("cvss", nlohmann::json())},
                   {"actively_exploited", hasTag(it.finding, "kev")},
                   {"fixed_version", it.finding.evidence.value("fixed_version", std::string())}});
  }
  v["notable"] = top;
  in.vulnerabilities = v;
  return in;
}

Notifier::Synthesizer makeSynthesizer(Reasoner& reasoner, Store& store) {
  return [&reasoner, &store](const Report& r) -> std::optional<Synthesis> {
    if (!reasoner.available()) return std::nullopt;
    std::vector<std::string> previous;
    if (auto prev = store.recentSummaries(nowTs() - kLookback, kPreviousMails)) {
      for (const auto& [ts, text] : prev.value()) previous.push_back(report::fmtDate(ts) + ": " + text);
    }
    auto s = reasoner.synthesize(makeSynthesisInput(r, previous));
    if (!s) {
      spdlog::warn("AI report unavailable, the mail goes out without it: {}", s.error());
      return std::nullopt;
    }
    return std::move(s.value());
  };
}

}  // namespace agent
