#include "report/report.h"

#include <algorithm>
#include <set>

#include "analysis/incident.h"
#include "report/labels.h"
#include "vuln/cwe_names.h"
#include "report/text_util.h"

namespace agent {

Severity effectiveSeverity(const Finding& f, const std::optional<Assessment>& a) {
  if (isVulnFinding(f)) return f.severity;
  return a ? std::max(f.severity, a->risk) : f.severity;
}

namespace {

ReportItem makeItem(Store& store, const Finding& f, int64_t period_from) {
  ReportItem it;
  it.finding = f;
  if (auto a = store.latestAssessment(f.id); a && a.value()) it.assessment = *a.value();
  it.effective = effectiveSeverity(f, it.assessment);
  it.is_new = f.first_seen >= period_from;
  return it;
}

void sortItems(std::vector<ReportItem>& items) {
  std::stable_sort(items.begin(), items.end(), [](const ReportItem& a, const ReportItem& b) {
    if (a.effective != b.effective) return a.effective > b.effective;
    return a.finding.last_seen > b.finding.last_seen;
  });
}

// By real priority (CVSS + active exploitation + EPSS + reachability); the older fallback is: exploited, severity, CVSS.
void sortVulns(std::vector<ReportItem>& items) {
  const auto score = [](const ReportItem& i) { return i.finding.evidence.value("cvss", nlohmann::json()).is_number() ? i.finding.evidence["cvss"].get<double>() : -1.0; };
  const auto prio = [](const ReportItem& i) { return i.finding.evidence.value("priority", nlohmann::json()).is_number() ? i.finding.evidence["priority"].get<int>() : -1; };
  std::stable_sort(items.begin(), items.end(), [&](const ReportItem& a, const ReportItem& b) {
    if (prio(a) != prio(b)) return prio(a) > prio(b);
    const bool ka = hasTag(a.finding, "kev"), kb = hasTag(b.finding, "kev");
    if (ka != kb) return ka;
    if (a.effective != b.effective) return a.effective > b.effective;
    return score(a) > score(b);
  });
}

void addRef(std::map<std::string, size_t>& m, const std::string& id) { ++m[id]; }

std::vector<std::pair<std::string, size_t>> ranked(const std::map<std::string, size_t>& m) {
  std::vector<std::pair<std::string, size_t>> v(m.begin(), m.end());
  std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
  return v;
}

void finish(Report& r, const ReportContext& ctx) {
  sortItems(r.items);
  sortItems(r.carry_over);
  sortVulns(r.vuln_items);
  if (r.items.size() > ctx.max_items) {
    r.omitted_items += r.items.size() - ctx.max_items;
    r.items.resize(ctx.max_items);
  }
  if (r.carry_over.size() > ctx.max_carry_over) {
    r.omitted_carry += r.carry_over.size() - ctx.max_carry_over;
    r.carry_over.resize(ctx.max_carry_over);
  }
  if (r.vuln_items.size() > ctx.max_vuln_items) {
    r.omitted_vulns += r.vuln_items.size() - ctx.max_vuln_items;
    r.vuln_items.resize(ctx.max_vuln_items);
  }
  std::map<std::string, size_t> mitre, cwe;
  for (const auto* list : {&r.items, &r.vuln_items}) {
    for (const auto& it : *list) {
      r.top = std::max(r.top, it.effective);
      for (const auto& m : it.finding.mitre) addRef(mitre, m);
      for (const auto& id : it.finding.cwe) {
        addRef(cwe, id);
        if (r.cwe_names.count(id)) continue;
        std::string name = ctx.cwe_name ? ctx.cwe_name(id) : std::string();
        if (name.empty()) name = builtinCweName(id);
        r.cwe_names[id] = name;
      }
    }
  }
  for (const auto& it : r.carry_over) r.top = std::max(r.top, it.effective);
  r.mitre_refs = ranked(mitre);
  r.cwe_refs = ranked(cwe);
}

void place(Report& r, ReportItem&& it) {
  (isVulnFinding(it.finding) ? r.vuln_items : r.items).push_back(std::move(it));
}

void countOpen(Store& store, Report& r, int64_t period_from) {
  auto open = store.listFindings("open", 100000);
  if (!open) return;
  r.open_total = open.value().size();
  std::set<std::string> packages;
  for (const auto& f : open.value()) {
    auto a = store.latestAssessment(f.id);
    const Severity eff = effectiveSeverity(f, a && a.value() ? a.value() : std::nullopt);
    ++r.open_by_severity[static_cast<size_t>(eff)];
    if (!isVulnFinding(f)) continue;
    auto& p = r.vuln_posture;
    ++p.total;
    // Banded by CVSS (what the administrator expects to read), not by the severity the rule gives the alert.
    const double cvss = f.evidence.contains("cvss") && f.evidence["cvss"].is_number() ? f.evidence["cvss"].get<double>() : -1;
    const size_t band = hasTag(f, "kev") || cvss >= 9.0 ? 4 : cvss >= 7.0 ? 3 : cvss >= 4.0 ? 2 : 1;
    ++p.by_severity[band];
    if (hasTag(f, "kev")) ++p.kev;
    if (hasTag(f, "fix_available")) ++p.with_fix;
    if (f.first_seen >= period_from) ++p.new_in_period;
    packages.insert(f.target + "|" + f.evidence.value("package", std::string()));
  }
  r.vuln_posture.packages = packages.size();
}

constexpr size_t kIncidentCards = 3;  // member findings of an incident that keep a full card; the others are timeline lines

// Open incidents that touch what this mail reports. Their members are summarised in the incident (timeline) and the
// least important ones leave the list of full cards, so one attack reads as one story instead of twelve findings.
void attachIncidents(Store& store, Report& r, const ReportContext& ctx) {
  auto incs = store.listIncidents("open", 200);
  if (!incs) return;
  std::set<int64_t> featured;
  for (const auto* list : {&r.items, &r.carry_over}) for (const auto& it : *list) featured.insert(it.finding.id);
  std::set<int64_t> drop_from_items, drop_from_carry;
  for (const auto& inc : incs.value()) {
    if (std::none_of(inc.finding_ids.begin(), inc.finding_ids.end(), [&](int64_t id) { return featured.count(id) > 0; })) continue;
    IncidentView v;
    v.row = inc;
    v.title = incidentTitle(inc.stages, inc.targets, ctx.lang);
    for (int64_t id : inc.finding_ids) {
      auto f = store.getFinding(id);
      if (!f || !f.value() || f.value()->status != "open") continue;
      ReportItem it = makeItem(store, *f.value(), r.period_from);
      it.incident_id = inc.id;
      v.timeline.push_back(std::move(it));
    }
    if (v.timeline.size() < 2) continue;
    std::stable_sort(v.timeline.begin(), v.timeline.end(), [](const ReportItem& a, const ReportItem& b) { return a.finding.first_seen < b.finding.first_seen; });
    // which members keep a card: the most severe ones that are already in this mail's list
    std::vector<const ReportItem*> in_list;
    for (auto& it : r.items) if (std::any_of(inc.finding_ids.begin(), inc.finding_ids.end(), [&](int64_t id) { return id == it.finding.id; })) in_list.push_back(&it);
    std::stable_sort(in_list.begin(), in_list.end(), [](const ReportItem* a, const ReportItem* b) { return a->effective > b->effective; });
    for (size_t i = 0; i < in_list.size(); ++i) {
      const_cast<ReportItem*>(in_list[i])->incident_id = inc.id;
      if (i >= kIncidentCards) drop_from_items.insert(in_list[i]->finding.id);
    }
    for (const auto& it : r.carry_over) {
      if (std::any_of(inc.finding_ids.begin(), inc.finding_ids.end(), [&](int64_t id) { return id == it.finding.id; })) drop_from_carry.insert(it.finding.id);
    }
    r.top = std::max(r.top, inc.severity);
    r.incidents.push_back(std::move(v));
  }
  const auto gone = [](const std::set<int64_t>& ids) { return [&ids](const ReportItem& it) { return ids.count(it.finding.id) > 0; }; };
  r.in_incident_timelines += drop_from_items.size();
  r.items.erase(std::remove_if(r.items.begin(), r.items.end(), gone(drop_from_items)), r.items.end());
  r.carry_over.erase(std::remove_if(r.carry_over.begin(), r.carry_over.end(), gone(drop_from_carry)), r.carry_over.end());
  std::stable_sort(r.incidents.begin(), r.incidents.end(), [](const IncidentView& a, const IncidentView& b) {
    return a.row.severity != b.row.severity ? a.row.severity > b.row.severity : a.row.last_ts > b.row.last_ts;
  });
}

}  // namespace

Result<Report> buildAlertReport(Store& store, const std::vector<Finding>& findings, const ReportContext& ctx, int64_t now) {
  Report r;
  r.kind = Report::Kind::Alert;
  r.lang = ctx.lang;
  r.host_label = ctx.host_label;
  r.subject_prefix = ctx.subject_prefix;
  r.llm_enabled = ctx.llm_enabled;
  r.generated_at = r.period_to = now;
  int64_t oldest = now;
  for (const auto& f : findings) {
    ReportItem it = makeItem(store, f, 0);
    it.is_new = true;
    place(r, std::move(it));
    oldest = std::min(oldest, f.first_seen);
  }
  r.period_from = oldest;
  r.new_in_period = findings.size();
  countOpen(store, r, oldest);
  finish(r, ctx);
  attachIncidents(store, r, ctx);
  return r;
}

Result<Report> buildDigestReport(Store& store, int64_t from, int64_t to, Severity min_severity, const ReportContext& ctx) {
  Report r;
  r.kind = Report::Kind::Digest;
  r.lang = ctx.lang;
  r.host_label = ctx.host_label;
  r.subject_prefix = ctx.subject_prefix;
  r.llm_enabled = ctx.llm_enabled;
  r.generated_at = to;
  r.period_from = from;
  r.period_to = to;

  auto open = store.listFindings("open", 100000);
  if (!open) return err(open.error());
  for (const auto& f : open.value()) {
    ReportItem it = makeItem(store, f, from);
    if (it.is_new) ++r.new_in_period;
    if (it.effective < min_severity) continue;
    // New problems are described in full; what was already reported stays as a one-line reminder.
    if (isVulnFinding(it.finding) || it.is_new) place(r, std::move(it));
    else r.carry_over.push_back(std::move(it));
  }
  countOpen(store, r, from);
  if (auto n = store.countResolvedSince(from)) r.resolved_in_period = n.value();
  finish(r, ctx);
  attachIncidents(store, r, ctx);

  if (ctx.intel) r.intel_lines = ctx.intel(from, to);
  auto health = store.collectorHealth(from);
  if (health) {
    for (const auto& h : health.value()) {
      HealthRow row;
      row.target = h.target;
      row.collector = h.collector;
      row.last_ok = h.last_ok;
      row.last_error_ts = h.last_error_ts;
      row.last_error = h.last_error;
      row.ok_count = h.ok_count;
      row.error_count = h.error_count;
      const auto it = ctx.intervals.find(h.target + "|" + h.collector);
      if (it != ctx.intervals.end()) {
        row.stale = h.last_ok == 0 || to - h.last_ok > it->second * 3 + 120;  // a silent collector is a blind spot
      }
      r.health.push_back(std::move(row));
    }
  }
  return r;
}

Report buildTestReport(const ReportContext& ctx, int64_t now) {
  Report r;
  r.kind = Report::Kind::Test;
  r.lang = ctx.lang;
  r.host_label = ctx.host_label;
  r.subject_prefix = ctx.subject_prefix;
  r.llm_enabled = ctx.llm_enabled;
  r.generated_at = r.period_from = r.period_to = now;
  return r;
}

std::string reportSubject(const Report& r) {
  const auto& l = report::labels(r.lang);
  std::string s = r.subject_prefix.empty() ? "" : r.subject_prefix + " ";
  switch (r.kind) {
    case Report::Kind::Test:
      return s + l.title_test;
    case Report::Kind::Alert: {
      std::set<std::string> targets;
      for (const auto* list : {&r.items, &r.vuln_items}) for (const auto& it : *list) targets.insert(it.finding.target);
      std::string t;
      size_t n = 0;
      for (const auto& x : targets) {
        if (n++ == 3) {
          t += ", ...";
          break;
        }
        t += (t.empty() ? "" : ", ") + x;
      }
      std::string up = report::severityLabel(l, r.top);
      for (auto& c : up) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
      return s + up + ": " + std::to_string(r.items.size() + r.omitted_items + r.in_incident_timelines + r.vuln_items.size() + r.omitted_vulns) + " finding - " + report::sanitize(t, 80);
    }
    case Report::Kind::Digest: {
      std::string d = s + l.title_digest + " " + report::fmtDate(r.generated_at) + " - " + std::to_string(r.open_total) + " " +
                      (r.lang == "en" ? "open" : "aperti");
      if (r.top >= Severity::Medium) d += std::string(" (") + report::severityLabel(l, r.top) + ")";
      return d;
    }
  }
  return s;
}

}  // namespace agent
