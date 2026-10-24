#include <cstdio>
#include <sstream>

#include "report/labels.h"
#include "report/report.h"
#include "report/mitre_names.h"
#include "report/text_util.h"
#include "report/view.h"

namespace agent {
namespace {

constexpr size_t kWidth = 78;

std::string upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

std::string rule(char c = '-') { return std::string(kWidth, c) + "\n"; }

std::string field(const std::string& label, const std::string& value, size_t label_w = 18) {
  std::string l = label;
  if (l.size() < label_w) l.append(label_w - l.size(), ' ');
  return "  " + l + ": " + report::wrap(value, kWidth, label_w + 4) + "\n";
}

}  // namespace

std::string renderText(const Report& r) {
  using namespace report;
  const Labels& L = labels(r.lang);
  std::ostringstream o;
  const char* title = r.kind == Report::Kind::Alert ? L.title_alert : r.kind == Report::Kind::Digest ? L.title_digest : L.title_test;

  o << rule('=') << "dyna_cyber_agent - " << upper(title) << "\n" << rule('=');
  if (r.kind == Report::Kind::Test) {
    o << "\n" << wrap(L.test_body, kWidth) << "\n\n"
      << field(L.generated, fmtTime(r.generated_at)) << field(L.agent_host, sanitize(r.host_label, 120));
    return o.str();
  }

  o << field(L.top_risk, upper(severityLabel(L, r.top)));
  o << field(L.generated, fmtTime(r.generated_at));
  o << field(L.agent_host, sanitize(r.host_label, 120));
  if (r.kind == Report::Kind::Digest) o << field(L.period, fmtTime(r.period_from) + "  ->  " + fmtTime(r.period_to));
  {
    std::string counts;
    for (int s = 4; s >= 0; --s) {
      const size_t n = r.open_by_severity[static_cast<size_t>(s)];
      if (n) counts += (counts.empty() ? "" : ", ") + std::to_string(n) + " " + severityLabel(L, static_cast<Severity>(s));
    }
    o << field(L.open_findings, std::to_string(r.open_total) + (counts.empty() ? "" : "  (" + counts + ")"));
  }
  o << field(L.new_findings, std::to_string(r.new_in_period));
  if (r.kind == Report::Kind::Digest) o << field(L.resolved, std::to_string(r.resolved_in_period));
  o << "\n";

  if (r.items.empty() && r.vuln_items.empty() && r.carry_over.empty() && r.kind == Report::Kind::Digest) o << wrap(L.quiet, kWidth) << "\n\n";

  // ---- the single AI report ---------------------------------------------------------
  const bool has_content = !r.items.empty() || !r.vuln_items.empty() || !r.carry_over.empty();
  if (r.synthesis) {
    const Synthesis& sy = *r.synthesis;
    o << rule('=') << upper(L.summary_ai) << "\n" << rule('=');
    o << wrap(sanitize(sy.headline, 400), kWidth) << "\n\n" << wrap(sanitize(sy.summary, 1800), kWidth) << "\n";
    if (!sy.priorities.empty()) {
      o << "\n" << upper(en(r) ? "Priorities" : "Priorita'") << ":\n";
      int n = 1;
      for (const auto& p : sy.priorities) {
        std::string ids;
        for (auto id : p.finding_ids) ids += (ids.empty() ? " (#" : ", #") + std::to_string(id);
        o << "  " << n++ << ". " << wrap(sanitize(p.text, 500) + (ids.empty() ? "" : ids + ")"), kWidth, 5) << "\n";
      }
    }
    for (const auto& c : sy.correlations) {
      o << "\n" << upper(L.correlations) << ":\n* [" << upper(severityLabel(L, c.risk)) << "] " << sanitize(c.title, 200) << "\n  "
        << wrap(sanitize(c.narrative, 1200), kWidth, 2) << "\n  Finding: ";
      std::string ids;
      for (auto id : c.finding_ids) ids += (ids.empty() ? "#" : ", #") + std::to_string(id);
      o << ids;
      for (const auto& m : c.mitre) o << "  " << sanitize(m, 16);
      o << "\n";
    }
    o << "\n";
  } else if (has_content) {
    o << wrap(r.llm_enabled ? (en(r) ? "AI summary unavailable right now (model unreachable): the raw data follows." : "Sintesi AI non disponibile in questo momento (modello non raggiungibile): seguono i dati grezzi.")
                            : L.no_ai, kWidth) << "\n\n";
  }

  // ---- incidents --------------------------------------------------------------------
  if (!r.incidents.empty()) {
    o << rule('=') << upper(en(r) ? "Incidents" : "Incidenti") << " (" << r.incidents.size() << ")\n" << rule('=');
    for (const auto& inc : r.incidents) {
      o << "\n" << (en(r) ? "INCIDENT #" : "INCIDENTE #") << inc.row.id << "  [" << upper(severityLabel(L, inc.row.severity)) << "]  " << sanitize(inc.title, 240) << "\n" << rule();
      o << field(en(r) ? "Period" : "Periodo", fmtTime(inc.row.first_ts) + "  ->  " + fmtTime(inc.row.last_ts));
      std::string ents;
      for (const auto& e : inc.row.entities) ents += (ents.empty() ? "" : ", ") + sanitize(e.value("kind", std::string()), 8) + " " + sanitize(e.value("value", std::string()), 80);
      if (!ents.empty()) o << field(en(r) ? "Shared" : "In comune", ents);
      o << "  " << (en(r) ? "Timeline:" : "Cronologia:") << "\n";
      for (const auto& it : inc.timeline) {
        const Finding& f = it.finding;
        o << "    " << fmtTime(f.first_seen) << "  [" << upper(severityLabel(L, it.effective)) << "]  #" << f.id << " " << f.rule_id << "  "
          << wrap(sanitize(f.title, 160) + " - " + sanitize(f.target, 60) + " " + sanitize(f.stable_key, 140), kWidth, 8) << "\n";
      }
    }
    o << "\n";
  }

  // ---- findings ---------------------------------------------------------------------
  if (!r.items.empty()) {
    o << rule('=') << upper(en(r) ? "Security findings" : "Finding di sicurezza") << " (" << r.items.size() + r.omitted_items << ")\n" << rule('=');
    for (const auto& it : r.items) {
      const Finding& f = it.finding;
      o << "\n#" << f.id << "  [" << upper(severityLabel(L, it.effective)) << "]  " << f.rule_id << "  " << sanitize(f.title, 200)
        << (it.is_new ? std::string("  (") + L.status_new + ")" : "") << "\n"
        << rule();
      o << field(L.target, sanitize(f.target, 80));
      o << field(L.subject, sanitize(f.stable_key, 300));
      if (!f.mitre.empty()) {
        std::string m;
        for (const auto& x : f.mitre) m += (m.empty() ? "" : ", ") + sanitize(x, 16);
        o << field(L.mitre, m);
      }
      if (!f.cwe.empty()) {
        std::string c;
        for (const auto& id : f.cwe) {
          const auto n = r.cwe_names.find(id);
          c += (c.empty() ? "" : "; ") + sanitize(id, 16) + (n != r.cwe_names.end() && !n->second.empty() ? " " + sanitize(n->second, 120) : "");
        }
        o << field(L.cwe, c);
      }
      o << field(L.seen, std::to_string(f.occurrences) + L.times + "  (" + L.first_seen + ": " + fmtTime(f.first_seen) + ", " +
                             L.last_seen + ": " + fmtTime(f.last_seen) + ")");
      if (f.evidence.is_object() && f.evidence.contains("explained_by") && f.evidence["explained_by"].is_object()) {
        const auto& x = f.evidence["explained_by"];
        o << field(en(r) ? "Explained by" : "Spiegato da", sanitize(x.value("package", std::string()), 80) + " " + sanitize(x.value("old_version", std::string()), 60) +
                                                              (x.value("old_version", std::string()).empty() ? "" : " -> ") + sanitize(x.value("new_version", std::string()), 60) +
                                                              " (" + fmtTime(x.value("changed_at", int64_t(0))) + ")");
      }
      if (it.incident_id) o << field(en(r) ? "Incident" : "Incidente", "#" + std::to_string(it.incident_id));
      if (f.severity != it.effective) o << field("Severity", std::string(severityLabel(L, f.severity)) + " -> " + severityLabel(L, it.effective) + " (AI)");
      if (!f.description.empty()) o << "\n  " << wrap(sanitize(f.description, 800), kWidth, 2) << "\n";
      for (const auto& d : f.drift) o << "  " << L.not_in_baseline << ": " << d.facet << " = " << sanitize(d.key, 300) << "\n";

      if (it.assessment) {
        const Assessment& a = *it.assessment;
        o << "\n  " << L.assessment << ": " << verdictLabel(L, a.verdict) << " (" << L.confidence << " " << a.confidence << "%, "
          << severityLabel(L, a.risk) << ")\n";
        for (const auto& fl : a.flags) if (fl == "prompt_injection_suspected") o << "  !! " << wrap(L.flag_injection, kWidth, 6) << "\n";
        if (!a.explanation.empty()) o << "    " << wrap(sanitize(a.explanation, 1500), kWidth, 4) << "\n";
        if (!a.recommended_actions.empty()) {
          o << "    " << L.actions << ":\n";
          int n = 1;
          for (const auto& x : a.recommended_actions) o << "      " << n++ << ". " << wrap(sanitize(x, 400), kWidth, 9) << "\n";
        }
        if (!a.additional_checks.empty()) {
          o << "    " << L.checks << ":\n";
          for (const auto& x : a.additional_checks) o << "      - " << wrap(sanitize(x, 300), kWidth, 8) << "\n";
        }
      }

      const auto rows = flattenEvidence(f.evidence);
      if (!rows.empty()) {
        o << "\n  " << L.evidence << ":\n";
        for (const auto& [k, v] : rows) o << "    " << k << " = " << wrap(v, kWidth, 6 + k.size() + 3) << "\n";
      }
    }
    if (r.omitted_items) {
      char buf[256];
      std::snprintf(buf, sizeof(buf), L.omitted, r.omitted_items);
      o << "\n" << buf << "\n";
    }
  }

  // ---- still open, already reported earlier -----------------------------------------
  if (!r.carry_over.empty()) {
    o << "\n" << rule('=') << upper(en(r) ? "Still open (already reported)" : "Ancora aperti (gia' segnalati)") << " (" << r.carry_over.size() + r.omitted_carry << ")\n" << rule('=');
    for (const auto& it : r.carry_over) {
      const Finding& f = it.finding;
      o << "#" << f.id << " [" << upper(severityLabel(L, it.effective)) << "] " << f.rule_id << " "
        << wrap(sanitize(f.title, 160) + " - " + sanitize(f.stable_key, 160) + " (" + sanitize(f.target, 60) + ", " + fmtDate(f.first_seen) + ")", kWidth, 6) << "\n";
    }
    if (r.omitted_carry) {
      char buf[256];
      std::snprintf(buf, sizeof(buf), L.omitted, r.omitted_carry);
      o << buf << "\n";
    }
  }

  // ---- vulnerabilities and references (always last: it is reference material) ---------
  if (!r.vuln_items.empty() || !r.mitre_refs.empty() || !r.cwe_refs.empty() || !r.intel_lines.empty()) {
    o << "\n" << rule('=') << upper(en(r) ? "Vulnerabilities and references (CVE / CWE / MITRE ATT&CK)" : "Vulnerabilita' e riferimenti (CVE / CWE / MITRE ATT&CK)") << "\n" << rule('=');
    const auto& p = r.vuln_posture;
    if (p.total) {
      std::string bands;
      for (int s = 4; s >= 1; --s) {
        const size_t n = p.by_severity[static_cast<size_t>(s)];
        if (n) bands += (bands.empty() ? "" : ", ") + std::to_string(n) + " " + severityLabel(L, static_cast<Severity>(s));
      }
      o << wrap((en(r) ? "Open vulnerabilities: " : "Vulnerabilita' aperte: ") + std::to_string(p.total) + (bands.empty() ? "" : " (" + bands + ")") +
                    (en(r) ? ", in " : ", su ") + std::to_string(p.packages) + (en(r) ? " package(s); " : " pacchetti; ") + std::to_string(p.kev) +
                    (en(r) ? " actively exploited; " : " attivamente sfruttate; ") + std::to_string(p.with_fix) +
                    (en(r) ? " with a fix available; " : " con correzione disponibile; ") + std::to_string(p.new_in_period) + (en(r) ? " new in period." : " nuove nel periodo."),
                kWidth) << "\n";
    }
    for (const auto& g : groupVulns(r)) {
      o << "\n" << g.target << " / " << g.package << (g.installed.empty() ? "" : " " + g.installed) << "\n";
      size_t shown = 0;
      for (const ReportItem* it : g.cves) {
        if (shown++ >= 8) { o << "    ... +" << g.cves.size() - 8 << (en(r) ? " more\n" : " altre\n"); break; }
        const CveView v = cveView(*it, r);
        char score[16];
        if (v.cvss >= 0) std::snprintf(score, sizeof(score), "%.1f", v.cvss); else std::snprintf(score, sizeof(score), "n/d");
        o << "  #" << it->finding.id << " " << v.cve << "  CVSS " << score;
        if (v.kev) o << "  [" << (en(r) ? "ACTIVELY EXPLOITED" : "ATTIVAMENTE SFRUTTATA") << "]";
        if (v.ransomware) o << "  [ransomware]";
        if (v.recent) o << "  [" << (en(r) ? "NEW" : "NUOVA") << "]";
        if (v.low_confidence) o << "  [" << (en(r) ? "to verify" : "da verificare") << "]";
        if (v.epss >= 0.01) { char e[24]; std::snprintf(e, sizeof(e), "%.*f%%", v.epss >= 0.1 ? 0 : 1, v.epss * 100); o << "  [EPSS " << e << "]"; }
        if (v.exposure == "listening") o << "  [" << (en(r) ? "listening: " : "in ascolto: ") << v.ports << "]";
        else if (v.exposure == "listening_local") o << "  [" << (en(r) ? "local listener" : "in ascolto (locale)") << "]";
        else if (v.exposure == "running") o << "  [" << (en(r) ? "running" : "in esecuzione") << "]";
        if (v.reboot_pending) o << "  [" << (en(r) ? "reboot pending" : "riavvio in attesa") << "]";
        if (!v.cwe_text.empty()) o << "  " << v.cwe_text;
        o << "  " << (v.fixed.empty() ? (en(r) ? "no fix known" : "nessuna correzione nota") : (en(r) ? "fix: " : "correzione: ") + v.fixed) << "\n";
      }
    }
    if (r.omitted_vulns) {
      o << "\n" << (en(r) ? "other " : "altre ") << r.omitted_vulns << (en(r) ? " vulnerabilities not shown (lowest priority): run `dyna_cyber_agent --events`\n" : " vulnerabilita' non mostrate (priorita' piu' bassa): usa `dyna_cyber_agent --events`\n");
    }
    if (!r.mitre_refs.empty()) {
      o << "\n" << upper(L.mitre) << ":\n";
      for (const auto& [id, n] : r.mitre_refs) {
        const std::string name = mitreName(id);
        o << "  " << sanitize(id, 16) << (name.empty() ? "" : "  " + name) << "  (" << n << ")\n";
      }
    }
    if (!r.cwe_refs.empty()) {
      o << "\n" << upper(L.cwe) << ":\n";
      for (const auto& [id, n] : r.cwe_refs) {
        const auto nm = r.cwe_names.find(id);
        o << "  " << sanitize(id, 16) << (nm != r.cwe_names.end() && !nm->second.empty() ? "  " + sanitize(nm->second, 100) : "") << "  (" << n << ")\n";
      }
    }
    if (!r.intel_lines.empty()) {
      o << "\n" << upper(L.intel) << ":\n";
      for (const auto& line : r.intel_lines) o << "* " << wrap(sanitize(line, 400), kWidth, 2) << "\n";
    }
  }

  // ---- collector health ---------------------------------------------------------------
  if (!r.health.empty()) {
    o << "\n" << rule('=') << upper(L.health) << "\n" << rule('=');
    for (const auto& h : r.health) {
      o << (h.stale ? "!! " : "   ") << sanitize(h.target, 60) << " / " << h.collector << ": " << h.ok_count << " " << L.ok_runs << ", "
        << h.error_count << " " << L.err_runs << ", " << L.last_ok << " " << (h.last_ok ? fmtTime(h.last_ok) : L.never)
        << (h.stale ? std::string("  <-- ") + L.stale : "") << "\n";
      if (h.error_count && !h.last_error.empty()) o << "      " << L.last_error << ": " << wrap(sanitize(h.last_error, 300), kWidth, 8 + std::string(L.last_error).size() + 2) << "\n";
    }
  }

  o << "\n" << rule() << wrap(L.footer_ai, kWidth) << "\n" << wrap(L.footer_accept, kWidth) << "\n";
  return o.str();
}

}  // namespace agent
