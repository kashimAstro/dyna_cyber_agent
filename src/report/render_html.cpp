#include <cstdio>
#include <sstream>

#include "report/labels.h"
#include "report/report.h"
#include "report/mitre_names.h"
#include "report/text_util.h"
#include "report/view.h"

namespace agent {
namespace {

using report::htmlEscape;
using report::sanitize;

struct Pal { const char *solid, *tint; };
// Solid colours keep >= 4.5:1 contrast with white text.
const Pal kPal[5] = {{"#4b5563", "#f3f4f6"},   // info
                     {"#1d4ed8", "#eff6ff"},   // low
                     {"#b45309", "#fffbeb"},   // medium
                     {"#c2410c", "#fff7ed"},   // high
                     {"#991b1b", "#fef2f2"}};  // critical

const char* kFont = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const char* kMono = "SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";

std::string E(const std::string& s, size_t max = 600) { return htmlEscape(sanitize(s, max)); }

std::string upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

std::string badge(const report::Labels& L, Severity s) {
  const auto i = static_cast<size_t>(s);
  return std::string("<span style=\"display:inline-block;padding:2px 9px;border-radius:11px;background:") + kPal[i].solid +
         ";color:#ffffff;font-size:12px;font-weight:700;letter-spacing:.4px;white-space:nowrap\">" +
         htmlEscape(upper(report::severityLabel(L, s))) + "</span>";
}

std::string chip(const std::string& text, const char* bg = "#e5e7eb", const char* fg = "#374151") {
  return std::string("<span class=\"chip\" style=\"display:inline-block;margin:2px 4px 2px 0;padding:1px 7px;border-radius:4px;background:") + bg +
         ";color:" + fg + ";font-size:12px;font-family:" + kMono + "\">" + htmlEscape(text) + "</span>";
}

std::string label(const std::string& t) {
  return "<div class=\"muted\" style=\"font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:#6b7280;margin:12px 0 4px\">" +
         htmlEscape(t) + "</div>";
}

std::string section(const std::string& title) {
  return "<tr><td style=\"padding:22px 4px 8px\"><div class=\"txt\" style=\"font-size:15px;font-weight:700;color:#111827\">" + htmlEscape(title) +
         "</div></td></tr>\n";
}

std::string metaRow(const std::string& k, const std::string& v_html) {
  return "<tr><td class=\"muted\" style=\"padding:2px 12px 2px 0;font-size:12px;color:#6b7280;white-space:nowrap;vertical-align:top\">" + htmlEscape(k) +
         "</td><td class=\"txt\" style=\"padding:2px 0;font-size:13px;color:#1f2937\">" + v_html + "</td></tr>";
}

std::string mono(const std::string& s) {
  return std::string("<span style=\"font-family:") + kMono + ";font-size:12px;word-break:break-all\">" + s + "</span>";
}

std::string statCell(const report::Labels& L, Severity s, size_t n) {
  const auto i = static_cast<size_t>(s);
  return std::string("<td align=\"center\" class=\"stat\" style=\"padding:10px 4px;background:") + kPal[i].tint + ";border-top:3px solid " + kPal[i].solid +
         "\"><div style=\"font-size:22px;font-weight:700;color:" + kPal[i].solid + "\">" + std::to_string(n) +
         "</div><div style=\"font-size:11px;color:#4b5563;text-transform:uppercase;letter-spacing:.5px\">" +
         htmlEscape(report::severityLabel(L, s)) + "</div></td>";
}

void renderFinding(std::ostringstream& o, const report::Labels& L, const ReportItem& it, const std::map<std::string, std::string>& r_cwe) {
  const Finding& f = it.finding;
  const auto i = static_cast<size_t>(it.effective);
  o << "<tr><td style=\"padding:0 0 14px\">\n"
    << "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-left:5px solid "
    << kPal[i].solid << ";border-radius:6px\"><tr><td style=\"padding:14px 16px\">\n";

  o << "<div class=\"txt\" style=\"font-size:15px;font-weight:700;color:#111827;line-height:1.35\">" << badge(L, it.effective) << " &nbsp;"
    << "<span style=\"color:#6b7280;font-weight:600\">#" << f.id << " &middot; " << E(f.rule_id, 40) << "</span><br>" << E(f.title, 200);
  if (it.is_new) o << " &nbsp;" << chip(L.status_new, "#dcfce7", "#166534");
  o << "</div>\n";

  o << "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-top:8px\">"
    << metaRow(L.target, E(f.target, 80)) << metaRow(L.subject, mono(E(f.stable_key, 300)))
    << metaRow(L.seen, std::to_string(f.occurrences) + htmlEscape(L.times) + " &middot; " + htmlEscape(report::fmtTime(f.first_seen)) + " &rarr; " +
                           htmlEscape(report::fmtTime(f.last_seen)));
  if (f.severity != it.effective) {
    o << metaRow("Severity", htmlEscape(report::severityLabel(L, f.severity)) + " &rarr; <b>" + htmlEscape(report::severityLabel(L, it.effective)) + "</b> (AI)");
  }
  o << "</table>\n";

  if (!f.description.empty()) {
    o << "<div class=\"txt\" style=\"margin-top:10px;font-size:13px;line-height:1.5;color:#374151\">" << E(f.description, 800) << "</div>\n";
  }
  if (f.evidence.is_object() && f.evidence.contains("explained_by") && f.evidence["explained_by"].is_object()) {
    const auto& x = f.evidence["explained_by"];
    const bool en_ = std::string(L.sev[1]) == "low";
    o << "<div class=\"txt\" style=\"margin-top:10px;padding:8px 10px;background:#ecfdf5;border-radius:4px;color:#065f46;font-size:12px\">&#10003; "
      << htmlEscape(en_ ? "Probably explained by a package update: " : "Probabilmente spiegato da un aggiornamento: ") << "<b>" << E(x.value("package", std::string()), 80) << "</b> "
      << E(x.value("old_version", std::string()), 60) << (x.value("old_version", std::string()).empty() ? "" : " &rarr; ") << E(x.value("new_version", std::string()), 60) << " &middot; "
      << htmlEscape(report::fmtTime(x.value("changed_at", int64_t(0)))) << "</div>\n";
  }
  if (it.incident_id) {
    o << "<div style=\"margin-top:8px\">" << chip((std::string(L.sev[1]) == "low" ? "incident #" : "incidente #") + std::to_string(it.incident_id), "#e0e7ff", "#3730a3") << "</div>\n";
  }
  if (!f.mitre.empty()) {
    o << label(L.mitre);
    for (const auto& m : f.mitre) o << chip(sanitize(m, 16), "#ede9fe", "#5b21b6");
  }
  if (!f.cwe.empty()) {
    o << label(L.cwe);
    for (const auto& id : f.cwe) {
      const auto n = r_cwe.find(id);
      o << chip(sanitize(id, 16) + (n != r_cwe.end() && !n->second.empty() ? " " + sanitize(n->second, 80) : ""), "#ccfbf1", "#115e59");
    }
  }
  if (!f.drift.empty()) {
    o << label(L.not_in_baseline);
    for (const auto& d : f.drift) o << "<div style=\"margin:2px 0\">" << chip(d.facet, "#fef3c7", "#92400e") << mono(E(d.key, 300)) << "</div>";
  }

  if (it.assessment) {
    const Assessment& a = *it.assessment;
    o << "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"ai\" style=\"margin-top:14px;background:#f5f3ff;border-radius:6px\"><tr><td style=\"padding:12px 14px\">"
      << "<div style=\"font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:#5b21b6\">" << htmlEscape(L.assessment) << "</div>"
      << "<div class=\"txt\" style=\"margin-top:4px;font-size:13px;color:#1f2937\"><b>" << htmlEscape(report::verdictLabel(L, a.verdict)) << "</b> &middot; "
      << htmlEscape(L.confidence) << " " << a.confidence << "% &middot; " << badge(L, a.risk) << "</div>";
    for (const auto& fl : a.flags) {
      if (fl == "prompt_injection_suspected") {
        o << "<div style=\"margin-top:8px;padding:8px 10px;background:#fee2e2;border-radius:4px;color:#7f1d1d;font-size:12px;font-weight:600\">&#9888; "
          << htmlEscape(L.flag_injection) << "</div>";
      }
    }
    if (!a.explanation.empty()) {
      o << "<div class=\"txt\" style=\"margin-top:8px;font-size:13px;line-height:1.5;color:#374151;white-space:pre-line\">" << E(a.explanation, 1500) << "</div>";
    }
    if (!a.recommended_actions.empty()) {
      o << label(L.actions) << "<ol class=\"txt\" style=\"margin:0;padding-left:20px;font-size:13px;line-height:1.5;color:#374151\">";
      for (const auto& x : a.recommended_actions) o << "<li style=\"margin:2px 0\">" << E(x, 400) << "</li>";
      o << "</ol>";
    }
    if (!a.additional_checks.empty()) {
      o << label(L.checks) << "<ul class=\"txt\" style=\"margin:0;padding-left:20px;font-size:13px;line-height:1.5;color:#374151\">";
      for (const auto& x : a.additional_checks) o << "<li style=\"margin:2px 0\">" << E(x, 300) << "</li>";
      o << "</ul>";
    }
    o << "</td></tr></table>\n";
  }

  const auto rows = report::flattenEvidence(f.evidence);
  if (!rows.empty()) {
    o << label(L.evidence)
      << "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"code\" style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:4px\">";
    for (const auto& [k, v] : rows) {
      o << "<tr><td class=\"muted\" style=\"padding:3px 10px;font-family:" << kMono << ";font-size:11px;color:#6b7280;vertical-align:top;white-space:nowrap\">"
        << htmlEscape(k) << "</td><td class=\"txt\" style=\"padding:3px 10px 3px 0;font-family:" << kMono
        << ";font-size:11px;color:#1f2937;word-break:break-all\">" << htmlEscape(v) << "</td></tr>";
    }
    o << "</table>\n";
  }
  o << "</td></tr></table>\n</td></tr>\n";
}

}  // namespace

std::string renderHtml(const Report& r) {
  using namespace report;
  const Labels& L = labels(r.lang);
  const char* title = r.kind == Report::Kind::Alert ? L.title_alert : r.kind == Report::Kind::Digest ? L.title_digest : L.title_test;
  const auto top = static_cast<size_t>(r.top);
  std::ostringstream o;

  std::string pre = r.kind == Report::Kind::Test ? std::string(L.test_body)
                    : r.synthesis                ? r.synthesis->headline
    : r.items.empty() && r.vuln_items.empty() ? std::string(L.quiet)
                                                 : std::to_string(r.items.size() + r.omitted_items + r.in_incident_timelines + r.vuln_items.size() + r.omitted_vulns) + " finding - " + severityLabel(L, r.top);

  o << "<!doctype html>\n<html lang=\"" << (r.lang == "en" ? "en" : "it") << "\"><head><meta charset=\"utf-8\">"
    << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    << "<meta name=\"color-scheme\" content=\"light dark\"><meta name=\"supported-color-schemes\" content=\"light dark\">"
    << "<title>" << htmlEscape(reportSubject(r)) << "</title>\n<style>\n"
    << "@media (prefers-color-scheme: dark){"
       ".page{background:#0f172a !important}.card{background:#1e293b !important;border-color:#334155 !important}"
       ".txt{color:#e2e8f0 !important}.muted{color:#94a3b8 !important}.code{background:#0f172a !important;border-color:#334155 !important}"
       ".ai{background:#2e1065 !important}.stat{background:#1e293b !important}.chip{background:#334155 !important;color:#e2e8f0 !important}}\n"
    << "@media (max-width:480px){.wrap{padding:8px 4px !important}}\n</style></head>\n"
    << "<body class=\"page\" style=\"margin:0;padding:0;background:#eef1f5;font-family:" << kFont << "\">\n"
    << "<div style=\"display:none;max-height:0;overflow:hidden;opacity:0;font-size:1px;line-height:1px\">" << E(pre, 140) << "</div>\n"
    << "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"page\" style=\"background:#eef1f5\"><tr><td align=\"center\" class=\"wrap\" style=\"padding:24px 12px\">\n"
    << "<table role=\"presentation\" width=\"680\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%;max-width:680px\">\n";

  // header band
  const char* band = r.kind == Report::Kind::Test ? "#374151" : kPal[top].solid;
  o << "<tr><td style=\"background:" << band << ";border-radius:8px 8px 0 0;padding:20px 24px\">"
    << "<div style=\"font-size:12px;font-weight:700;letter-spacing:1px;color:#ffffffcc;text-transform:uppercase\">dyna_cyber_agent</div>"
    << "<div style=\"font-size:22px;font-weight:700;color:#ffffff;margin-top:2px\">" << htmlEscape(title) << "</div>";
  if (r.kind != Report::Kind::Test) {
    o << "<div style=\"font-size:13px;color:#ffffffdd;margin-top:6px\">" << htmlEscape(L.top_risk) << ": <b>" << htmlEscape(upper(severityLabel(L, r.top)))
      << "</b></div>";
  }
  o << "</td></tr>\n";

  o << "<tr><td class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-top:0;border-radius:0 0 8px 8px;padding:18px 24px\">\n"
    << "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\">"
    << metaRow(L.generated, htmlEscape(fmtTime(r.generated_at))) << metaRow(L.agent_host, E(r.host_label, 120));
  if (r.kind == Report::Kind::Digest) o << metaRow(L.period, htmlEscape(fmtTime(r.period_from)) + " &rarr; " + htmlEscape(fmtTime(r.period_to)));
  o << "</table>\n";

  if (r.kind == Report::Kind::Test) {
    o << "<p class=\"txt\" style=\"font-size:14px;line-height:1.6;color:#1f2937;margin:16px 0 0\">" << htmlEscape(L.test_body) << "</p></td></tr>\n";
  } else {
    o << "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"6\" style=\"margin:16px -6px 0;width:calc(100% + 12px)\"><tr>";
    for (int s = 4; s >= 0; --s) o << statCell(L, static_cast<Severity>(s), r.open_by_severity[static_cast<size_t>(s)]);
    o << "</tr></table>\n"
      << "<div class=\"muted\" style=\"font-size:12px;color:#6b7280;margin-top:6px\">" << htmlEscape(L.open_findings) << ": <b>" << r.open_total << "</b> &middot; "
      << htmlEscape(L.new_findings) << ": <b>" << r.new_in_period << "</b>"
      << (r.kind == Report::Kind::Digest ? " &middot; " + htmlEscape(L.resolved) + ": <b>" + std::to_string(r.resolved_in_period) + "</b>" : std::string()) << "</div>\n</td></tr>\n";
  }

  if (r.kind != Report::Kind::Test) {
    if (r.items.empty() && r.vuln_items.empty() && r.carry_over.empty() && r.kind == Report::Kind::Digest) {
      o << "<tr><td style=\"padding:20px 4px\"><div class=\"txt\" style=\"font-size:15px;color:#166534;background:#dcfce7;border-radius:6px;padding:14px 16px\">&#10003; "
        << htmlEscape(L.quiet) << "</div></td></tr>\n";
    }

    const bool has_content = !r.items.empty() || !r.vuln_items.empty() || !r.carry_over.empty();
    const bool is_en = r.lang == "en";
    const auto card = [&](const char* border) {
      return std::string("<tr><td style=\"padding:0 0 10px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-left:5px solid ") +
             border + ";border-radius:6px\"><tr><td style=\"padding:14px 16px\">";
    };
    const std::string card_end = "</td></tr></table></td></tr>\n";

    // ---- the single AI report, first thing the reader sees ----
    if (r.synthesis) {
      const Synthesis& sy = *r.synthesis;
      o << section(L.summary_ai) << card("#5b21b6") << "<div class=\"txt\" style=\"font-size:16px;font-weight:700;line-height:1.4;color:#111827\">" << E(sy.headline, 400)
        << "</div><div class=\"txt\" style=\"margin-top:8px;font-size:14px;line-height:1.6;color:#1f2937\">" << E(sy.summary, 1800) << "</div>";
      if (!sy.priorities.empty()) {
        o << label(is_en ? "Priorities" : "Priorita'") << "<ol class=\"txt\" style=\"margin:0;padding-left:20px;font-size:13px;line-height:1.55;color:#374151\">";
        for (const auto& p : sy.priorities) {
          o << "<li style=\"margin:3px 0\">" << E(p.text, 500);
          for (auto id : p.finding_ids) o << " " << chip("#" + std::to_string(id));
          o << "</li>";
        }
        o << "</ol>";
      }
      for (const auto& c : sy.correlations) {
        const auto i = static_cast<size_t>(c.risk);
        o << "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-top:12px;background:" << kPal[i].tint
          << ";border-radius:6px\"><tr><td style=\"padding:10px 14px\"><div style=\"font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:#4b5563\">"
          << htmlEscape(L.correlations) << "</div><div style=\"margin-top:4px;font-size:14px;font-weight:700;color:#111827\">" << badge(L, c.risk) << " &nbsp;" << E(c.title, 200)
          << "</div><div style=\"margin-top:4px;font-size:13px;line-height:1.5;color:#374151\">" << E(c.narrative, 1200) << "</div><div style=\"margin-top:6px\">";
        for (auto id : c.finding_ids) o << chip("#" + std::to_string(id));
        for (const auto& m : c.mitre) o << chip(sanitize(m, 16), "#ede9fe", "#5b21b6");
        o << "</div></td></tr></table>";
      }
      o << card_end;
    } else if (has_content) {
      o << "<tr><td class=\"muted\" style=\"padding:14px 4px 0;font-size:12px;color:#6b7280\">"
        << htmlEscape(r.llm_enabled ? (is_en ? "AI summary unavailable right now (model unreachable): the raw data follows." : "Sintesi AI non disponibile in questo momento (modello non raggiungibile): seguono i dati grezzi.")
                                    : L.no_ai)
        << "</td></tr>\n";
    }

    // ---- incidents: related findings told as one story ----
    if (!r.incidents.empty()) {
      o << section(std::string(is_en ? "Incidents" : "Incidenti") + " (" + std::to_string(r.incidents.size()) + ")");
      for (const auto& inc : r.incidents) {
        const auto i = static_cast<size_t>(inc.row.severity);
        o << "<tr><td style=\"padding:0 0 14px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-left:5px solid "
          << kPal[i].solid << ";border-radius:6px\"><tr><td style=\"padding:14px 16px\">"
          << "<div class=\"txt\" style=\"font-size:15px;font-weight:700;color:#111827;line-height:1.35\">" << badge(L, inc.row.severity) << " &nbsp;<span style=\"color:#6b7280;font-weight:600\">"
          << (is_en ? "incident" : "incidente") << " #" << inc.row.id << "</span><br>" << E(inc.title, 240) << "</div>"
          << "<div class=\"muted\" style=\"margin-top:4px;font-size:12px;color:#6b7280\">" << htmlEscape(fmtTime(inc.row.first_ts)) << " &rarr; " << htmlEscape(fmtTime(inc.row.last_ts))
          << " &middot; " << inc.timeline.size() << (is_en ? " findings" : " finding") << "</div>";
        if (!inc.row.entities.empty()) {
          o << "<div style=\"margin-top:8px\">";
          for (const auto& e : inc.row.entities) o << chip(sanitize(e.value("kind", std::string()), 8) + " " + sanitize(e.value("value", std::string()), 80), "#e0e7ff", "#3730a3");
          o << "</div>";
        }
        o << "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"code\" style=\"margin-top:10px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:4px\">";
        for (const auto& it : inc.timeline) {
          const Finding& f = it.finding;
          o << "<tr><td class=\"muted\" style=\"padding:5px 10px;font-size:11px;color:#6b7280;white-space:nowrap;vertical-align:top\">" << htmlEscape(fmtTime(f.first_seen)) << "</td>"
            << "<td style=\"padding:5px 6px;vertical-align:top\">" << badge(L, it.effective) << "</td>"
            << "<td class=\"txt\" style=\"padding:5px 10px 5px 0;font-size:12px;color:#1f2937\"><span class=\"muted\" style=\"color:#6b7280\">#" << f.id << " " << E(f.rule_id, 30) << "</span> " << E(f.title, 160)
            << "<div class=\"muted\" style=\"color:#6b7280\">" << E(f.target, 60) << " &middot; " << mono(E(f.stable_key, 140)) << "</div></td></tr>";
        }
        o << "</table></td></tr></table></td></tr>\n";
      }
    }

    // ---- security findings ----
    if (!r.items.empty()) {
      o << section(std::string(is_en ? "Security findings" : "Finding di sicurezza") + " (" + std::to_string(r.items.size() + r.omitted_items) + ")");
      for (const auto& it : r.items) renderFinding(o, L, it, r.cwe_names);
      if (r.omitted_items) {
        char buf[256];
        std::snprintf(buf, sizeof(buf), L.omitted, r.omitted_items);
        o << "<tr><td class=\"muted\" style=\"padding:0 4px 10px;font-size:13px;color:#6b7280\">" << htmlEscape(buf) << "</td></tr>\n";
      }
    }

    // ---- still open, reported before ----
    if (!r.carry_over.empty()) {
      o << section(std::string(is_en ? "Still open (already reported)" : "Ancora aperti (gia' segnalati)") + " (" + std::to_string(r.carry_over.size() + r.omitted_carry) + ")")
        << "<tr><td style=\"padding:0 0 10px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:6px\">";
      bool first = true;
      for (const auto& it : r.carry_over) {
        const Finding& f = it.finding;
        o << "<tr><td class=\"txt\" style=\"padding:7px 14px;" << (first ? "" : "border-top:1px solid #e5e7eb;") << "font-size:13px;color:#1f2937\">" << badge(L, it.effective)
          << " <span class=\"muted\" style=\"color:#6b7280\">#" << f.id << " &middot; " << E(f.rule_id, 40) << "</span> " << E(f.title, 160)
          << "<div class=\"muted\" style=\"font-size:12px;color:#6b7280;margin-top:2px\">" << E(f.target, 60) << " &middot; " << mono(E(f.stable_key, 160)) << " &middot; "
          << htmlEscape(report::fmtDate(f.first_seen)) << "</div></td></tr>";
        first = false;
      }
      o << "</table></td></tr>\n";
      if (r.omitted_carry) {
        char buf[256];
        std::snprintf(buf, sizeof(buf), L.omitted, r.omitted_carry);
        o << "<tr><td class=\"muted\" style=\"padding:0 4px 10px;font-size:13px;color:#6b7280\">" << htmlEscape(buf) << "</td></tr>\n";
      }
    }

    // ---- collector health ----
    // ---- vulnerabilities and references: reference material, so it comes last ----
    if (!r.vuln_items.empty() || !r.mitre_refs.empty() || !r.cwe_refs.empty() || !r.intel_lines.empty()) {
      o << section(is_en ? "Vulnerabilities and references (CVE / CWE / MITRE ATT&CK)" : "Vulnerabilita' e riferimenti (CVE / CWE / MITRE ATT&CK)");
      const auto& p = r.vuln_posture;
      if (p.total) {
        o << "<tr><td style=\"padding:0 0 10px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"6\" style=\"margin:0 -6px;width:calc(100% + 12px)\"><tr>";
        for (int sv = 4; sv >= 1; --sv) o << statCell(L, static_cast<Severity>(sv), p.by_severity[static_cast<size_t>(sv)]);
        o << "</tr></table><div class=\"muted\" style=\"font-size:12px;color:#6b7280;margin-top:4px\">" << p.total << (is_en ? " open vulnerabilities in " : " vulnerabilita' aperte su ")
          << p.packages << (is_en ? " package(s) &middot; " : " pacchetti &middot; ") << "<b>" << p.kev << "</b>" << (is_en ? " actively exploited" : " attivamente sfruttate") << " &middot; " << p.with_fix
          << (is_en ? " with a fix available" : " con correzione disponibile") << " &middot; " << p.new_in_period << (is_en ? " new in period" : " nuove nel periodo") << "</div></td></tr>\n";
      }
      const auto groups = groupVulns(r);
      if (!groups.empty()) {
        o << "<tr><td style=\"padding:0 0 10px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:6px\">";
        bool first_group = true;
        for (const auto& g : groups) {
          o << "<tr><td class=\"txt\" style=\"padding:9px 14px;" << (first_group ? "" : "border-top:1px solid #e5e7eb;") << "font-size:13px;color:#1f2937\"><b>" << E(g.package, 80) << "</b> "
            << "<span class=\"muted\" style=\"color:#6b7280\">" << E(g.installed, 60) << " &middot; " << E(g.target, 60) << "</span>";
          size_t shown = 0;
          for (const ReportItem* it : g.cves) {
            if (shown++ >= 8) {
              o << "<div class=\"muted\" style=\"font-size:12px;color:#6b7280;margin-top:3px\">+" << g.cves.size() - 8 << (is_en ? " more" : " altre") << "</div>";
              break;
            }
            const CveView v = cveView(*it, r);
            char score[16];
            if (v.cvss >= 0) std::snprintf(score, sizeof(score), "%.1f", v.cvss); else std::snprintf(score, sizeof(score), "n/d");
            o << "<div style=\"margin-top:5px;font-size:12px;line-height:1.5\">" << mono(htmlEscape(v.cve)) << " <b>CVSS " << score << "</b> ";
            if (v.kev) o << chip(is_en ? "ACTIVELY EXPLOITED" : "ATTIVAMENTE SFRUTTATA", "#fee2e2", "#7f1d1d");
            if (v.ransomware) o << chip("ransomware", "#fee2e2", "#7f1d1d");
            if (v.recent) o << chip(is_en ? "NEW" : "NUOVA", "#dcfce7", "#166534");
            if (v.low_confidence) o << chip(is_en ? "to verify" : "da verificare", "#fef3c7", "#92400e");
            if (v.epss >= 0.1) { char e[24]; std::snprintf(e, sizeof(e), "EPSS %.0f%%", v.epss * 100); o << chip(e, "#fee2e2", "#7f1d1d"); }
            else if (v.epss >= 0.01) { char e[24]; std::snprintf(e, sizeof(e), "EPSS %.1f%%", v.epss * 100); o << chip(e); }
            if (v.exposure == "listening") o << chip((is_en ? "listening: " : "in ascolto: ") + v.ports, "#fee2e2", "#7f1d1d");
            else if (v.exposure == "listening_local") o << chip(is_en ? "local listener" : "in ascolto (locale)", "#fef3c7", "#92400e");
            else if (v.exposure == "running") o << chip(is_en ? "running" : "in esecuzione");
            if (v.reboot_pending) o << chip(is_en ? "reboot pending" : "riavvio in attesa", "#e0e7ff", "#3730a3");
            o << " <span class=\"muted\" style=\"color:#6b7280\">" << (v.fixed.empty() ? htmlEscape(is_en ? "no fix known" : "nessuna correzione nota") : htmlEscape(is_en ? "fix: " : "correzione: ") + mono(htmlEscape(v.fixed)))
              << "</span>";
            if (!v.cwe_text.empty()) o << " " << chip(v.cwe_text, "#ccfbf1", "#115e59");
            o << "</div>";
          }
          o << "</td></tr>";
          first_group = false;
        }
        o << "</table></td></tr>\n";
      }
      if (r.omitted_vulns) {
        o << "<tr><td class=\"muted\" style=\"padding:0 4px 10px;font-size:13px;color:#6b7280\">" << (is_en ? "other " : "altre ") << r.omitted_vulns
          << (is_en ? " vulnerabilities not shown (lowest priority): run `dyna_cyber_agent --events`" : " vulnerabilita' non mostrate (priorita' piu' bassa): usa `dyna_cyber_agent --events`") << "</td></tr>\n";
      }
      if (!r.mitre_refs.empty() || !r.cwe_refs.empty()) {
        o << "<tr><td style=\"padding:0 0 10px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:6px\"><tr><td style=\"padding:6px 16px 12px\">";
        if (!r.mitre_refs.empty()) {
          o << label(L.mitre) << "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\">";
          for (const auto& [id, n] : r.mitre_refs) {
            const std::string name = mitreName(id);
            o << "<tr><td style=\"padding:2px 10px 2px 0;vertical-align:top\">" << chip(sanitize(id, 16), "#ede9fe", "#5b21b6") << "</td><td class=\"txt\" style=\"padding:2px 0;font-size:13px;color:#1f2937\">"
              << htmlEscape(name) << " <span class=\"muted\" style=\"color:#6b7280\">(" << n << ")</span></td></tr>";
          }
          o << "</table>";
        }
        if (!r.cwe_refs.empty()) {
          o << label(L.cwe) << "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\">";
          for (const auto& [id, n] : r.cwe_refs) {
            const auto nm = r.cwe_names.find(id);
            o << "<tr><td style=\"padding:2px 10px 2px 0;vertical-align:top\">" << chip(sanitize(id, 16), "#ccfbf1", "#115e59") << "</td><td class=\"txt\" style=\"padding:2px 0;font-size:13px;color:#1f2937\">"
              << (nm != r.cwe_names.end() ? E(nm->second, 100) : std::string()) << " <span class=\"muted\" style=\"color:#6b7280\">(" << n << ")</span></td></tr>";
          }
          o << "</table>";
        }
        o << "</td></tr></table></td></tr>\n";
      }
      if (!r.intel_lines.empty()) {
        o << "<tr><td style=\"padding:0 0 10px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:6px\"><tr><td style=\"padding:6px 16px 10px\">"
          << label(L.intel) << "<ul class=\"txt\" style=\"margin:0;padding-left:18px;font-size:13px;line-height:1.55;color:#374151\">";
        for (const auto& line : r.intel_lines) o << "<li style=\"margin:3px 0\">" << E(line, 400) << "</li>";
        o << "</ul></td></tr></table></td></tr>\n";
      }
    }

    if (!r.health.empty()) {
      o << section(L.health) << "<tr><td><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"card\" style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:6px\">";
      bool first = true;
      for (const auto& h : r.health) {
        o << "<tr><td style=\"padding:8px 14px;" << (first ? "" : "border-top:1px solid #e5e7eb;") << "font-size:13px\" class=\"txt\">"
          << (h.stale ? "<span style=\"color:#991b1b;font-weight:700\">&#9888; " : "<span>") << E(h.target, 60) << " / " << E(h.collector, 40) << "</span>"
          << " <span class=\"muted\" style=\"color:#6b7280;font-size:12px\">&middot; " << h.ok_count << " " << L.ok_runs << ", " << h.error_count << " " << L.err_runs << " &middot; "
          << htmlEscape(L.last_ok) << ": " << htmlEscape(h.last_ok ? fmtTime(h.last_ok) : L.never) << "</span>";
        if (h.stale) o << " " << chip(L.stale, "#fee2e2", "#7f1d1d");
        if (h.error_count && !h.last_error.empty()) {
          o << "<div class=\"muted\" style=\"font-size:12px;color:#6b7280;margin-top:2px\">" << htmlEscape(L.last_error) << ": " << mono(E(h.last_error, 300)) << "</div>";
        }
        o << "</td></tr>";
        first = false;
      }
      o << "</table></td></tr>\n";
    }

    o << "<tr><td class=\"muted\" style=\"padding:18px 4px 4px;font-size:12px;line-height:1.55;color:#6b7280\">" << htmlEscape(L.footer_ai) << "<br>"
      << htmlEscape(L.footer_accept) << "</td></tr>\n";
  }

  o << "</table>\n</td></tr></table>\n</body></html>\n";
  return o.str();
}

}  // namespace agent
