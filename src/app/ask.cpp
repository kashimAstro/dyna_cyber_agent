#include "app/ask.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <map>

#include "llm/context.h"
#include "llm/prompt.h"
#include "report/text_util.h"

namespace agent {
namespace {

constexpr int64_t kDay = 86400;
constexpr int64_t kMaxWindow = 90 * kDay;
constexpr size_t kMaxFindings = 40;
constexpr size_t kMaxIncidents = 8;
constexpr size_t kMaxPackageEvents = 40;

// lower case, accents folded to ASCII, apostrophes dropped: "martedì" and "martedi'" both become "martedi"
std::string fold(const std::string& s) {
  static const std::map<std::string, char> accents = {{"à", 'a'}, {"á", 'a'}, {"è", 'e'}, {"é", 'e'}, {"ì", 'i'}, {"í", 'i'}, {"ò", 'o'}, {"ó", 'o'}, {"ù", 'u'}, {"ú", 'u'},
                                                       {"À", 'a'}, {"È", 'e'}, {"É", 'e'}, {"Ì", 'i'}, {"Ò", 'o'}, {"Ù", 'u'}};
  std::string out;
  for (size_t i = 0; i < s.size();) {
    bool done = false;
    if (static_cast<unsigned char>(s[i]) >= 0x80 && i + 1 < s.size()) {
      const auto it = accents.find(s.substr(i, 2));
      if (it != accents.end()) {
        out += it->second;
        i += 2;
        done = true;
      }
    }
    if (done) continue;
    const char c = s[i++];
    if (c == '\'' || c == '`') {  // "nell'ultima" is two words; "martedi'" and "e'" are accents written as an apostrophe
      if (i < s.size() && std::isalpha(static_cast<unsigned char>(s[i]))) out += ' ';
      continue;
    }
    out += std::isalnum(static_cast<unsigned char>(c)) || c == ' ' ? static_cast<char>(std::tolower(static_cast<unsigned char>(c))) : ' ';
  }
  return out;
}

std::vector<std::string> words(const std::string& folded) {
  std::vector<std::string> w;
  std::string cur;
  for (char c : folded + " ") {
    if (c == ' ') {
      if (!cur.empty()) w.push_back(cur);
      cur.clear();
    } else {
      cur += c;
    }
  }
  return w;
}

bool isFrom(const std::string& w) { return w == "da" || w == "dal" || w == "dalla" || w == "dallo" || w == "dai" || w == "since" || w == "from" || w == "after" || w == "dopo"; }

int weekdayOf(const std::string& w) {  // 0 = Sunday, as in struct tm
  static const std::vector<std::vector<std::string>> names = {{"domenica", "sunday"},  {"lunedi", "monday"},   {"martedi", "tuesday"}, {"mercoledi", "wednesday"},
                                                              {"giovedi", "thursday"}, {"venerdi", "friday"}, {"sabato", "saturday"}};
  for (size_t d = 0; d < names.size(); ++d) {
    if (w == names[d][0] || w == names[d][1]) return static_cast<int>(d);
  }
  return -1;
}

std::tm localTm(int64_t ts) {
  const std::time_t t = static_cast<std::time_t>(ts);
  std::tm tm{};
  localtime_r(&t, &tm);
  return tm;
}

int64_t startOfDay(int64_t ts, int days_back = 0) {
  std::tm tm = localTm(ts);
  tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
  tm.tm_mday -= days_back;
  tm.tm_isdst = -1;
  return static_cast<int64_t>(std::mktime(&tm));
}

std::string stamp(int64_t ts, bool en) {
  static const char* wd_it[] = {"domenica", "lunedi", "martedi", "mercoledi", "giovedi", "venerdi", "sabato"};
  static const char* wd_en[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
  static const char* mo_it[] = {"gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"};
  static const char* mo_en[] = {"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"};
  const std::tm tm = localTm(ts);
  char hm[16];
  std::strftime(hm, sizeof(hm), "%H:%M", &tm);
  return std::string(en ? wd_en[tm.tm_wday] : wd_it[tm.tm_wday]) + " " + std::to_string(tm.tm_mday) + " " + (en ? mo_en[tm.tm_mon] : mo_it[tm.tm_mon]) + " " +
         std::to_string(tm.tm_year + 1900) + " " + hm;
}

}  // namespace

AskWindow parseAskWindow(const std::string& question, int64_t now, const std::string& language) {
  const bool en = language == "en";
  const auto w = words(fold(question));
  AskWindow out;
  out.to = now;
  int64_t from = 0, to = now;
  bool found = false;

  const auto number_after = [&](size_t i) -> int64_t {  // "ultime 36 ore": the number right after the word at i
    if (i + 1 < w.size() && !w[i + 1].empty() && std::all_of(w[i + 1].begin(), w[i + 1].end(), [](unsigned char c) { return std::isdigit(c); })) {
      try { return std::stoll(w[i + 1]); } catch (...) { return 0; }
    }
    return 0;
  };

  for (size_t i = 0; i < w.size() && !found; ++i) {
    const std::string& x = w[i];
    const bool from_before = i > 0 && isFrom(w[i - 1]);
    if (x == "ultime" || x == "ultimi" || x == "ultimo" || x == "ultima" || x == "last" || x == "past" || x == "scorse" || x == "scorsi") {
      const int64_t n = number_after(i);
      const std::string unit = i + (n ? 2 : 1) < w.size() ? w[i + (n ? 2 : 1)] : "";
      const int64_t k = n ? n : 1;
      if (unit == "ora" || unit == "ore" || unit == "hour" || unit == "hours") { from = now - k * 3600; found = true; }
      else if (unit == "minuti" || unit == "minuto" || unit == "minutes" || unit == "minute") { from = now - k * 60; found = true; }
      else if (unit == "giorno" || unit == "giorni" || unit == "day" || unit == "days") { from = now - k * kDay; found = true; }
      else if (unit == "settimana" || unit == "settimane" || unit == "week" || unit == "weeks") { from = now - k * 7 * kDay; found = true; }
      else if (unit == "mese" || unit == "mesi" || unit == "month" || unit == "months") { from = now - k * 30 * kDay; found = true; }
    } else if (x == "oggi" || x == "today") {
      from = startOfDay(now);
      found = true;
    } else if (x == "ieri" || x == "yesterday") {
      from = startOfDay(now, 1);
      if (!from_before) to = startOfDay(now);  // "ieri" alone is the whole of yesterday; "da ieri" runs until now
      found = true;
    } else if ((x == "questa" || x == "this") && i + 1 < w.size() && (w[i + 1] == "settimana" || w[i + 1] == "week")) {
      const int back = (localTm(now).tm_wday + 6) % 7;  // days since Monday
      from = startOfDay(now, back);
      found = true;
    } else if (weekdayOf(x) >= 0) {
      const int wd = weekdayOf(x);
      int back = (localTm(now).tm_wday - wd + 7) % 7;
      if (back == 0) back = 7;  // the same weekday as today means last week's
      from = startOfDay(now, back);
      if (!from_before) to = startOfDay(now, back - 1);  // "martedi" alone is that one day
      found = true;
    }
  }

  if (!found) {
    from = now - 7 * kDay;
    out.detected = false;
  } else {
    out.detected = true;
  }
  if (from < now - kMaxWindow) from = now - kMaxWindow;
  if (to > now) to = now;
  if (from >= to) from = to - 3600;
  out.from = from;
  out.to = to;
  if (!out.detected) {
    out.label = en ? "the last 7 days (default: the question names no period)" : "gli ultimi 7 giorni (predefinito: la domanda non indica un periodo)";
  } else {
    out.label = (en ? "from " : "da ") + stamp(from, en) + (en ? " to " : " a ") + (to >= now - 60 ? (en ? "now" : "ora") : stamp(to, en));
  }
  return out;
}

std::vector<std::string> askTargets(const std::string& question, const std::vector<std::string>& configured) {
  const std::string q = fold(question);
  std::vector<std::string> out;
  for (const auto& name : configured) {
    const std::string n = fold(name);
    if (n.empty()) continue;
    for (size_t at = q.find(n); at != std::string::npos; at = q.find(n, at + 1)) {
      const bool left = at == 0 || !std::isalnum(static_cast<unsigned char>(q[at - 1]));
      const bool right = at + n.size() >= q.size() || !std::isalnum(static_cast<unsigned char>(q[at + n.size()]));
      if (left && right) {
        out.push_back(name);
        break;
      }
    }
  }
  return out;
}

std::string askLanguage(const std::string& question, const std::string& fallback) {
  const auto w = words(fold(question));
  int it = 0, en = 0;
  for (const auto& x : w) {
    if (x == "cosa" || x == "che" || x == "chi" || x == "perche" || x == "come" || x == "quali" || x == "quanti" || x == "sono" || x == "stato" || x == "sulla" || x == "sul" ||
        x == "dal" || x == "ultime" || x == "ultimi" || x == "ieri" || x == "oggi" || x == "mostra" || x == "dimmi" || x == "ci" || x == "della" || x == "nel" || x == "sulle")
      ++it;
    if (x == "what" || x == "who" || x == "why" || x == "how" || x == "which" || x == "the" || x == "since" || x == "changed" || x == "show" || x == "tell" || x == "did" ||
        x == "has" || x == "were" || x == "was" || x == "last" || x == "yesterday" || x == "today" || x == "on" || x == "happened")
      ++en;
  }
  if (it > en) return "it";
  if (en > it) return "en";
  return fallback == "en" ? "en" : "it";
}

AskContext gatherAskContext(Store& store, const std::vector<std::string>& targets, const std::vector<std::string>& configured, const AskWindow& window) {
  using nlohmann::json;
  AskContext ctx;
  ctx.window = window;
  ctx.targets = targets.empty() ? configured : targets;
  const auto inTargets = [&](const std::string& t) { return std::find(ctx.targets.begin(), ctx.targets.end(), t) != ctx.targets.end(); };

  json findings = json::array();
  size_t n_new = 0, n_open = 0, n_resolved = 0, n_accepted = 0;
  std::vector<Finding> all;
  for (const auto& t : ctx.targets) {
    auto r = store.findingsActive(window.from, window.to, t, 400);
    if (r) for (auto& f : r.value()) all.push_back(std::move(f));
  }
  std::stable_sort(all.begin(), all.end(), [](const Finding& a, const Finding& b) { return a.severity != b.severity ? a.severity > b.severity : a.last_seen > b.last_seen; });
  ctx.findings_total = all.size();
  for (const auto& f : all) {
    const bool fresh = f.first_seen >= window.from;
    if (fresh) ++n_new;
    if (f.status == "open") ++n_open;
    else if (f.status == "resolved") ++n_resolved;
    else if (f.status == "accepted") ++n_accepted;
    if (findings.size() >= kMaxFindings) continue;
    json j = findingForPrompt(f, true);
    j.erase("rule_description");  // 40 findings must fit the model's context: the title says what the rule is
    j.erase("first_seen_utc");
    j.erase("last_seen_utc");
    j["target"] = f.target;
    j["severity"] = toString(f.severity);
    j["status"] = f.status;
    j["first_seen"] = report::fmtTime(f.first_seen);
    j["last_seen"] = report::fmtTime(f.last_seen);
    j["new_in_period"] = fresh;
    if (f.status == "accepted") {
      if (auto a = store.acceptanceOf(f.id); a && a.value() && !a.value()->note.empty()) j["accepted_note"] = report::sanitize(a.value()->note, 200);
    }
    findings.push_back(std::move(j));
    ctx.finding_ids.push_back(f.id);
  }
  ctx.findings_shown = findings.size();

  json incidents = json::array();
  if (auto inc = store.listIncidents("", 60)) {
    for (const auto& i : inc.value()) {
      if (incidents.size() >= kMaxIncidents) break;
      if (i.last_ts < window.from || i.first_ts > window.to) continue;
      bool mine = false;
      for (const auto& t : i.targets) if (t.is_string() && inTargets(t.get<std::string>())) mine = true;
      if (!mine) continue;
      incidents.push_back({{"incident_id", i.id}, {"title", report::sanitize(i.title, 200)}, {"severity", toString(i.severity)}, {"status", i.status},
                           {"first", report::fmtTime(i.first_ts)}, {"last", report::fmtTime(i.last_ts)}, {"stages", i.stages}, {"shared", i.entities},
                           {"finding_ids", i.finding_ids}});
    }
  }

  json packages = json::array();
  size_t pkg_total = 0;
  for (const auto& t : ctx.targets) {
    auto ev = store.packageEvents(t, window.from, 400);
    if (!ev) continue;
    for (const auto& e : ev.value()) {
      if (e.ts > window.to || e.kind == "inventory") continue;
      ++pkg_total;
      if (packages.size() < kMaxPackageEvents) {
        packages.push_back({{"target", t}, {"time", report::fmtTime(e.ts)}, {"package", report::sanitize(e.package, 80)}, {"change", e.kind},
                            {"from_version", report::sanitize(e.old_version, 60)}, {"to_version", report::sanitize(e.new_version, 60)}});
      }
    }
  }

  json problems = json::array();
  if (auto h = store.collectorHealth(window.from)) {
    for (const auto& c : h.value()) {
      if (!inTargets(c.target) || c.error_count == 0) continue;
      problems.push_back({{"target", c.target}, {"collector", c.collector}, {"errors", c.error_count}, {"ok_runs", c.ok_count},
                          {"last_error", report::sanitize(c.last_error, 160)}, {"last_error_time", report::fmtTime(c.last_error_ts)}});
    }
  }

  json sources = json::array();
  for (const auto& t : ctx.targets) {
    auto s = store.listSources(window.from, t, 5);
    if (!s) continue;
    for (const auto& r : s.value()) {
      if (r.last_ts > window.to) continue;
      sources.push_back({{"target", t}, {"address", r.ip}, {"ssh_failures", r.ssh_fail}, {"ssh_logins", r.ssh_ok}, {"scans", r.scans}, {"web_hits", r.web_hits}, {"web_4xx", r.web_4xx}});
    }
  }

  size_t mails = 0;
  if (auto n = store.listNotifications(100)) {
    for (const auto& m : n.value()) if (m.status == "sent" && m.kind != "test" && m.created_at >= window.from && m.created_at <= window.to) ++mails;
  }

  ctx.facts = {{"note", "all times are UTC; every number below was computed by the agent from its own database"},
               {"period", {{"from", report::fmtTime(window.from)}, {"to", report::fmtTime(window.to)}, {"described_as", window.label}, {"named_in_question", window.detected}}},
               {"machines", ctx.targets},
               {"counts", {{"findings_active_in_period", ctx.findings_total}, {"first_seen_in_period", n_new}, {"open_now", n_open}, {"resolved", n_resolved},
                           {"accepted_as_normal", n_accepted}, {"incidents", incidents.size()}, {"package_changes", pkg_total}, {"mails_sent", mails}}},
               {"findings", findings},
               {"findings_not_shown", ctx.findings_total - ctx.findings_shown},
               {"incidents", incidents},
               {"package_changes", packages},
               {"package_changes_not_shown", pkg_total - packages.size()},
               {"attack_sources_top", sources},
               {"collection_problems", problems}};
  return ctx;
}

}  // namespace agent
