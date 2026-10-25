#include "report/notifier.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <set>

namespace agent {
namespace {

int64_t systemNow() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string domainOf(const std::string& mailbox) {
  const std::string a = addressOf(mailbox);
  const size_t at = a.rfind('@');
  return at == std::string::npos ? "localhost" : a.substr(at + 1);
}

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// The same mailbox listed twice (or with different capitalisation) would receive every mail twice.
std::vector<std::string> uniqueRecipients(const std::vector<std::string>& in) {
  std::vector<std::string> out;
  std::set<std::string> seen;
  for (const auto& r : in) {
    if (seen.insert(lower(addressOf(r))).second) out.push_back(r);
    else spdlog::warn("alerting.recipients lists '{}' more than once: ignoring the duplicate", addressOf(r));
  }
  return out;
}

std::string joinRecipients(const std::vector<std::string>& r) {
  std::string s;
  for (const auto& x : r) s += (s.empty() ? "" : ", ") + x;
  return s;
}

}  // namespace

Notifier::Notifier(Store& store, IMailer& mailer, AlertingConfig cfg, ReportContext ctx, Clock clock)
    : store_(store), mailer_(mailer), cfg_(std::move(cfg)), ctx_(std::move(ctx)), clock_(clock ? std::move(clock) : Clock(systemNow)) {
  cfg_.recipients = uniqueRecipients(cfg_.recipients);
  ctx_.lang = cfg_.language;
  ctx_.subject_prefix = cfg_.subject_prefix;
}

void Notifier::backoff(int slot, int64_t now) {
  ++failures_[slot];
  const int shift = std::min(failures_[slot] - 1, 4);
  retry_not_before_[slot] = now + std::min<int64_t>(3600, 300LL << shift);  // 5, 10, 20, 40, 60 minutes
}

Result<bool> Notifier::deliver(const Report& report, const std::string& kind, const std::vector<int64_t>& finding_ids) {
  const int64_t now = clock_();
  Report r = report;
  if (synthesizer_ && r.kind != Report::Kind::Test && (!r.items.empty() || !r.vuln_items.empty() || !r.carry_over.empty())) {
    std::string key = kind;
    for (const auto* list : {&r.items, &r.vuln_items, &r.carry_over}) for (const auto& it : *list) key += "," + std::to_string(it.finding.id);
    if (key == cache_key_ && cache_value_) {
      r.synthesis = cache_value_;
    } else {
      r.synthesis = synthesizer_(r);
      cache_key_ = key;
      cache_value_ = r.synthesis;
    }
  }
  MailMessage m;
  m.from = cfg_.smtp.from;
  m.to = cfg_.recipients;
  m.subject = reportSubject(r);
  m.text = renderText(r);
  m.html = renderHtml(r);
  m.importance = r.top;
  m.date = now;
  m.message_id_domain = domainOf(cfg_.smtp.from);

  Store::Notification n;
  n.kind = kind;
  n.created_at = now;
  n.subject = m.subject;
  n.recipients = joinRecipients(m.to);
  n.finding_ids = finding_ids;
  if (r.synthesis) n.summary = r.synthesis->headline + " - " + r.synthesis->summary;

  auto sent = mailer_.send(m);
  n.status = sent ? "sent" : "failed";
  if (!sent) n.error = sent.error();
  auto id = store_.recordNotification(n);
  if (!sent) return err(sent.error());
  if (!id) {
    spdlog::error("mail sent but could not be recorded: {}", id.error());
    return err(id.error());
  }
  cache_key_.clear();
  cache_value_.reset();
  if (kind == "alert") {
    if (auto r2 = store_.markAlerted(finding_ids, id.value(), now); !r2) spdlog::error("cannot mark findings as alerted: {}", r2.error());
  }
  return true;
}

bool Notifier::alertPass(bool flush, Outcome& out) {
  const int64_t now = clock_();
  if (now < retry_not_before_[0]) return false;

  auto pending = store_.listUnalerted(5000);
  if (!pending) {
    spdlog::error("alert pass: {}", pending.error());
    return false;
  }
  const Severity threshold = *parseSeverity(cfg_.min_severity);
  std::vector<Finding> eligible;
  Severity top = Severity::Info;
  for (auto& f : pending.value()) {
    auto a = store_.latestAssessment(f.id);
    std::optional<Assessment> as = a && a.value() ? a.value() : std::nullopt;
    const Severity eff = effectiveSeverity(f, as);
    if (eff < threshold) continue;
    // Long-standing vulnerabilities are a to-do list, not an emergency: they travel in the digest only.
    if (isVulnFinding(f) && hasTag(f, "established")) continue;
    // A new program that a package upgrade just installed is reported in the digest, not as an emergency. Critical ones still alert.
    if (hasTag(f, "explained_by_update") && eff < Severity::Critical) continue;
    // Give the LLM (and related findings) a chance to arrive first; never hold a finding forever.
    // Vulnerabilities are never assessed by the model, so they do not wait for it.
    const bool ready = flush || isVulnFinding(f) || as.has_value() || !ctx_.llm_enabled || now - f.first_seen >= cfg_.alert_delay.count();
    if (!ready) continue;
    top = std::max(top, eff);
    eligible.push_back(std::move(f));
  }
  // A chain of findings that together reach the threshold is an alert even when every piece alone is below it.
  if (auto incs = store_.listIncidents("open", 200)) {
    std::set<int64_t> have;
    for (const auto& f : eligible) have.insert(f.id);
    for (const auto& inc : incs.value()) {
      if (inc.severity < threshold) continue;
      for (auto& f : pending.value()) {
        if (f.id == 0 || have.count(f.id)) continue;
        if (std::find(inc.finding_ids.begin(), inc.finding_ids.end(), f.id) == inc.finding_ids.end()) continue;
        if (isVulnFinding(f)) continue;
        const bool ready = flush || !ctx_.llm_enabled || now - f.first_seen >= cfg_.alert_delay.count();
        if (!ready) continue;
        top = std::max(top, inc.severity);
        have.insert(f.id);
        eligible.push_back(f);
      }
      top = std::max(top, inc.severity);
    }
  }
  if (eligible.empty()) return false;

  if (auto sent = store_.countNotifications("alert", "sent", now - 3600); sent && sent.value() >= static_cast<size_t>(cfg_.max_per_hour)) {
    spdlog::warn("alert rate cap reached ({} mails/hour): {} finding(s) held back", cfg_.max_per_hour, eligible.size());
    return false;
  }
  if (auto last = store_.lastNotificationTime("alert", "sent"); last && last.value() && top < Severity::Critical &&
                                                              now - *last.value() < cfg_.cooldown.count() && !flush) {
    return false;  // batching: they will ride in the next mail
  }

  auto report = buildAlertReport(store_, eligible, ctx_, now);
  if (!report) {
    spdlog::error("cannot build alert report: {}", report.error());
    return false;
  }
  // Everything eligible is in this mail (what does not fit is counted in "other N"), so all of it counts as
  // reported: nothing is drip-fed into later mails.
  std::vector<int64_t> shown;
  for (const auto& f : eligible) shown.push_back(f.id);

  auto d = deliver(report.value(), "alert", shown);
  if (!d) {
    out.error = d.error();
    backoff(0, now);
    spdlog::error("alert mail failed ({} finding(s), retry in {}s): {}", shown.size(), retry_not_before_[0] - now, d.error());
    return false;
  }
  failures_[0] = 0;
  spdlog::info("alert mail sent: {} finding(s), top severity {}", shown.size(), toString(report.value().top));
  return true;
}

int64_t Notifier::nextDigestDue(int64_t last) const {
  if (cfg_.digest_at.empty()) return last + cfg_.digest_every.count();
  const std::time_t t = static_cast<std::time_t>(last);
  std::tm tm{};
  localtime_r(&t, &tm);
  tm.tm_hour = std::stoi(cfg_.digest_at.substr(0, 2));
  tm.tm_min = std::stoi(cfg_.digest_at.substr(3, 2));
  tm.tm_sec = 0;
  tm.tm_isdst = -1;
  std::time_t next = std::mktime(&tm);
  if (next <= t) {
    tm.tm_mday += 1;
    tm.tm_isdst = -1;
    next = std::mktime(&tm);
  }
  return static_cast<int64_t>(next);
}

bool Notifier::digestPass(Outcome& out) {
  if (!cfg_.digest_enabled) return false;
  const int64_t now = clock_();
  if (now < retry_not_before_[1]) return false;

  int64_t last = now;
  auto meta = store_.getMeta("digest_last");
  if (!meta) {
    spdlog::error("digest pass: {}", meta.error());
    return false;
  }
  if (meta.value()) {
    last = std::stoll(*meta.value());
  } else {
    store_.setMeta("digest_last", std::to_string(now));  // anchor: the first digest comes one period after the first start
  }
  if (now < nextDigestDue(last)) return false;

  auto report = buildDigestReport(store_, last, now, *parseSeverity(cfg_.digest_min_severity), ctx_);
  if (!report) {
    spdlog::error("cannot build digest: {}", report.error());
    return false;
  }
  // Nothing new and nothing solved: the previous reports still describe the situation.
  const bool quiet = report.value().new_in_period == 0 && report.value().resolved_in_period == 0;
  const bool all_healthy = std::none_of(report.value().health.begin(), report.value().health.end(), [](const HealthRow& h) { return h.stale; });
  if (quiet && all_healthy && !cfg_.digest_when_empty) {
    store_.setMeta("digest_last", std::to_string(now));
    return false;
  }
  auto d = deliver(report.value(), "digest", {});
  if (!d) {
    out.error = d.error();
    backoff(1, now);
    spdlog::error("digest mail failed (retry in {}s): {}", retry_not_before_[1] - now, d.error());
    return false;
  }
  failures_[1] = 0;
  store_.setMeta("digest_last", std::to_string(now));
  spdlog::info("digest mail sent ({} open finding(s))", report.value().open_total);
  return true;
}

Notifier::Outcome Notifier::tick(bool flush) {
  Outcome out;
  if (!enabled()) return out;
  // "Pause the mails" from the settings page: findings keep accumulating and go out in the first mail after the pause.
  if (auto p = store_.getMeta("mail_pause_until"); p && p.value() && std::atoll(p.value()->c_str()) > clock_()) return out;
  out.alert_sent = alertPass(flush, out);
  if (!flush) out.digest_sent = digestPass(out);
  return out;
}

Result<bool> Notifier::sendTest() {
  const Report r = buildTestReport(ctx_, clock_());
  return deliver(r, "test", {});
}

}  // namespace agent
