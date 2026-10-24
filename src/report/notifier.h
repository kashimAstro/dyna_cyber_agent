#pragma once
#include <functional>
#include <optional>

#include "report/mailer.h"
#include "report/report.h"
#include "store/store.h"

namespace agent {

// Decides when mails go out and sends them:
//  - alert mails for findings at/above alerting.min_severity (after a short delay so the LLM assessment and
//    related findings can ride along; cooldown + hourly cap prevent storms; critical skips the cooldown);
//  - a periodic digest (also when nothing happened: silence must not be mistaken for health).
// All state lives in the database, so a restart neither loses nor repeats notifications.
class Notifier {
 public:
  using Clock = std::function<int64_t()>;

  Notifier(Store& store, IMailer& mailer, AlertingConfig cfg, ReportContext ctx, Clock clock = nullptr);

  struct Outcome {
    bool alert_sent = false;
    bool digest_sent = false;
    std::string error;  // last send error, if any
  };
  // `flush` skips the alert delay (used by --once, where there is no later tick).
  Outcome tick(bool flush = false);

  // Writes the ONE AI report of a mail (headline, summary, priorities, correlations). Returns nullopt when the
  // model is unavailable: the mail then goes out without that section instead of waiting.
  using Synthesizer = std::function<std::optional<Synthesis>(const Report&)>;
  void setSynthesizer(Synthesizer s) { synthesizer_ = std::move(s); }

  Result<bool> sendTest();
  bool enabled() const { return !cfg_.recipients.empty(); }

 private:
  bool alertPass(bool flush, Outcome& out);
  bool digestPass(Outcome& out);
  Result<bool> deliver(const Report& r, const std::string& kind, const std::vector<int64_t>& finding_ids);
  int64_t nextDigestDue(int64_t last) const;
  void backoff(int slot, int64_t now);

  Store& store_;
  IMailer& mailer_;
  AlertingConfig cfg_;
  ReportContext ctx_;
  Clock clock_;
  Synthesizer synthesizer_;
  std::string cache_key_;                 // a mail that failed to send is retried with the same AI report
  std::optional<Synthesis> cache_value_;
  int failures_[2] = {0, 0};          // 0 = alert, 1 = digest
  int64_t retry_not_before_[2] = {0, 0};
};

}  // namespace agent
