#pragma once
#include <string>

#include "core/severity.h"

namespace agent::report {

struct Labels {
  const char *title_alert, *title_digest, *title_test;
  const char *top_risk, *generated, *agent_host, *period, *open_findings, *new_findings, *findings;
  const char *summary_ai, *correlations, *health, *target, *rule, *subject, *seen, *first_seen, *last_seen, *times;
  const char *assessment, *verdict, *confidence, *actions, *checks, *evidence, *not_in_baseline, *mitre, *status_new, *status_known;
  const char *flag_injection, *omitted, *quiet, *collector, *last_ok, *last_error, *stale, *ok_runs, *err_runs, *never;
  const char *footer_ai, *footer_accept, *test_body, *no_ai, *resolved, *cwe, *intel;
  const char *sev[5];                  // info .. critical
  const char *verdicts[4];             // likely_malicious, suspicious, likely_benign, needs_more_data
};

const Labels& labels(const std::string& lang);
const char* severityLabel(const Labels& l, Severity s);
const char* verdictLabel(const Labels& l, const std::string& verdict);

}  // namespace agent::report
