#pragma once
#include <optional>

#include "collectors/collector.h"

namespace agent {

struct CronEntry {
  std::string schedule, user, command;
};

struct UnitInfo {
  std::string description, user, schedule, listen;
  std::vector<std::string> exec, wanted_by;
};

// Pure parsers (exposed for tests).
// `system_format`: /etc/crontab and /etc/cron.d lines carry a user column, per-user crontabs do not.
std::vector<CronEntry> parseCrontab(const std::string& text, bool system_format);
UnitInfo parseUnitFile(const std::string& text);

// Cron jobs, systemd units, shell and login startup files, ld.so.preload: the places where an intruder makes
// something come back after a reboot or a logout.
class PersistenceCollector final : public ICollector {
 public:
  std::string name() const override { return "persistence"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::minutes(5); }
  Result<CollectOutput> collect(ITransport& t) override;
};

}  // namespace agent
