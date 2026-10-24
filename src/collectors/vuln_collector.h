#pragma once
#include "collectors/collector.h"

namespace agent {

// Matches a target's software inventory (the latest `packages` snapshot) against the local vulnerability
// database. It reads no data from the target itself: the work happens on the agent's machine. Pseudo-collector:
// the transport is not used.
class VulnCollector final : public ICollector {
 public:
  std::string name() const override { return "vulns"; }
  std::chrono::seconds defaultInterval() const override { return interval_; }
  void configure(const CollectorOptions& o) override;
  Result<CollectOutput> collect(ITransport& t) override;

 private:
  CollectorOptions opts_;
  std::chrono::seconds interval_{3600};
};

}  // namespace agent
