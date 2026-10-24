#pragma once
#include <set>
#include <string>

#include "collectors/collector.h"

namespace agent {

// What makes a machine different from the others that do the same job. Targets with the same `group:` are compared
// with each other: a user, a listening port, a kernel module, an SSH key or a program that exists on ONE machine of
// five identical web servers is worth a look even if it is part of that machine's baseline (a backdoor installed
// before monitoring started is "normal" to the baseline, but never to its peers). The reverse is reported too:
// something all the others have and this one lacks (a service that is down, a security tool that is missing).
//
// It reads what the other targets' collectors have already recorded; it never touches any machine.
class PeerCollector final : public ICollector {
 public:
  std::string name() const override { return "peers"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::minutes(30); }
  void configure(const CollectorOptions& o) override { opts_ = o; }
  Result<CollectOutput> collect(ITransport& t) override;

  // "facet|key" of everything a snapshot says about the machine, in a form that is comparable across hosts.
  static std::set<std::string> comparableItems(const Snapshot& s);

 private:
  CollectorOptions opts_;
};

}  // namespace agent
