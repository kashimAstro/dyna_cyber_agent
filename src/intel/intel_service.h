#pragma once
#include <atomic>
#include <thread>

#include "intel/threat_intel.h"

namespace agent {

// Keeps the threat lists fresh: one thread that sleeps almost all the time.
class IntelService {
 public:
  IntelService(ThreatIntel& ti, IHttpClient& http, ThreatIntelConfig cfg) : ti_(ti), http_(http), cfg_(std::move(cfg)) {}
  ~IntelService() { join(); }
  void start(const std::atomic<bool>& stop);
  void join();

 private:
  void loop(const std::atomic<bool>& stop);

  ThreatIntel& ti_;
  IHttpClient& http_;
  ThreatIntelConfig cfg_;
  std::thread thread_;
};

}  // namespace agent
