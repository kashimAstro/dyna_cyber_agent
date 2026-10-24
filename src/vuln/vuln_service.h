#pragma once
#include <atomic>
#include <functional>
#include <mutex>
#include <thread>

#include "vuln/feed_sync.h"

namespace agent {

// Background refresh of the vulnerability feeds: one thread, sleeping most of the time. A cold NVD download
// continues across runs (it is resumable), a failed one is retried sooner than the regular interval.
class VulnService {
 public:
  using NewKevHook = std::function<void(const std::vector<std::string>&)>;

  VulnService(FeedSync& sync, VulnConfig cfg, NewKevHook on_new_kev = nullptr) : sync_(sync), cfg_(std::move(cfg)), on_new_kev_(std::move(on_new_kev)) {}
  ~VulnService() { join(); }

  void start(const std::atomic<bool>& stop);
  void join();

  struct Status {
    int64_t last_run = 0;
    std::vector<SyncReport> reports;
  };
  Status status() const;

 private:
  void loop(const std::atomic<bool>& stop);

  FeedSync& sync_;
  VulnConfig cfg_;
  NewKevHook on_new_kev_;
  std::thread thread_;
  mutable std::mutex mu_;
  Status status_;
};

}  // namespace agent
