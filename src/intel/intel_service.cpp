#include "intel/intel_service.h"

#include <spdlog/spdlog.h>

#include <chrono>

namespace agent {

void IntelService::start(const std::atomic<bool>& stop) {
  if (thread_.joinable()) return;
  thread_ = std::thread([this, &stop] { loop(stop); });
}

void IntelService::join() {
  if (thread_.joinable()) thread_.join();
}

void IntelService::loop(const std::atomic<bool>& stop) {
  const auto sleepFor = [&](std::chrono::seconds s) {
    for (auto until = std::chrono::steady_clock::now() + s; !stop && std::chrono::steady_clock::now() < until;) std::this_thread::sleep_for(std::chrono::milliseconds(500));
  };
  sleepFor(std::chrono::seconds(20));  // let the agent start collecting first
  while (!stop) {
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    size_t ok = 0, failed = 0, ranges = 0;
    for (const auto& r : ti_.refresh(http_, now, cfg_.refresh_every.count(), std::chrono::seconds(60))) {
      if (r.ok) { ++ok; ranges += r.ranges; } else { ++failed; }
    }
    spdlog::info("threat lists: {} ready ({} ranges), {} failed", ok, ranges, failed);
    sleepFor(std::chrono::minutes(failed ? 30 : 60));  // a failed list is retried sooner; the age check inside refresh() skips fresh ones
  }
}

}  // namespace agent
