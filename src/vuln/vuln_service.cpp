#include "vuln/vuln_service.h"

#include <spdlog/spdlog.h>

#include <chrono>

namespace agent {

void VulnService::start(const std::atomic<bool>& stop) {
  if (thread_.joinable()) return;
  thread_ = std::thread([this, &stop] { loop(stop); });
}

void VulnService::join() {
  if (thread_.joinable()) thread_.join();
}

VulnService::Status VulnService::status() const {
  std::lock_guard<std::mutex> lock(mu_);
  return status_;
}

void VulnService::loop(const std::atomic<bool>& stop) {
  auto sleepFor = [&](std::chrono::seconds s) {
    const auto until = std::chrono::steady_clock::now() + s;
    while (!stop && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(std::chrono::milliseconds(500));
  };
  sleepFor(std::chrono::seconds(20));  // let the collectors start first
  while (!stop) {
    spdlog::info("vulnerability feeds: synchronisation started");
    auto reports = sync_.syncAll();
    bool retry_soon = false;
    for (const auto& r : reports) {
      if (r.ok && !r.partial) spdlog::info("vulnerability feed {}: {}", r.feed, r.message);
      else spdlog::warn("vulnerability feed {}: {}", r.feed, r.message);
      retry_soon |= !r.ok || r.partial;
      if (!r.new_kev.empty()) {
        std::string ids;
        for (size_t i = 0; i < r.new_kev.size() && i < 10; ++i) ids += (i ? ", " : "") + r.new_kev[i];
        spdlog::warn("CISA KEV: {} newly exploited vulnerabilit{} ({})", r.new_kev.size(), r.new_kev.size() == 1 ? "y" : "ies", ids);
        if (on_new_kev_) on_new_kev_(r.new_kev);
      }
    }
    {
      std::lock_guard<std::mutex> lock(mu_);
      status_.last_run = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
      status_.reports = std::move(reports);
    }
    if (stop) break;
    // a cold NVD download or a failed feed continues soon; otherwise the regular interval applies
    sleepFor(retry_soon ? std::min(cfg_.refresh_every, std::chrono::seconds(1800)) : cfg_.refresh_every);
  }
}

}  // namespace agent
