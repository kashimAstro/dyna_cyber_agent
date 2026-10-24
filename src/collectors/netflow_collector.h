#pragma once
#include <map>
#include <optional>
#include <string>

#include "collectors/collector.h"
#include "store/store.h"

namespace agent {

struct BeaconParams {
  size_t min_events = 8;
  int64_t min_span = 600;     // seconds between the first and the last connection
  double max_jitter = 0.25;   // allowed spread of the interval, as a fraction of it
  int64_t min_period = 20;
  int64_t max_period = 3600;
  int64_t sample = 15;        // how often the network is sampled: connections cannot be timed better than this
};

struct Beacon {
  std::string dest, comm;
  int port = 0;
  size_t events = 0;
  double period = 0, jitter = 0;
  int64_t first = 0, last = 0;
};

// Connections to the same address at a steady pace are how malware asks "any orders?". Real clients are bursty;
// software that polls (updates, monitoring) is learned in the baseline like everything else.
std::optional<Beacon> detectBeacon(const Store::ConnSeries& s, const BeaconParams& p);

// Outbound traffic rate against what is normal for the interface (an exponentially weighted average kept across restarts).
struct TrafficModel {
  double ewma = 0, var = 0;
  int64_t samples = 0;
};
// Returns true when `rate` (bytes/s) is far above the model; always updates the model afterwards.
bool trafficSpike(TrafficModel& m, double rate);

// What a target sends to the outside, seen from the agent's own records:
//   beaconing  (needs the connection events recorded from the `network` snapshots)
//   traffic    (/proc/net/dev: bytes sent per interface, compared with its usual rate)
class NetflowCollector final : public ICollector {
 public:
  std::string name() const override { return "netflow"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::minutes(2); }
  void configure(const CollectorOptions& o) override { opts_ = o; }
  Result<CollectOutput> collect(ITransport& t) override;

  static std::map<std::string, std::pair<uint64_t, uint64_t>> parseNetDev(const std::string& text);  // iface -> {rx_bytes, tx_bytes}

 private:
  struct Last { uint64_t tx = 0; int64_t ts = 0; };
  CollectorOptions opts_;
  std::map<std::string, Last> last_;
  std::map<std::string, int> hot_;  // consecutive samples above the model
};

}  // namespace agent
