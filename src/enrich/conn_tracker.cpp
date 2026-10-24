#include "enrich/conn_tracker.h"

#include <set>

#include "core/util.h"

namespace agent {
namespace {

constexpr int64_t kForget = 300;  // seconds; longer than TIME_WAIT (60 s) plus a few polls
constexpr int kEphemeralFrom = 32768;

bool loopbackOrAny(const std::string& a) { return a.empty() || a == "0.0.0.0" || a == "::" || a == "::1" || util::startsWith(a, "127."); }

}  // namespace

std::vector<Store::ConnEvent> ConnTracker::update(const Snapshot& net) {
  std::vector<Store::ConnEvent> events;
  std::set<int> listening_ports;
  for (const auto& o : net.observations) {
    if (o.type == "socket.inet" && std::find(o.tags.begin(), o.tags.end(), "listening") != o.tags.end()) listening_ports.insert(o.data.value("local_port", 0));
  }
  for (const auto& o : net.observations) {
    if (o.type != "socket.inet") continue;
    const std::string proto = o.data.value("proto", std::string());
    if (proto != "tcp" && proto != "tcp6") continue;
    const std::string remote = o.data.value("remote_addr", std::string());
    const int rport = o.data.value("remote_port", 0), lport = o.data.value("local_port", 0);
    const std::string state = o.data.value("state", std::string());
    if (state == "LISTEN" || rport == 0 || loopbackOrAny(remote)) continue;
    if (lport < kEphemeralFrom || listening_ports.count(lport)) continue;  // inbound: a client talking to one of our services
    const std::string key = proto + "|" + remote + ":" + std::to_string(rport) + "|" + std::to_string(lport);
    const bool known = seen_.count(key) > 0;
    seen_[key] = net.ts;
    if (known || !primed_) continue;
    std::string comm;
    if (o.data.contains("owners") && o.data["owners"].is_array() && !o.data["owners"].empty()) comm = o.data["owners"][0].value("comm", std::string());
    events.push_back({remote, comm, rport, net.ts});
  }
  for (auto it = seen_.begin(); it != seen_.end();) it = net.ts - it->second > kForget ? seen_.erase(it) : std::next(it);
  primed_ = true;
  return events;
}

}  // namespace agent
