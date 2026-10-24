#include <catch2/catch.hpp>

#include <chrono>

#include "analysis/analyzer.h"
#include "analysis/rule.h"
#include "collectors/netflow_collector.h"
#include "enrich/conn_tracker.h"
#include "fake_transport.h"

using namespace agent;

namespace {

Store::ConnSeries series(std::vector<int64_t> times, const std::string& dest = "203.0.113.50", int port = 8443) {
  Store::ConnSeries s;
  s.dest = dest;
  s.port = port;
  s.comm = "updater";
  s.times = std::move(times);
  return s;
}

std::vector<int64_t> every(int64_t period, size_t n, int64_t start = 1000, int64_t jitter = 0) {
  std::vector<int64_t> t;
  for (size_t i = 0; i < n; ++i) t.push_back(start + static_cast<int64_t>(i) * period + (i % 2 ? jitter : -jitter));
  return t;
}

Observation sock(const std::string& raddr, int rport, int lport, const std::string& state, const std::string& comm = "updater", std::vector<std::string> tags = {}) {
  Observation o;
  o.type = "socket.inet";
  o.key = "k" + raddr + std::to_string(lport);
  o.tags = std::move(tags);
  o.data = {{"proto", "tcp"}, {"local_addr", "10.0.0.5"}, {"local_port", lport}, {"remote_addr", raddr}, {"remote_port", rport}, {"state", state},
            {"owners", comm.empty() ? nlohmann::json::array() : nlohmann::json::array({{{"pid", 1}, {"comm", comm}}})}};
  return o;
}

Snapshot netSnap(int64_t ts, std::vector<Observation> obs) {
  Snapshot s;
  s.target = "web01";
  s.collector = "network";
  s.ts = ts;
  s.observations = std::move(obs);
  return s;
}

}  // namespace

TEST_CASE("beaconing: a steady pace is a beacon, a burst or a ragged one is not") {
  BeaconParams p;
  auto b = detectBeacon(series(every(60, 20)), p);
  REQUIRE(b);
  REQUIRE(b->period == Approx(60));
  REQUIRE(b->events == 20);
  REQUIRE(b->jitter == Approx(0).margin(0.01));

  REQUIRE(detectBeacon(series(every(60, 20, 1000, 5)), p));           // 5 s of wobble around a 60 s beat
  REQUIRE_FALSE(detectBeacon(series(every(60, 5)), p));               // too few
  REQUIRE_FALSE(detectBeacon(series(every(4, 40)), p));               // too fast for the polling to tell, and a short span
  REQUIRE_FALSE(detectBeacon(series(every(5000, 12)), p));            // slower than an hour
  std::vector<int64_t> ragged = {1000, 1010, 1300, 1330, 2000, 2040, 2900, 3000, 3100, 5000, 5100, 7000};
  REQUIRE_FALSE(detectBeacon(series(ragged), p));

  // parallel connections opened together count once
  std::vector<int64_t> bursts;
  for (int i = 0; i < 12; ++i) for (int k = 0; k < 4; ++k) bursts.push_back(1000 + i * 90 + k);
  auto bb = detectBeacon(series(bursts), p);
  REQUIRE(bb);
  REQUIRE(bb->events == 12);
  REQUIRE(bb->period == Approx(90));

  // one missed beat among many does not hide it
  auto t = every(60, 20);
  t.erase(t.begin() + 8);
  REQUIRE(detectBeacon(series(t), p));
}

TEST_CASE("connection tracker: only NEW outbound connections, never the ones already open") {
  ConnTracker tr;
  auto first = tr.update(netSnap(100, {sock("203.0.113.50", 443, 40001, "ESTABLISHED")}));
  REQUIRE(first.empty());  // primed: it was open before we started looking

  auto second = tr.update(netSnap(115, {sock("203.0.113.50", 443, 40001, "ESTABLISHED"), sock("198.51.100.7", 8443, 40002, "ESTABLISHED", "evil"),
                                         sock("203.0.113.50", 443, 40003, "TIME_WAIT", "")}));
  REQUIRE(second.size() == 2);
  REQUIRE(second[0].dest == "198.51.100.7");
  REQUIRE(second[0].port == 8443);
  REQUIRE(second[0].comm == "evil");
  REQUIRE(second[0].ts == 115);
  REQUIRE(second[1].dest == "203.0.113.50");  // a short connection that only shows up as TIME_WAIT is still a connection

  auto third = tr.update(netSnap(130, {sock("198.51.100.7", 8443, 40002, "ESTABLISHED", "evil")}));
  REQUIRE(third.empty());  // the same connection

  // inbound clients, listeners, loopback and local-looking traffic are not outbound connections
  Observation listen = sock("0.0.0.0", 0, 22, "LISTEN", "sshd", {"listening"});
  auto fourth = tr.update(netSnap(145, {listen, sock("192.0.2.9", 51000, 22, "ESTABLISHED", "sshd"), sock("127.0.0.1", 5432, 40010, "ESTABLISHED", "app"),
                                         sock("192.0.2.77", 80, 1234, "ESTABLISHED", "app")}));
  REQUIRE(fourth.empty());
}

TEST_CASE("traffic model: learns the usual rate, ignores bursts, calls a sustained jump") {
  TrafficModel m;
  for (int i = 0; i < 300; ++i) REQUIRE_FALSE(trafficSpike(m, 40e3 + (i % 7) * 1000.0));  // ~40 kB/s, warming up
  REQUIRE(m.ewma == Approx(43e3).margin(5e3));
  REQUIRE_FALSE(trafficSpike(m, 100e3));   // 2.5x: busy, not abnormal
  REQUIRE_FALSE(trafficSpike(m, 400e3));   // below the absolute floor of half a megabyte per second
  REQUIRE(trafficSpike(m, 5e6));            // 5 MB/s
  const double after = m.ewma;
  REQUIRE(trafficSpike(m, 5e6));
  REQUIRE(m.ewma < after * 1.5);            // a spike barely teaches the model

  TrafficModel cold;
  REQUIRE_FALSE(trafficSpike(cold, 50e6));  // no verdict before the warm-up
}

TEST_CASE("netflow: interface table and the collector") {
  const auto dev = NetflowCollector::parseNetDev(
      "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
      "    lo:  100  1 0 0 0 0 0 0   100 1 0 0 0 0 0 0\n  eth0: 5000 10 0 0 0 0 0 0  7000 12 0 0 0 0 0 0\n");
  REQUIRE(dev.size() == 2);
  REQUIRE(dev.at("eth0").first == 5000);
  REQUIRE(dev.at("eth0").second == 7000);

  auto st = Store::open(":memory:");
  Store& store = *st.value();
  const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  std::vector<Store::ConnEvent> ev;
  for (int i = 0; i < 12; ++i) ev.push_back({"198.51.100.7", "evil", 4444, now - 3600 + i * 120});
  for (int i = 0; i < 12; ++i) ev.push_back({"203.0.113.9", "browser", 443, now - 3500 + i * 37 * (i % 3 + 1)});  // irregular
  REQUIRE(store.recordConnections("web01", ev).ok());

  NetflowCollector c;
  CollectorOptions o;
  o.target = "web01";
  o.store = &store;
  o.beaconing = true;
  o.traffic_spikes = true;
  c.configure(o);
  FakeTransport t;
  t.files["/proc/net/dev"] = "h\nh\n eth0: 1 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n";
  auto r = c.collect(t);
  REQUIRE(r.ok());
  REQUIRE(r.value().observations.size() == 1);
  const auto& b = r.value().observations[0];
  REQUIRE(b.type == "net.beacon");
  REQUIRE(b.key == "beacon|198.51.100.7:4444");
  REQUIRE(b.data["period_s"] == 120);
  REQUIRE(b.data["uncommon_external"] == true);
  REQUIRE(std::find(b.tags.begin(), b.tags.end(), "external_dest") != b.tags.end());
}

TEST_CASE("netflow: the shipped rules separate an ordinary beacon from one to an odd port, and respect the baseline") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(rules.ok());
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  Analyzer an(store, rules.value(), std::chrono::seconds(1000));
  store.baselineMeta("web01", 0);
  auto snap = [](int64_t ts, const std::string& dest, int port, bool odd) {
    Snapshot s;
    s.target = "web01";
    s.collector = "netflow";
    s.ts = ts;
    Observation o;
    o.type = "net.beacon";
    o.key = "beacon|" + dest + ":" + std::to_string(port);
    o.tags = {"beacon", "external_dest"};
    o.data = {{"dest", dest}, {"port", port}, {"comm", "updater"}, {"events", 20}, {"period_s", 60}, {"jitter", 0.0}, {"uncommon_external", odd}};
    s.observations.push_back(o);
    return s;
  };
  // learned during the baseline: an update checker that has always polled
  REQUIRE(an.analyze(snap(10, "203.0.113.1", 443, false)).value().fresh.empty());
  REQUIRE(an.analyze(snap(100000, "203.0.113.1", 443, false)).value().fresh.empty());
  auto fresh = an.analyze(snap(100100, "198.51.100.7", 4444, true));
  REQUIRE(fresh.value().fresh.size() == 1);
  REQUIRE(fresh.value().fresh[0].rule_id == "NET-031");
  auto ordinary = an.analyze(snap(100200, "203.0.113.2", 443, false));
  REQUIRE(ordinary.value().fresh.size() == 1);
  REQUIRE(ordinary.value().fresh[0].rule_id == "NET-030");
}
