#include <catch2/catch.hpp>

#include "app/format.h"
#include "collectors/collector.h"
#include "fake_transport.h"
#include "store/store.h"

using namespace agent;

TEST_CASE("store round-trips snapshots") {
  auto st = Store::open(":memory:");
  REQUIRE(st.ok());
  auto& store = *st.value();

  Snapshot s;
  s.target = "t1";
  s.collector = "processes";
  s.ts = 1000;
  s.warnings = {"w1"};
  s.observations.push_back({"process", "1:5", {{"pid", 1}, {"comm", "init"}}, {"a", "b"}});
  s.observations.push_back({"process", "2:6", {{"pid", 2}}, {}});
  REQUIRE(store.save(s).ok());

  auto got = store.latest("t1", "processes");
  REQUIRE(got.ok());
  REQUIRE(got.value().has_value());
  const auto& g = *got.value();
  REQUIRE(g.ts == 1000);
  REQUIRE(g.warnings == std::vector<std::string>{"w1"});
  REQUIRE(g.observations.size() == 2);
  REQUIRE(g.observations[0].tags == std::vector<std::string>{"a", "b"});
  REQUIRE(g.observations[0].data["comm"] == "init");
  REQUIRE(g.observations[1].tags.empty());

  REQUIRE_FALSE(store.latest("t1", "network").value().has_value());
  REQUIRE_FALSE(store.latest("other", "processes").value().has_value());
}

TEST_CASE("latest ignores failed snapshots; prune cascades") {
  auto st = Store::open(":memory:");
  auto& store = *st.value();
  Snapshot ok;
  ok.target = "t";
  ok.collector = "c";
  ok.ts = 100;
  ok.observations.push_back({"x", "k", {}, {}});
  Snapshot bad;
  bad.target = "t";
  bad.collector = "c";
  bad.ts = 200;
  bad.error = "boom";
  store.save(ok);
  store.save(bad);
  REQUIRE(store.latest("t", "c").value()->ts == 100);

  REQUIRE(store.prune(150).value() == 1);
  REQUIRE_FALSE(store.latest("t", "c").value().has_value());
}

TEST_CASE("runCollector captures failures and format renders them") {
  FakeTransport empty;
  auto c = makeCollector("users");
  REQUIRE(c);
  Snapshot s = runCollector(*c, empty, "tgt");
  REQUIRE_FALSE(s.error.empty());
  REQUIRE(formatSnapshot(s).find("ERROR") != std::string::npos);
  REQUIRE_FALSE(makeCollector("nope"));
}

TEST_CASE("attack sources accumulate per address and day, and respect the period") {
  auto st = Store::open(":memory:");
  Store& s = *st.value();
  const int64_t day = 86400LL * 20000;
  Store::SourceDelta d;
  d.ip = "198.51.100.5";
  d.ssh_fail = 3;
  d.users_json = "[\"root\"]";
  REQUIRE(s.recordSources("web01", {d}, day + 100).ok());
  d.ssh_fail = 4;
  d.ssh_ok = 1;
  d.users_json = "[\"admin\"]";
  REQUIRE(s.recordSources("web01", {d}, day + 200).ok());
  Store::SourceDelta other;
  other.ip = "203.0.113.9";
  other.scans = 2;
  REQUIRE(s.recordSources("db01", {other}, day - 5 * 86400).ok());

  auto all = s.listSources(0, "", 10);
  REQUIRE(all.ok());
  REQUIRE(all.value().size() == 2);
  REQUIRE(all.value()[0].ip == "198.51.100.5");  // busiest first
  REQUIRE(all.value()[0].ssh_fail == 7);
  REQUIRE(all.value()[0].ssh_ok == 1);
  REQUIRE(all.value()[0].first_ts == day + 100);
  REQUIRE(all.value()[0].last_ts == day + 200);
  REQUIRE(all.value()[0].users.size() == 2);
  REQUIRE(s.listSources(day, "", 10).value().size() == 1);          // the older address is outside the period
  REQUIRE(s.listSources(0, "db01", 10).value().size() == 1);        // filter by target
  REQUIRE(s.listSources(0, "nothere", 10).value().empty());
}

TEST_CASE("attack sources are recovered once from earlier findings") {
  auto st = Store::open(":memory:");
  Store& s = *st.value();
  Finding f;
  f.fingerprint = "LOG-001|web01|bf";
  f.rule_id = "LOG-001";
  f.title = "Brute force";
  f.severity = Severity::Medium;
  f.target = "web01";
  f.collector = "logs";
  f.obs_type = "log.auth.bruteforce";
  f.stable_key = "bruteforce|198.51.100.5|2026-10-22";
  f.first_seen = f.last_seen = 1700000000;
  f.evidence = {{"src_ip", "198.51.100.5"}, {"failures", 11}, {"users", {"root", "admin"}}};
  REQUIRE(s.upsertFinding(f).ok());
  REQUIRE(s.backfillSources().value() == 1);
  REQUIRE(s.backfillSources().value() == 0);  // idempotent
  const auto rows = s.listSources(0, "", 10).value();
  REQUIRE(rows.size() == 1);
  REQUIRE(rows[0].ssh_fail == 11);
}
