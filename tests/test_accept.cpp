#include <catch2/catch.hpp>

#include "store/store.h"

using namespace agent;

namespace {

Finding mk(const std::string& key, std::vector<Identity> drift) {
  Finding f;
  f.fingerprint = "PROC-007|web01|" + key;
  f.rule_id = "PROC-007";
  f.title = "New program";
  f.severity = Severity::High;
  f.target = "web01";
  f.collector = "processes";
  f.obs_type = "process";
  f.stable_key = key;
  f.first_seen = f.last_seen = 100;
  f.drift = std::move(drift);
  return f;
}

}  // namespace

TEST_CASE("accepting: the note and the expiry are kept, reopening takes exactly what was added out of the baseline") {
  auto st = Store::open(":memory:");
  REQUIRE(st.ok());
  Store& s = *st.value();
  // "pre" was already normal before the decision: it must survive a reopen
  REQUIRE(s.addToBaseline("web01", {{"proc.exe", "pre"}}, 50).ok());
  const int64_t id = s.upsertFinding(mk("/srv/job", {{"proc.exe", "pre"}, {"proc.exe", "/srv/job"}})).value().id;

  REQUIRE(s.acceptFinding(id, 1000, "nightly backup", 5000).ok());
  REQUIRE(s.getFinding(id).value()->status == "accepted");
  REQUIRE(s.inBaseline("web01", {"proc.exe", "/srv/job"}).value());
  auto acc = s.acceptanceOf(id);
  REQUIRE(acc.value().has_value());
  REQUIRE(acc.value()->note == "nightly backup");
  REQUIRE(acc.value()->expires_at == 5000);
  REQUIRE(acc.value()->added.size() == 1);  // only the identity that was new

  // accepting again updates the decision and does not forget what it had added
  REQUIRE(s.acceptFinding(id, 1100, "still the backup", 0).ok());
  acc = s.acceptanceOf(id);
  REQUIRE(acc.value()->note == "still the backup");
  REQUIRE(acc.value()->expires_at == 0);
  REQUIRE(acc.value()->added.size() == 1);

  // an acceptance without a deadline never expires by itself
  REQUIRE(s.reopenExpired(1000000).value().empty());

  REQUIRE(s.acceptFinding(id, 1200, "for a week", 2000).ok());
  REQUIRE(s.reopenExpired(1999).value().empty());
  const auto due = s.reopenExpired(2000);
  REQUIRE(due.ok());
  REQUIRE(due.value() == std::vector<int64_t>{id});
  REQUIRE(s.getFinding(id).value()->status == "open");
  REQUIRE_FALSE(s.acceptanceOf(id).value().has_value());
  REQUIRE_FALSE(s.inBaseline("web01", {"proc.exe", "/srv/job"}).value());  // it will be reported again
  REQUIRE(s.inBaseline("web01", {"proc.exe", "pre"}).value());               // what was normal before stays normal
}

TEST_CASE("reopening: only accepted findings, and the finding may alert again") {
  auto st = Store::open(":memory:");
  Store& s = *st.value();
  const int64_t id = s.upsertFinding(mk("/srv/x", {{"proc.exe", "/srv/x"}})).value().id;
  REQUIRE_FALSE(s.reopenFinding(id, 10).value());           // it is open: nothing to take back
  REQUIRE_FALSE(s.reopenFinding(999, 10).ok());              // unknown
  REQUIRE_FALSE(s.acceptFinding(999, 10).ok());

  REQUIRE(s.markAlerted({id}, 1, 20).ok());
  REQUIRE(s.listUnalerted(10).value().empty());
  REQUIRE(s.acceptFinding(id, 30).ok());
  REQUIRE(s.reopenFinding(id, 40).value());
  const auto again = s.listUnalerted(10);
  REQUIRE(again.value().size() == 1);                        // the decision no longer holds: it is reported again
  REQUIRE(again.value()[0].id == id);
}

TEST_CASE("findings active in a period: overlap with the window, target filter, noise rule left out") {
  auto st = Store::open(":memory:");
  Store& s = *st.value();
  Finding a = mk("a", {});
  a.first_seen = 100;
  a.last_seen = 200;
  Finding b = mk("b", {});
  b.first_seen = b.last_seen = 900;
  Finding c = mk("c", {});
  c.target = "db01";
  c.fingerprint = "PROC-007|db01|c";
  c.first_seen = c.last_seen = 150;
  Finding noise = mk("n", {});
  noise.rule_id = "LOG-050";
  noise.fingerprint = "LOG-050|web01|n";
  noise.first_seen = noise.last_seen = 150;
  for (const auto* f : {&a, &b, &c, &noise}) REQUIRE(s.upsertFinding(*f).ok());

  REQUIRE(s.findingsActive(120, 300, "", 10).value().size() == 2);       // a and c; b is later, noise is not a finding to ask about
  REQUIRE(s.findingsActive(120, 300, "web01", 10).value().size() == 1);
  REQUIRE(s.findingsActive(250, 300, "", 10).value().empty());
  REQUIRE(s.findingsActive(0, 1000, "", 1).value().size() == 1);          // limit
}
