#include <catch2/catch.hpp>

#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>

#include "analysis/analyzer.h"
#include "analysis/rule.h"
#include "enrich/enrich.h"
#include "intel/threat_intel.h"
#include "scripted_http.h"

using namespace agent;

namespace {

std::string tmpPath(const std::string& name) { return "/tmp/dyna_cyber_agent_test_" + name + "_" + std::to_string(::getpid()); }

// A small world: Milano (20.0.0.x), Sydney (1.0.0.x), Roma (30.0.0.x), Frankfurt (40.0.0.x).
// The database file must outlive the lookups (a reader re-opens the path when it changes), so it is removed at the end.
struct World {
  std::unique_ptr<GeoDb> db;
  std::string path;
  GeoDb* get() { return db.get(); }
  ~World() { std::remove(path.c_str()); }
};

World world() {
  const std::string csv = tmpPath("w.csv"), db = tmpPath("w.db");
  {
    std::ofstream f(csv);
    f << "0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0\n";
    for (int i = 0; i < 1500; ++i) f << "50." << i / 256 << "." << i % 256 << ".0,50." << i / 256 << "." << i % 256 << ".255,EU,FR,Idf,Paris,48.85,2.35\n";
    f << "20.0.0.0,20.0.0.255,EU,IT,Lombardia,Milano,45.46,9.19\n";
    f << "1.0.0.0,1.0.0.255,OC,AU,NSW,Sydney,-33.87,151.21\n";
    f << "30.0.0.0,30.0.0.255,EU,IT,Lazio,Roma,41.9,12.5\n";
    f << "40.0.0.0,40.0.0.255,EU,DE,Hesse,Frankfurt,50.11,8.68\n";
  }
  REQUIRE(GeoDb::importCsv(db, csv, "test", std::chrono::seconds(1)).ok());
  std::remove(csv.c_str());
  auto g = GeoDb::open(db);
  REQUIRE(g.ok());
  return World{std::move(g.value()), db};
}

Observation login(const std::string& user, const std::string& ip) {
  Observation o;
  o.type = "log.auth.login";
  o.key = "login|" + user + "|" + ip + "|publickey";
  o.data = {{"user", user}, {"src_ip", ip}, {"method", "publickey"}, {"count", 1}};
  return o;
}

Snapshot logsSnap(int64_t ts, std::vector<Observation> obs) {
  Snapshot s;
  s.target = "web01";
  s.collector = "logs";
  s.ts = ts;
  s.observations = std::move(obs);
  return s;
}

const Observation* find(const Snapshot& s, const std::string& type) {
  for (const auto& o : s.observations) if (o.type == type) return &o;
  return nullptr;
}
bool tagged(const Observation* o, const char* t) { return o && std::find(o->tags.begin(), o->tags.end(), t) != o->tags.end(); }

}  // namespace

TEST_CASE("distance between two places") {
  REQUIRE(Enricher::distanceKm(45.46, 9.19, 41.9, 12.5) == Approx(477).margin(10));       // Milano - Roma
  REQUIRE(Enricher::distanceKm(45.46, 9.19, -33.87, 151.21) == Approx(16557).margin(100));  // Milano - Sydney
  REQUIRE(Enricher::distanceKm(10, 10, 10, 10) == Approx(0).margin(0.001));
}

TEST_CASE("logins: impossible travel is flagged, ordinary movement and VPN-free repeats are not") {
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  auto geo = world();
  AnalysisConfig cfg;
  Enricher en(store, cfg);
  en.setGeo(geo.get());
  const int64_t t0 = 1'800'000'000;

  auto s1 = logsSnap(t0, {login("alice", "20.0.0.7")});  // Milano
  en.apply(s1);
  const auto* o1 = find(s1, "log.auth.login");
  REQUIRE(o1->data["cc"] == "IT");
  REQUIRE(o1->data["city"] == "Milano");
  REQUIRE(o1->data["hour_bucket"].is_number());
  REQUIRE_FALSE(tagged(o1, "impossible_travel"));

  auto s2 = logsSnap(t0 + 30 * 60, {login("alice", "20.0.0.7")});  // the same place again
  en.apply(s2);
  REQUIRE_FALSE(tagged(find(s2, "log.auth.login"), "impossible_travel"));

  auto s3 = logsSnap(t0 + 2 * 3600, {login("alice", "30.0.0.9")});  // Roma, 477 km in 2 h by car: plausible (and below the minimum distance)
  en.apply(s3);
  REQUIRE_FALSE(tagged(find(s3, "log.auth.login"), "impossible_travel"));

  auto s4 = logsSnap(t0 + 3 * 3600, {login("alice", "1.0.0.5")});  // Sydney one hour later
  en.apply(s4);
  const auto* o4 = find(s4, "log.auth.login");
  REQUIRE(tagged(o4, "impossible_travel"));
  REQUIRE(o4->data["travel"]["from_cc"] == "IT");
  REQUIRE(o4->data["travel"]["distance_km"].get<double>() > 15000);
  REQUIRE(o4->data["travel"]["speed_kmh"].get<double>() > 10000);

  auto bob = logsSnap(t0 + 3 * 3600, {login("bob", "1.0.0.5")});  // another account has its own history
  en.apply(bob);
  REQUIRE_FALSE(tagged(find(bob, "log.auth.login"), "impossible_travel"));

  // a flight: 16000 km in 30 hours is possible, and the look-back is 24 hours anyway
  auto s5 = logsSnap(t0 + 3 * 3600 + 30 * 3600, {login("alice", "20.0.0.7")});
  en.apply(s5);
  REQUIRE_FALSE(tagged(find(s5, "log.auth.login"), "impossible_travel"));

  // private addresses and a missing database are quietly skipped
  auto lan = logsSnap(t0 + 40 * 3600, {login("alice", "192.168.1.20")});
  en.apply(lan);
  REQUIRE_FALSE(find(lan, "log.auth.login")->data.contains("cc"));
  Enricher blind(store, cfg);
  auto s6 = logsSnap(t0, {login("alice", "20.0.0.7")});
  blind.apply(s6);
  REQUIRE_FALSE(find(s6, "log.auth.login")->data.contains("cc"));

  AnalysisConfig off;
  off.travel = false;
  Enricher disabled(store, off);
  disabled.setGeo(geo.get());
  auto s7 = logsSnap(t0, {login("alice", "20.0.0.7")});
  disabled.apply(s7);
  REQUIRE_FALSE(find(s7, "log.auth.login")->data.contains("cc"));
}

TEST_CASE("logins: a new country or hour is drift once the baseline is locked") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(rules.ok());
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  auto geo = world();
  Enricher en(store, AnalysisConfig{});
  en.setGeo(geo.get());
  Analyzer an(store, rules.value(), std::chrono::hours(6));
  const int64_t day = 1'800'000'000 / 86400 * 86400;  // midnight UTC
  store.baselineMeta("web01", day + 5 * 3600);        // learning from 05:00 UTC for six hours

  auto learn = logsSnap(day + 10 * 3600, {login("alice", "20.0.0.7")});
  en.apply(learn);
  REQUIRE(an.analyze(learn).value().learning);

  auto same = logsSnap(day + 11 * 3600, {login("alice", "20.0.0.8")});  // same country, same 3 h slot (09-12)
  en.apply(same);
  std::vector<std::string> same_rules;
  for (const auto& f : an.analyze(same).value().fresh) same_rules.push_back(f.rule_id);
  REQUIRE(std::find(same_rules.begin(), same_rules.end(), "LOG-061") == same_rules.end());
  REQUIRE(std::find(same_rules.begin(), same_rules.end(), "LOG-062") == same_rules.end());

  auto odd = logsSnap(day + 3 * 86400 + 3 * 3600, {login("alice", "40.0.0.4")});  // Germany at 03:00, three days later
  en.apply(odd);
  std::set<std::string> got;
  for (const auto& f : an.analyze(odd).value().fresh) got.insert(f.rule_id);
  REQUIRE(got.count("LOG-061"));  // a country this account never logged in from
  REQUIRE(got.count("LOG-062"));  // an hour it never logged in at
}

TEST_CASE("outbound connections get a country, which is drift when it is new") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  auto geo = world();
  Enricher en(store, AnalysisConfig{});
  en.setGeo(geo.get());
  Analyzer an(store, rules.value(), std::chrono::seconds(1000));
  store.baselineMeta("web01", 0);

  auto snap = [](int64_t ts, const std::string& ip, const std::string& state) {
    Snapshot s;
    s.target = "web01";
    s.collector = "network";
    s.ts = ts;
    Observation o;
    o.type = "socket.inet";
    o.key = "k" + ip;
    o.data = {{"proto", "tcp"}, {"local_addr", "10.0.0.5"}, {"local_port", 41000}, {"remote_addr", ip}, {"remote_port", 443}, {"state", state}, {"owners", nlohmann::json::array()}};
    s.observations.push_back(o);
    return s;
  };
  auto learn = snap(10, "20.0.0.7", "ESTABLISHED");
  en.apply(learn);
  REQUIRE(find(learn, "socket.inet")->data["remote_cc"] == "IT");
  REQUIRE(an.analyze(learn).value().learning);

  auto known = snap(100000, "30.0.0.2", "ESTABLISHED");  // Roma: another city of the same country
  en.apply(known);
  for (const auto& f : an.analyze(known).value().fresh) REQUIRE(f.rule_id != "NET-032");  // a new destination, but not a new country

  auto fresh = snap(100100, "1.0.0.9", "ESTABLISHED");
  en.apply(fresh);
  auto r = an.analyze(fresh);
  bool country_rule = false;
  for (const auto& f : r.value().fresh) country_rule |= f.rule_id == "NET-032";
  REQUIRE(country_rule);

  auto closed = snap(100200, "40.0.0.1", "TIME_WAIT");  // not a live connection: no country
  en.apply(closed);
  REQUIRE_FALSE(find(closed, "socket.inet")->data.contains("remote_cc"));
  auto lan = snap(100300, "192.168.1.1", "ESTABLISHED");
  en.apply(lan);
  REQUIRE_FALSE(find(lan, "socket.inet")->data.contains("remote_cc"));
}

TEST_CASE("threat lists: parsing and lookup") {
  const auto r = ThreatIntel::parseList(
      "# comment\n; Spamhaus\n1.10.16.0/20 ; SBL256894\n203.0.113.5\n203.0.113.6  # next one\n10.0.0.0/8\nnot an ip\n2001:db8::/32\n300.1.1.1\n1.2.3.4/33\n1.2.3.4/0\n");
  REQUIRE(r.size() == 1);  // 1.2.3.4/0 is the whole internet and swallows every other range
  REQUIRE(r[0].lo == 0);
  REQUIRE(r[0].hi == 0xFFFFFFFFu);

  const auto ok = ThreatIntel::parseList("1.10.16.0/20 ; x\n203.0.113.5\n203.0.113.6\n203.0.113.7\n");
  REQUIRE(ok.size() == 2);  // the three neighbouring addresses merge
  REQUIRE(ThreatIntel::parseIpv4("1.2.3.4") == 0x01020304u);
  REQUIRE_FALSE(ThreatIntel::parseIpv4("1.2.3"));
  REQUIRE_FALSE(ThreatIntel::parseIpv4("1.2.3.256"));
  REQUIRE_FALSE(ThreatIntel::parseIpv4("::1"));
}

TEST_CASE("threat lists: download, keep on failure, strongest category wins") {
  const std::string dir = tmpPath("intel");
  std::filesystem::remove_all(dir);
  std::vector<ThreatIntelConfig::List> lists = {{"feodo", "https://lists.test/feodo.txt", "c2"}, {"drop", "https://lists.test/drop.txt", "attacker"}, {"broken", "https://lists.test/broken.txt", "scanner"}};
  ThreatIntel ti(dir, lists);
  REQUIRE(ti.load() == 0);
  REQUIRE(ti.empty());

  ScriptedHttp http;
  http.ok("feodo.txt", "# c2\n198.51.100.0/24\n");
  http.ok("drop.txt", "198.51.100.0/25 ; SBL1\n192.0.2.0/24 ; SBL2\n");
  http.status("broken.txt", 503);
  const auto reps = ti.refresh(http, 1000, 0, std::chrono::seconds(5));
  REQUIRE(reps.size() == 3);
  REQUIRE(reps[0].ok);
  REQUIRE(reps[1].ok);
  REQUIRE_FALSE(reps[2].ok);

  const auto c2 = ti.lookup("198.51.100.10");
  REQUIRE(c2);
  REQUIRE(c2->category == "c2");           // listed in two lists: the more serious category is reported
  REQUIRE(c2->list == "feodo");
  REQUIRE(ti.lookup("192.0.2.77")->list == "drop");
  REQUIRE_FALSE(ti.lookup("203.0.113.1"));
  REQUIRE_FALSE(ti.lookup("not an ip"));
  REQUIRE_FALSE(ti.lookup("2001:db8::1"));

  // a restart reads the copy from disk without any network
  ThreatIntel again(dir, lists);
  REQUIRE(again.load() == 3);
  REQUIRE(again.lookup("198.51.100.10"));

  // a bad download (an HTML error page) never replaces a good list
  ScriptedHttp bad;
  bad.ok("feodo.txt", "<html>rate limited</html>");
  bad.status("drop.txt", 500);
  bad.status("broken.txt", 500);
  const auto r2 = again.refresh(bad, 2000, 0, std::chrono::seconds(5));
  REQUIRE_FALSE(r2[0].ok);
  REQUIRE(again.lookup("198.51.100.10"));

  // a header with no entries (nothing active right now) is a valid list: it replaces the old copy
  ScriptedHttp empty;
  empty.ok("feodo.txt", "####\n# abuse.ch Feodo Tracker (IPs only)\n# Last updated: today\n####\n");
  empty.status("drop.txt", 500);
  empty.status("broken.txt", 500);
  const auto r_empty = again.refresh(empty, 3000, 0, std::chrono::seconds(5));
  REQUIRE(r_empty[0].ok);
  REQUIRE(again.lookup("198.51.100.10")->list == "drop");  // feodo is now empty; only the other list still covers it

  // fresh copies are not downloaded again
  ScriptedHttp quiet;
  const auto r3 = ti.refresh(quiet, 1100, 3600, std::chrono::seconds(5));
  REQUIRE(quiet.requested.size() == 1);  // only the list that never succeeded
  REQUIRE(r3[0].ok);
  std::filesystem::remove_all(dir);
}

TEST_CASE("threat lists tag sockets and logins, and the rules rate them") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  const std::string dir = tmpPath("intel2");
  std::filesystem::remove_all(dir);
  ThreatIntel ti(dir, {{"feodo", "https://x.test/f", "c2"}, {"drop", "https://x.test/d", "attacker"}});
  ScriptedHttp http;
  http.ok("/f", "198.51.100.0/24\n");
  http.ok("/d", "192.0.2.0/24\n");
  ti.refresh(http, 1, 0, std::chrono::seconds(5));

  auto st = Store::open(":memory:");
  Store& store = *st.value();
  Enricher en(store, AnalysisConfig{});
  en.setThreatIntel(&ti);
  Analyzer an(store, rules.value(), std::chrono::seconds(0));
  store.lockBaseline("web01", 0);

  Snapshot net;
  net.target = "web01";
  net.collector = "network";
  net.ts = 100;
  for (const char* ip : {"198.51.100.4", "192.0.2.8", "203.0.113.1"}) {
    Observation o;
    o.type = "socket.inet";
    o.key = std::string("k") + ip;
    o.data = {{"proto", "tcp"}, {"local_addr", "10.0.0.5"}, {"local_port", 41000}, {"remote_addr", ip}, {"remote_port", 443}, {"state", "ESTABLISHED"}, {"owners", nlohmann::json::array()}};
    net.observations.push_back(o);
  }
  en.apply(net);
  REQUIRE(net.observations[0].data["ti"]["category"] == "c2");
  REQUIRE(tagged(&net.observations[0], "ti_c2"));
  REQUIRE(tagged(&net.observations[1], "ti_malicious"));
  REQUIRE_FALSE(tagged(&net.observations[1], "ti_c2"));
  REQUIRE_FALSE(net.observations[2].data.contains("ti"));
  std::map<std::string, Severity> by;
  for (const auto& f : an.analyze(net).value().fresh) by[f.rule_id] = f.severity;
  REQUIRE(by["TI-001"] == Severity::Critical);
  REQUIRE(by["TI-002"] == Severity::High);
  REQUIRE(by.size() >= 2);

  auto lg = logsSnap(200, {login("alice", "192.0.2.50")});
  en.apply(lg);
  REQUIRE(tagged(find(lg, "log.auth.login"), "ti_malicious"));
  bool ti3 = false;
  for (const auto& f : an.analyze(lg).value().fresh) ti3 |= f.rule_id == "TI-003";
  REQUIRE(ti3);

  Observation bf;
  bf.type = "log.auth.bruteforce";
  bf.key = "bf";
  bf.data = {{"src_ip", "192.0.2.50"}, {"failures", 40}};
  Snapshot bs = logsSnap(300, {bf});
  en.apply(bs);
  REQUIRE(tagged(find(bs, "log.auth.bruteforce"), "ti_known_attacker"));  // already an attack: the list only adds confidence
  std::filesystem::remove_all(dir);
}
