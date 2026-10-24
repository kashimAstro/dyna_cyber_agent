#include <catch2/catch.hpp>

#include <cstdio>
#include <fstream>

#include "geo/geo_db.h"

using namespace agent;

namespace {

std::string tmpPath(const std::string& name) { return "/tmp/dyna_cyber_agent_test_" + name + "_" + std::to_string(::getpid()); }

}  // namespace

TEST_CASE("geo: local and special addresses are never plotted") {
  for (const char* ip : {"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.19", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1", "garbage", ""}) {
    INFO(ip);
    REQUIRE(GeoDb::isLocalAddress(ip));
  }
  for (const char* ip : {"8.8.8.8", "172.32.0.1", "1.1.1.1", "2606:4700::1111"}) {
    INFO(ip);
    REQUIRE_FALSE(GeoDb::isLocalAddress(ip));
  }
}

TEST_CASE("geo: a DB-IP style CSV is imported and answers lookups") {
  const std::string csv = tmpPath("geo.csv"), db = tmpPath("geo.db");
  {
    std::ofstream f(csv);
    f << "0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0\n";
    for (int i = 0; i < 1500; ++i) {  // the importer refuses tiny files: they are not a real database
      f << "20." << i / 256 << "." << i % 256 << ".0,20." << i / 256 << "." << i % 256 << ".255,EU,IT,Lombardia,\"Milano, centro\",45.4642,9.19\n";
    }
    f << "1.0.0.0,1.0.0.255,OC,AU,Queensland,\"South Brisbane\",-27.4767,153.017\n";
    f << "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,EU,DE,Hesse,Frankfurt,50.11,8.68\n";
  }
  auto n = GeoDb::importCsv(db, csv, "test", std::chrono::seconds(1700000000));
  REQUIRE(n.ok());
  REQUIRE(n.value() == 1502);  // the "unknown" row is skipped

  auto g = GeoDb::open(db);
  REQUIRE(g.ok());
  REQUIRE_FALSE(g.value()->empty());
  const auto au = g.value()->lookup("1.0.0.77");
  REQUIRE(au.has_value());
  REQUIRE(au->cc == "AU");
  REQUIRE(au->city == "South Brisbane");
  REQUIRE(au->lat == Approx(-27.4767));
  const auto mi = g.value()->lookup("20.0.3.200");
  REQUIRE(mi.has_value());
  REQUIRE(mi->city == "Milano, centro");  // a quoted comma survives
  const auto de = g.value()->lookup("2001:db8:1::5");
  REQUIRE(de.has_value());
  REQUIRE(de->cc == "DE");
  REQUIRE(g.value()->lookup("::ffff:1.0.0.1")->cc == "AU");  // IPv4 in IPv6 clothes
  REQUIRE_FALSE(g.value()->lookup("1.0.1.1").has_value());   // between ranges
  REQUIRE_FALSE(g.value()->lookup("0.0.0.5").has_value());
  REQUIRE_FALSE(g.value()->lookup("192.168.1.1").has_value());  // local: no lookup at all
  REQUIRE(g.value()->meta("source").value() == "test");

  REQUIRE_FALSE(GeoDb::importCsv(db, csv + ".missing", "x", std::chrono::seconds(1)).ok());
  std::remove(csv.c_str());
  std::remove(db.c_str());
}

TEST_CASE("geo: a missing database is empty, not an error") {
  auto g = GeoDb::open(tmpPath("absent.db"));
  REQUIRE(g.ok());
  REQUIRE(g.value()->empty());
  REQUIRE_FALSE(g.value()->lookup("8.8.8.8").has_value());
}

TEST_CASE("geo: only https downloads are allowed") {
  REQUIRE_FALSE(downloadFile("http://example.invalid/x", tmpPath("dl"), std::chrono::seconds(1), nullptr).ok());
  REQUIRE(dbipCityUrl(2026, 3) == "https://download.db-ip.com/free/dbip-city-lite-2026-03.csv.gz");
}
