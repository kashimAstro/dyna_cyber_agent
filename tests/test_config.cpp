#include <catch2/catch.hpp>

#include "core/config.h"

using namespace agent;

TEST_CASE("duration parsing") {
  REQUIRE(parseDuration("30s").value().count() == 30);
  REQUIRE(parseDuration("5m").value().count() == 300);
  REQUIRE(parseDuration("2h").value().count() == 7200);
  REQUIRE(parseDuration("1d").value().count() == 86400);
  REQUIRE_FALSE(parseDuration("").ok());
  REQUIRE_FALSE(parseDuration("5").ok());
  REQUIRE_FALSE(parseDuration("5x").ok());
  REQUIRE_FALSE(parseDuration("-5s").ok());
}

TEST_CASE("valid config") {
  auto c = parseConfig(R"(
targets:
  - name: a
    transport: local
    collectors: all
  - name: b
    transport: ssh
    host: h
    user: u
    key: /k
    collectors: [network]
    interval: { network: 15s }
)");
  REQUIRE(c.ok());
  REQUIRE(c.value().targets.size() == 2);
  REQUIRE(c.value().targets[0].collectors.empty());
  REQUIRE(c.value().targets[1].ssh.port == 22);
  REQUIRE(c.value().targets[1].intervals.at("network").count() == 15);
  REQUIRE(c.value().llm.url == "http://127.0.0.1:8080");
}

TEST_CASE("invalid configs are rejected") {
  REQUIRE_FALSE(parseConfig("targets: []").ok());
  REQUIRE_FALSE(parseConfig("foo: bar").ok());
  REQUIRE_FALSE(parseConfig("retention_days: 0\ntargets:\n  - {name: a, transport: local}").ok());
  REQUIRE_FALSE(parseConfig("- a").ok());
  REQUIRE_FALSE(parseConfig("targets: [").ok());
  REQUIRE_FALSE(parseConfig("targets:\n  - {name: a, transport: ftp}").ok());
  REQUIRE_FALSE(parseConfig("targets:\n  - {name: a, transport: ssh, host: h}").ok());
  REQUIRE_FALSE(parseConfig("log_level: loud\ntargets:\n  - {name: a, transport: local}").ok());
  REQUIRE_FALSE(parseConfig("alerting: {min_severity: x}\ntargets:\n  - {name: a, transport: local}").ok());
  REQUIRE_FALSE(parseConfig("targets:\n  - {name: a, transport: local}\n  - {name: a, transport: local}").ok());
}

TEST_CASE("missing config file") { REQUIRE_FALSE(loadConfigFile("/nonexistent/agent.yaml").ok()); }

TEST_CASE("analysis, groups and threat intelligence settings") {
  const std::string tgt = "targets: [{name: a, transport: local, group: web-servers}, {name: b, transport: local}]\n";
  auto def = parseConfig(tgt);
  REQUIRE(def.ok());
  const auto& d = def.value();
  REQUIRE(d.targets[0].group == "web-servers");
  REQUIRE(d.targets[1].group.empty());
  REQUIRE(d.analysis.explain_updates);
  REQUIRE(d.analysis.explain_window.count() == 7 * 86400);
  REQUIRE(d.analysis.incidents);
  REQUIRE(d.analysis.incident_window.count() == 86400);
  REQUIRE(d.analysis.peers);
  REQUIRE(d.analysis.peer_min_group == 3);
  REQUIRE(d.analysis.log_templates);
  REQUIRE(d.analysis.travel_max_kmh == Approx(900));
  REQUIRE(d.vuln.epss);
  REQUIRE(d.vuln.exposure);
  REQUIRE(d.threat_intel.enabled);
  REQUIRE(d.threat_intel.lists.size() == defaultThreatLists().size());  // the built-in set
  REQUIRE(d.threat_intel.lists[0].name == "feodo");

  auto custom = parseConfig(R"(
analysis:
  explain_updates: {enabled: false, window: 2d}
  incidents: {window: 6h, min_findings: 3}
  peers: {enabled: false, min_group_size: 5, min_share: 0.9}
  logs: {templates: false, max_new_per_cycle: 10}
  outbound: {beaconing: false, new_countries: false, traffic_spikes: false}
  travel: {enabled: false, max_speed_kmh: 600, min_distance_km: 300}
vuln: {epss: false, exposure: false, epss_url: "https://mirror.example/epss-{date}.csv.gz"}
threat_intel:
  enabled: true
  refresh_every: 6h
  lists:
    - {name: mine, url: "https://lists.example/c2.txt", category: c2}
)" + tgt);
  REQUIRE(custom.ok());
  const auto& c = custom.value();
  REQUIRE_FALSE(c.analysis.explain_updates);
  REQUIRE(c.analysis.explain_window.count() == 2 * 86400);
  REQUIRE(c.analysis.incident_window.count() == 6 * 3600);
  REQUIRE(c.analysis.incident_min_findings == 3);
  REQUIRE_FALSE(c.analysis.peers);
  REQUIRE(c.analysis.peer_min_group == 5);
  REQUIRE(c.analysis.peer_min_share == Approx(0.9));
  REQUIRE_FALSE(c.analysis.log_templates);
  REQUIRE(c.analysis.log_templates_per_cycle == 10);
  REQUIRE_FALSE(c.analysis.beaconing);
  REQUIRE_FALSE(c.analysis.travel);
  REQUIRE(c.analysis.travel_min_km == Approx(300));
  REQUIRE_FALSE(c.vuln.epss);
  REQUIRE(c.vuln.epss_url == "https://mirror.example/epss-{date}.csv.gz");
  REQUIRE(c.threat_intel.lists.size() == 1);
  REQUIRE(c.threat_intel.lists[0].category == "c2");
  REQUIRE(c.threat_intel.refresh_every.count() == 6 * 3600);

  auto bad = [&](const std::string& y) { return parseConfig(y + tgt).ok(); };
  REQUIRE_FALSE(bad("analysis: {peers: {min_group_size: 2}}\n"));        // two machines have no majority
  REQUIRE_FALSE(bad("analysis: {peers: {min_share: 0.5}}\n"));
  REQUIRE_FALSE(bad("analysis: {incidents: {min_findings: 1}}\n"));
  REQUIRE_FALSE(bad("analysis: {incidents: {window: 1m}}\n"));
  REQUIRE_FALSE(bad("analysis: {logs: {max_new_per_cycle: 0}}\n"));
  REQUIRE_FALSE(bad("analysis: {travel: {max_speed_kmh: 10}}\n"));
  REQUIRE_FALSE(bad("threat_intel: {refresh_every: 5m}\n"));
  REQUIRE_FALSE(bad("threat_intel: {lists: [{name: x, url: ftp://x, category: c2}]}\n"));
  REQUIRE_FALSE(bad("threat_intel: {lists: [{name: x, url: https://x, category: nice}]}\n"));
  REQUIRE_FALSE(bad("threat_intel: {lists: [{name: x, url: https://x}, {name: x, url: https://y}]}\n"));
  REQUIRE_FALSE(bad("vuln: {epss_url: ftp://x}\n"));
  REQUIRE_FALSE(parseConfig("targets: [{name: a, transport: local, group: 'bad group!'}]\n").ok());
}
