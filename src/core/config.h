#pragma once
#include <chrono>
#include <map>
#include <string>
#include <vector>

#include "core/result.h"

namespace agent {

struct LlmConfig {
  bool enabled = true;
  std::string url = "http://127.0.0.1:8080";  // llama-server base URL
  std::chrono::seconds timeout{300};          // a Q8 model on modest hardware can be slow
  std::string model;                          // optional, llama-server serves whatever it loaded
  std::string api_key_file;                   // optional, for `llama-server --api-key`
  double temperature = 0.2;                   // low: this is analysis, not creative writing
  int max_tokens = 4096;
  int context_tokens = 32768;                 // must not exceed llama-server's `-c`
  int max_findings_per_call = 8;
  std::chrono::seconds batch_window{30};      // wait this long to group related new findings
  std::string language = "italiano";          // derived from Config::language ("english" / "italiano")
  std::string focus_file;                     // admin instructions ("today watch X")
};

struct SmtpConfig {
  std::string host;
  int port = 587;
  std::string user;
  std::string password_file;  // password is read from a file, never inline
  std::string from;           // "agent@example.com" or "Agent <agent@example.com>"
  std::string tls = "starttls";  // starttls | ssl | none
  std::chrono::seconds timeout{30};
};

struct AlertingConfig {
  std::string min_severity = "high";          // findings at or above this are mailed as alerts
  std::chrono::seconds alert_delay{120};      // wait for the LLM assessment / related findings before mailing
  std::chrono::seconds cooldown{300};         // minimum gap between alert mails (critical bypasses it)
  int max_per_hour = 6;                       // hard cap on alert mails, whatever the severity
  std::string subject_prefix = "[dyna_cyber_agent]";
  std::string language = "it";                // derived from Config::language (it | en)
  std::vector<std::string> recipients;
  SmtpConfig smtp;

  bool digest_enabled = true;
  std::chrono::seconds digest_every{86400};
  std::string digest_at;                      // optional "HH:MM" (local time) instead of a fixed interval
  std::string digest_min_severity = "low";
  bool digest_when_empty = false;             // send the digest even when nothing is new (a heartbeat); stopped collectors always force it
};

// Vulnerability intelligence: public feeds downloaded to this machine (never to the targets) and matched
// against what the targets have installed.
struct VulnConfig {
  bool enabled = true;
  std::string db_path;                              // default: <state_dir>/vuln.db
  std::chrono::seconds refresh_every{6 * 3600};     // how often the feeds are refreshed
  std::chrono::seconds match_every{3600};           // how often targets are re-matched against the database
  bool kev = true;                                  // CISA Known Exploited Vulnerabilities
  bool nvd = true;                                  // NVD CVE records (scores, CWE, CPE ranges)
  bool cwe = true;                                  // MITRE CWE names and descriptions
  bool osv = true;                                  // OSV.dev: distribution-aware matching (Debian, Ubuntu, Rocky, Alma)
  bool epss = true;                                 // EPSS exploitation-probability scores (FIRST.org, daily file)
  bool exposure = true;                             // rank by reachability: is the vulnerable package listening / running / awaiting a restart?
  std::string cpe_match = "auto";                   // auto | always | never: upstream-version matching against NVD CPE data
  int nvd_initial_days = 120;                       // first synchronisation looks back this far
  std::string nvd_api_key_file;                     // optional: raises the NVD rate limit tenfold
  double min_cvss = 7.0;                            // matches below this score are counted, not listed
  int new_within_days = 14;                         // "recent": published / added to KEV within this window
  std::string kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  std::string nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  std::string cwe_url = "https://cwe-api.mitre.org/api/v1";
  std::string osv_url = "https://api.osv.dev";
  std::string epss_url = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz";  // {date} = YYYY-MM-DD, tried for the last few days
  std::chrono::seconds timeout{120};
};

// Local web console (read-only views, targeted AI analyses, report previews). Off by default.
struct WebConfig {
  bool enabled = false;
  std::string listen = "127.0.0.1";  // address to bind; anything but loopback is clear text: put a TLS proxy in front
  int port = 8484;
  std::string token_file;            // default: <state_dir>/web.token (generated on first start, mode 0600)
};

// Offline IP geolocation for the attack map (DB-IP "IP to City Lite", downloaded with --geo-update).
struct GeoConfig {
  std::string db_path;  // default: <state_dir>/geo.db
};

// Analysis that goes beyond one rule on one observation. Each part can be switched off on its own.
struct AnalysisConfig {
  bool explain_updates = true;                       // mark findings explained by a recent package upgrade
  std::chrono::seconds explain_window{7 * 86400};
  bool incidents = true;                             // chain related findings into incidents with a timeline
  std::chrono::seconds incident_window{24 * 3600};   // findings further apart than this are not linked
  size_t incident_min_findings = 2;
  bool peers = true;                                 // compare targets of the same group with each other
  size_t peer_min_group = 3;                         // members needed (the target included) before "the others do not have it" means anything
  double peer_min_share = 0.8;                       // share of the other members that must lack the item
  bool log_templates = true;                         // learn the shape of every log message, report shapes never seen before
  size_t log_templates_per_cycle = 25;
  bool beaconing = true;                             // periodic connections to the same outside address
  bool outbound_countries = true;                    // outbound connections to a country never seen before
  bool traffic_spikes = true;                        // outbound traffic far above the interface's normal
  bool travel = true;                                // impossible travel / new country / unusual hour for logins
  double travel_max_kmh = 900;
  double travel_min_km = 500;
};

// Public IP blocklists downloaded to the agent's machine (nothing about the targets is ever sent).
struct ThreatIntelConfig {
  bool enabled = true;
  std::string dir;                                   // default: <state_dir>/intel
  std::chrono::seconds refresh_every{12 * 3600};
  struct List {
    std::string name, url, category;                 // category: c2 | attacker | scanner | compromised
  };
  std::vector<List> lists;                           // empty in the file = the built-in set
};

struct SshConfig {
  std::string host;
  int port = 22;
  std::string user;
  std::string key_file;
  std::string known_hosts;
  std::string proxy_jump;             // optional bastion: user@host[:port]
  std::string gate = "stream";        // stream: nothing installed on the target | installed: run gate_path
  std::string gate_path;              // e.g. /usr/local/bin/dyna_cyber_agent-gate
  bool sudo = false;                  // installed gate only: run it through `sudo -n` to read other users' /proc
  int connect_timeout = 10;           // seconds
  int op_timeout = 30;                // seconds per batch of reads
  std::string ssh_binary = "/usr/bin/ssh";
};

struct TargetConfig {
  std::string name;
  std::string transport;  // "local" | "ssh"
  SshConfig ssh;
  std::string group;                    // targets with the same group are compared with each other (peer analysis)
  std::vector<std::string> collectors;  // empty = all
  std::vector<std::string> log_paths;  // empty = autodetect; "auth:|web:|kernel:|syslog:" prefix forces the type, last component may use * and ?
  int log_backfill_kb = 0;             // first time a log is seen, also read this much of its end (0 = start at the end)
  std::map<std::string, std::chrono::seconds> intervals;
};

struct Config {
  std::string language = "it";  // the one language setting: it | en (mail labels, AI text, web console)
  std::string log_level = "info";
  std::string log_file;
  std::string state_dir = "/var/lib/dyna_cyber_agent";
  int retention_days = 14;  // snapshots older than this are pruned
  std::string rules_dir = "/etc/dyna_cyber_agent/rules";
  std::chrono::seconds baseline_learning{7 * 86400};  // drift rules stay quiet while the baseline is learned
  LlmConfig llm;
  AlertingConfig alerting;
  VulnConfig vuln;
  WebConfig web;
  GeoConfig geo;
  AnalysisConfig analysis;
  ThreatIntelConfig threat_intel;
  std::vector<TargetConfig> targets;
};

// The public lists used when `threat_intel.lists` is not given.
std::vector<ThreatIntelConfig::List> defaultThreatLists();

// Parses and validates a YAML document.
Result<Config> parseConfig(const std::string& yaml_text);
Result<Config> loadConfigFile(const std::string& path);

// Parses "30s", "5m", "2h", "1d".
Result<std::chrono::seconds> parseDuration(const std::string& s);

// "Name <a@b.c>" -> "a@b.c"; a bare address is returned unchanged.
std::string addressOf(const std::string& mailbox);
// Conservative syntax check: rejects whitespace/control characters (header injection) and list syntax.
bool validEmailAddress(const std::string& addr);

}  // namespace agent
