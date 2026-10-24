#include "core/config.h"

#include <yaml-cpp/yaml.h>

#include <cctype>
#include <fstream>
#include <set>
#include <sstream>

#include "core/util.h"
#include "transport/ssh_validate.h"

namespace agent {

std::string addressOf(const std::string& mailbox) {
  const size_t lt = mailbox.rfind('<'), gt = mailbox.rfind('>');
  if (lt != std::string::npos && gt != std::string::npos && gt > lt) return mailbox.substr(lt + 1, gt - lt - 1);
  return mailbox;
}

bool validEmailAddress(const std::string& a) {
  if (a.empty() || a.size() > 254) return false;
  const size_t at = a.find('@');
  if (at == std::string::npos || at == 0 || at != a.rfind('@') || at + 1 >= a.size()) return false;
  for (unsigned char c : a) {
    if (c <= 0x20 || c == 0x7F || c == '<' || c == '>' || c == ',' || c == ';' || c == '"' || c == '(' || c == ')') return false;
  }
  return true;
}

std::vector<ThreatIntelConfig::List> defaultThreatLists() {
  return {
      {"feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "c2"},
      {"spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt", "attacker"},
      {"firehol_level1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "attacker"},
      {"et_compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "compromised"},
      {"blocklist_de_ssh", "https://lists.blocklist.de/lists/ssh.txt", "attacker"},
  };
}

Result<std::chrono::seconds> parseDuration(const std::string& s) {
  if (s.size() < 2) return err("invalid duration '" + s + "'");
  const char unit = s.back();
  const std::string num = s.substr(0, s.size() - 1);
  for (char c : num) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return err("invalid duration '" + s + "'");
  }
  if (num.size() > 9) return err("duration too large '" + s + "'");
  const long n = std::stol(num);
  switch (unit) {
    case 's': return std::chrono::seconds(n);
    case 'm': return std::chrono::seconds(n * 60);
    case 'h': return std::chrono::seconds(n * 3600);
    case 'd': return std::chrono::seconds(n * 86400);
    default: return err("invalid duration unit in '" + s + "'");
  }
}

namespace {

template <typename T>
T get(const YAML::Node& n, const char* key, T def) {
  const YAML::Node v = n[key];
  return v && !v.IsNull() ? v.as<T>() : def;  // `key:` / `key: null` / `key: ~` mean "not set", not the text "null"
}

std::vector<std::string> getList(const YAML::Node& n, const char* key) {
  std::vector<std::string> out;
  const YAML::Node v = n[key];
  if (!v || v.IsNull()) return out;
  if (v.IsScalar()) {  // allow `collectors: all`
    out.push_back(v.as<std::string>());
    return out;
  }
  for (const auto& e : v) out.push_back(e.as<std::string>());
  return out;
}

bool validClock(const std::string& s) {
  if (s.size() != 5 || s[2] != ':') return false;
  for (size_t i : {0u, 1u, 3u, 4u}) if (!std::isdigit(static_cast<unsigned char>(s[i]))) return false;
  return std::stoi(s.substr(0, 2)) < 24 && std::stoi(s.substr(3, 2)) < 60;
}

const std::set<std::string> kSeverities{"info", "low", "medium", "high", "critical"};
const std::set<std::string> kLogLevels{"trace", "debug", "info", "warn", "error", "critical", "off"};

Result<TargetConfig> parseTarget(const YAML::Node& n) {
  TargetConfig t;
  t.name = get<std::string>(n, "name", "");
  if (t.name.empty()) return err("target without 'name'");
  t.transport = get<std::string>(n, "transport", "");
  if (t.transport != "local" && t.transport != "ssh") {
    return err("target '" + t.name + "': transport must be 'local' or 'ssh'");
  }
  if (t.transport == "ssh") {
    SshConfig& x = t.ssh;
    x.host = get<std::string>(n, "host", "");
    x.port = get<int>(n, "port", 22);
    x.user = get<std::string>(n, "user", "");
    x.key_file = get<std::string>(n, "key", "");
    x.known_hosts = get<std::string>(n, "known_hosts", "");
    x.proxy_jump = get<std::string>(n, "proxy_jump", "");
    x.gate = get<std::string>(n, "gate", "stream");
    x.gate_path = get<std::string>(n, "gate_path", "");
    x.sudo = get<bool>(n, "sudo", false);
    x.connect_timeout = get<int>(n, "connect_timeout", 10);
    x.op_timeout = get<int>(n, "op_timeout", 30);
    x.ssh_binary = get<std::string>(n, "ssh_binary", "/usr/bin/ssh");
    const std::string who = "target '" + t.name + "': ";
    if (x.host.empty() || x.user.empty() || x.key_file.empty()) return err(who + "ssh requires host, user and key");
    if (!validSshHost(x.host)) return err(who + "invalid host '" + x.host + "'");
    if (!validSshUser(x.user)) return err(who + "invalid user '" + x.user + "'");
    if (x.port < 1 || x.port > 65535) return err(who + "invalid port");
    if (!x.proxy_jump.empty() && !validSshJump(x.proxy_jump)) return err(who + "invalid proxy_jump");
    if (x.gate != "stream" && x.gate != "installed") return err(who + "gate must be 'stream' or 'installed'");
    if (x.gate == "installed" && !validGatePath(x.gate_path)) return err(who + "gate: installed requires an absolute gate_path (letters, digits, . _ - /)");
    if (x.sudo && x.gate != "installed") return err(who + "sudo needs gate: installed (sudoers can only allow a fixed command)");
    if (x.connect_timeout < 1 || x.connect_timeout > 120) return err(who + "connect_timeout must be in [1, 120]");
    if (x.op_timeout < 5 || x.op_timeout > 600) return err(who + "op_timeout must be in [5, 600]");
    if (x.ssh_binary.empty() || x.ssh_binary[0] != '/') return err(who + "ssh_binary must be an absolute path");
  }
  t.group = get<std::string>(n, "group", "");
  if (!t.group.empty()) {
    for (unsigned char ch : t.group) {
      if (!(std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.')) return err("target '" + t.name + "': group may only contain letters, digits, . _ -");
    }
    if (t.group.size() > 64) return err("target '" + t.name + "': group is too long");
  }
  t.collectors = getList(n, "collectors");
  if (t.collectors.size() == 1 && t.collectors[0] == "all") t.collectors.clear();
  t.log_paths = getList(n, "log_paths");
  for (const auto& lp : t.log_paths) {
    std::string path = lp;
    for (const char* prefix : {"auth:", "web:", "kernel:", "syslog:"}) if (util::startsWith(path, prefix)) path = path.substr(std::string(prefix).size());
    if (path.empty() || path[0] != '/' || path.find('\n') != std::string::npos || path.find("..") != std::string::npos ||
        path.find_first_of("*?") < path.rfind('/')) {  // wildcards are only allowed in the last path component
      return err("target '" + t.name + "': invalid log path '" + lp + "' (absolute, no .., wildcards only in the file name)");
    }
  }
  t.log_backfill_kb = get<int>(n, "log_backfill_kb", 0);
  if (t.log_backfill_kb < 0 || t.log_backfill_kb > 8192) return err("target '" + t.name + "': log_backfill_kb must be in [0, 8192]");
  if (const YAML::Node iv = n["interval"]) {
    for (const auto& kv : iv) {
      auto d = parseDuration(kv.second.as<std::string>());
      if (!d) return err("target '" + t.name + "': interval." + kv.first.as<std::string>() + ": " + d.error());
      t.intervals[kv.first.as<std::string>()] = d.value();
    }
  }
  return t;
}

}  // namespace

Result<Config> parseConfig(const std::string& yaml_text) {
  try {
    const YAML::Node root = YAML::Load(yaml_text);
    if (!root.IsMap()) return err("config root must be a mapping");
    Config c;

    c.log_level = get<std::string>(root, "log_level", c.log_level);
    if (!kLogLevels.count(c.log_level)) return err("invalid log_level '" + c.log_level + "'");
    c.log_file = get<std::string>(root, "log_file", "");
    c.state_dir = get<std::string>(root, "state_dir", c.state_dir);
    c.retention_days = get<int>(root, "retention_days", c.retention_days);
    if (c.retention_days < 1) return err("retention_days must be >= 1");
    c.rules_dir = get<std::string>(root, "rules_dir", c.rules_dir);
    if (const YAML::Node b = root["baseline"]) {
      auto d = parseDuration(get<std::string>(b, "learning", "7d"));
      if (!d) return err("baseline.learning: " + d.error());
      c.baseline_learning = d.value();
    }

    c.language = get<std::string>(root, "language", c.language);
    if (c.language != "it" && c.language != "en") return err("language must be 'it' or 'en'");
    c.alerting.language = c.language;
    c.llm.language = c.language == "en" ? "english" : "italiano";

    if (const YAML::Node l = root["llm"]) {
      LlmConfig& m = c.llm;
      m.enabled = get<bool>(l, "enabled", m.enabled);
      m.url = get<std::string>(l, "url", m.url);
      if (!util::startsWith(m.url, "http://") && !util::startsWith(m.url, "https://")) return err("llm.url must start with http:// or https://");
      while (m.url.size() > 8 && m.url.back() == '/') m.url.pop_back();
      m.timeout = std::chrono::seconds(get<int>(l, "timeout", static_cast<int>(m.timeout.count())));
      if (m.timeout.count() <= 0) return err("llm.timeout must be > 0");
      m.model = get<std::string>(l, "model", "");
      m.api_key_file = get<std::string>(l, "api_key_file", "");
      m.temperature = get<double>(l, "temperature", m.temperature);
      if (m.temperature < 0 || m.temperature > 2) return err("llm.temperature must be in [0, 2]");
      m.max_tokens = get<int>(l, "max_tokens", m.max_tokens);
      m.context_tokens = get<int>(l, "context_tokens", m.context_tokens);
      if (m.max_tokens < 256) return err("llm.max_tokens must be >= 256");
      if (m.context_tokens < m.max_tokens + 2048) return err("llm.context_tokens must leave room for the prompt (>= max_tokens + 2048)");
      m.max_findings_per_call = get<int>(l, "max_findings_per_call", m.max_findings_per_call);
      if (m.max_findings_per_call < 1 || m.max_findings_per_call > 100) return err("llm.max_findings_per_call must be in [1, 100]");
      auto bw = parseDuration(get<std::string>(l, "batch_window", "30s"));
      if (!bw) return err("llm.batch_window: " + bw.error());
      m.batch_window = bw.value();
      if (l["language"]) return err("llm.language was removed: use the top-level 'language: it | en'");
      m.focus_file = get<std::string>(l, "focus_file", "");
    }

    if (const YAML::Node an = root["analysis"]) {
      AnalysisConfig& x = c.analysis;
      auto dur = [&](const YAML::Node& n, const char* key, std::chrono::seconds def, std::chrono::seconds min, const std::string& what) -> Result<std::chrono::seconds> {
        auto d = parseDuration(get<std::string>(n, key, std::to_string(def.count()) + "s"));
        if (!d) return err(what + ": " + d.error());
        if (d.value() < min) return err(what + " is too short");
        return d.value();
      };
      if (const YAML::Node e = an["explain_updates"]) {
        x.explain_updates = get<bool>(e, "enabled", x.explain_updates);
        auto w = dur(e, "window", x.explain_window, std::chrono::hours(1), "analysis.explain_updates.window");
        if (!w) return err(w.error());
        x.explain_window = w.value();
      }
      if (const YAML::Node e = an["incidents"]) {
        x.incidents = get<bool>(e, "enabled", x.incidents);
        auto w = dur(e, "window", x.incident_window, std::chrono::minutes(10), "analysis.incidents.window");
        if (!w) return err(w.error());
        x.incident_window = w.value();
        const int mf = get<int>(e, "min_findings", static_cast<int>(x.incident_min_findings));
        if (mf < 2 || mf > 50) return err("analysis.incidents.min_findings must be in [2, 50]");
        x.incident_min_findings = static_cast<size_t>(mf);
      }
      if (const YAML::Node e = an["peers"]) {
        x.peers = get<bool>(e, "enabled", x.peers);
        const int mg = get<int>(e, "min_group_size", static_cast<int>(x.peer_min_group));
        if (mg < 3 || mg > 1000) return err("analysis.peers.min_group_size must be in [3, 1000] (with two hosts there is no 'majority')");
        x.peer_min_group = static_cast<size_t>(mg);
        x.peer_min_share = get<double>(e, "min_share", x.peer_min_share);
        if (x.peer_min_share <= 0.5 || x.peer_min_share > 1.0) return err("analysis.peers.min_share must be in (0.5, 1]");
      }
      if (const YAML::Node e = an["logs"]) {
        x.log_templates = get<bool>(e, "templates", x.log_templates);
        const int n = get<int>(e, "max_new_per_cycle", static_cast<int>(x.log_templates_per_cycle));
        if (n < 1 || n > 500) return err("analysis.logs.max_new_per_cycle must be in [1, 500]");
        x.log_templates_per_cycle = static_cast<size_t>(n);
      }
      if (const YAML::Node e = an["outbound"]) {
        x.beaconing = get<bool>(e, "beaconing", x.beaconing);
        x.outbound_countries = get<bool>(e, "new_countries", x.outbound_countries);
        x.traffic_spikes = get<bool>(e, "traffic_spikes", x.traffic_spikes);
      }
      if (const YAML::Node e = an["travel"]) {
        x.travel = get<bool>(e, "enabled", x.travel);
        x.travel_max_kmh = get<double>(e, "max_speed_kmh", x.travel_max_kmh);
        x.travel_min_km = get<double>(e, "min_distance_km", x.travel_min_km);
        if (x.travel_max_kmh < 100 || x.travel_max_kmh > 5000) return err("analysis.travel.max_speed_kmh must be in [100, 5000]");
        if (x.travel_min_km < 50 || x.travel_min_km > 20000) return err("analysis.travel.min_distance_km must be in [50, 20000]");
      }
    }

    if (const YAML::Node ti = root["threat_intel"]) {
      ThreatIntelConfig& x = c.threat_intel;
      x.enabled = get<bool>(ti, "enabled", x.enabled);
      x.dir = get<std::string>(ti, "dir", "");
      auto re = parseDuration(get<std::string>(ti, "refresh_every", "12h"));
      if (!re) return err("threat_intel.refresh_every: " + re.error());
      if (re.value().count() < 3600) return err("threat_intel.refresh_every must be at least 1h (be polite with public services)");
      x.refresh_every = re.value();
      if (const YAML::Node ls = ti["lists"]) {
        if (!ls.IsSequence()) return err("threat_intel.lists must be a list");
        std::set<std::string> seen;
        for (const auto& l : ls) {
          ThreatIntelConfig::List item;
          item.name = get<std::string>(l, "name", "");
          item.url = get<std::string>(l, "url", "");
          item.category = get<std::string>(l, "category", "attacker");
          if (item.name.empty() || item.name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos) return err("threat_intel.lists: every list needs a 'name' (letters, digits, _ -)");
          if (!seen.insert(item.name).second) return err("threat_intel.lists: duplicate name '" + item.name + "'");
          if (!util::startsWith(item.url, "https://") && !util::startsWith(item.url, "http://")) return err("threat_intel.lists." + item.name + ".url must start with https://");
          if (item.category != "c2" && item.category != "attacker" && item.category != "scanner" && item.category != "compromised") return err("threat_intel.lists." + item.name + ".category must be c2, attacker, scanner or compromised");
          x.lists.push_back(std::move(item));
        }
      }
    }

    if (const YAML::Node g = root["geo"]) c.geo.db_path = get<std::string>(g, "db_path", "");

    if (const YAML::Node w = root["web"]) {
      WebConfig& x = c.web;
      x.enabled = get<bool>(w, "enabled", x.enabled);
      x.listen = get<std::string>(w, "listen", x.listen);
      x.port = get<int>(w, "port", x.port);
      x.token_file = get<std::string>(w, "token_file", "");
      if (x.listen.empty()) return err("web.listen must not be empty");
      if (x.port < 1 || x.port > 65535) return err("web.port must be in [1, 65535]");
    }

    if (const YAML::Node v = root["vuln"]) {
      VulnConfig& x = c.vuln;
      x.enabled = get<bool>(v, "enabled", x.enabled);
      x.db_path = get<std::string>(v, "db_path", "");
      auto re = parseDuration(get<std::string>(v, "refresh_every", "6h"));
      auto me = parseDuration(get<std::string>(v, "match_every", "1h"));
      if (!re) return err("vuln.refresh_every: " + re.error());
      if (!me) return err("vuln.match_every: " + me.error());
      x.refresh_every = re.value();
      x.match_every = me.value();
      if (x.refresh_every.count() < 1800) return err("vuln.refresh_every must be at least 30m (be polite with public services)");
      if (x.match_every.count() < 60) return err("vuln.match_every must be at least 1m");
      x.kev = get<bool>(v, "kev", x.kev);
      x.nvd = get<bool>(v, "nvd", x.nvd);
      x.cwe = get<bool>(v, "cwe", x.cwe);
      x.osv = get<bool>(v, "osv", x.osv);
      x.cpe_match = get<std::string>(v, "cpe_match", "auto");
      if (x.cpe_match != "auto" && x.cpe_match != "always" && x.cpe_match != "never") return err("vuln.cpe_match must be auto, always or never");
      x.nvd_initial_days = get<int>(v, "nvd_initial_days", x.nvd_initial_days);
      if (x.nvd_initial_days < 1 || x.nvd_initial_days > 3650) return err("vuln.nvd_initial_days must be in [1, 3650]");
      x.nvd_api_key_file = get<std::string>(v, "nvd_api_key_file", "");
      x.min_cvss = get<double>(v, "min_cvss", x.min_cvss);
      if (x.min_cvss < 0 || x.min_cvss > 10) return err("vuln.min_cvss must be in [0, 10]");
      x.new_within_days = get<int>(v, "new_within_days", x.new_within_days);
      if (x.new_within_days < 1 || x.new_within_days > 365) return err("vuln.new_within_days must be in [1, 365]");
      for (auto [key, field] : std::initializer_list<std::pair<const char*, std::string*>>{{"kev_url", &x.kev_url}, {"nvd_url", &x.nvd_url}, {"cwe_url", &x.cwe_url}, {"osv_url", &x.osv_url}}) {
        *field = get<std::string>(v, key, *field);
        while (field->size() > 8 && field->back() == '/') field->pop_back();
        if (!util::startsWith(*field, "https://") && !util::startsWith(*field, "http://")) return err(std::string("vuln.") + key + " must start with https:// (or http:// for a local mirror)");
      }
      x.epss = get<bool>(v, "epss", x.epss);
      x.exposure = get<bool>(v, "exposure", x.exposure);
      x.epss_url = get<std::string>(v, "epss_url", x.epss_url);
      if (!util::startsWith(x.epss_url, "https://") && !util::startsWith(x.epss_url, "http://")) return err("vuln.epss_url must start with https:// (or http:// for a local mirror)");
      x.timeout = std::chrono::seconds(get<int>(v, "timeout", 120));
      if (x.timeout.count() <= 0) return err("vuln.timeout must be > 0");
    }

    if (const YAML::Node a = root["alerting"]) {
      AlertingConfig& al = c.alerting;
      al.min_severity = get<std::string>(a, "min_severity", al.min_severity);
      if (!kSeverities.count(al.min_severity)) return err("invalid alerting.min_severity '" + al.min_severity + "'");
      auto delay = parseDuration(get<std::string>(a, "alert_delay", "2m"));
      auto cool = parseDuration(get<std::string>(a, "cooldown", "5m"));
      if (!delay) return err("alerting.alert_delay: " + delay.error());
      if (!cool) return err("alerting.cooldown: " + cool.error());
      al.alert_delay = delay.value();
      al.cooldown = cool.value();
      al.max_per_hour = get<int>(a, "max_per_hour", al.max_per_hour);
      if (al.max_per_hour < 1 || al.max_per_hour > 120) return err("alerting.max_per_hour must be in [1, 120]");
      al.subject_prefix = get<std::string>(a, "subject_prefix", al.subject_prefix);
      if (a["language"]) return err("alerting.language was removed: use the top-level 'language: it | en'");
      al.recipients = getList(a, "recipients");
      for (const auto& r : al.recipients) {
        if (!validEmailAddress(r)) return err("invalid recipient address '" + r + "'");
      }
      if (const YAML::Node s = a["smtp"]) {
        SmtpConfig& sm = al.smtp;
        sm.host = get<std::string>(s, "host", "");
        sm.port = get<int>(s, "port", 587);
        sm.user = get<std::string>(s, "user", "");
        sm.password_file = get<std::string>(s, "password_file", "");
        sm.from = get<std::string>(s, "from", "");
        sm.tls = get<std::string>(s, "tls", "starttls");
        sm.timeout = std::chrono::seconds(get<int>(s, "timeout", 30));
        if (sm.port < 1 || sm.port > 65535) return err("alerting.smtp.port is invalid");
        if (sm.tls != "starttls" && sm.tls != "ssl" && sm.tls != "none") return err("alerting.smtp.tls must be starttls, ssl or none");
        if (sm.timeout.count() <= 0) return err("alerting.smtp.timeout must be > 0");
        const bool local = sm.host == "localhost" || sm.host == "127.0.0.1" || sm.host == "::1";
        if (sm.tls == "none" && !sm.user.empty() && !local) {
          return err("alerting.smtp: 'user' is set ('" + sm.user + "') but tls is 'none': the password would travel in clear text. "
                     "For a relay that needs no login, delete the 'user' (and 'password_file') lines; otherwise use tls: starttls or ssl");
        }
      }
      if (const YAML::Node d = a["digest"]) {
        al.digest_enabled = get<bool>(d, "enabled", true);
        auto ev = parseDuration(get<std::string>(d, "every", "24h"));
        if (!ev) return err("alerting.digest.every: " + ev.error());
        al.digest_every = ev.value();
        if (al.digest_every.count() < 600) return err("alerting.digest.every must be at least 10m");
        al.digest_at = get<std::string>(d, "at", "");
        if (!al.digest_at.empty() && !validClock(al.digest_at)) return err("alerting.digest.at must be HH:MM");
        al.digest_min_severity = get<std::string>(d, "min_severity", al.digest_min_severity);
        if (!kSeverities.count(al.digest_min_severity)) return err("invalid alerting.digest.min_severity");
        al.digest_when_empty = get<bool>(d, "send_when_empty", false);
      }
      if (!al.recipients.empty()) {
        if (al.smtp.host.empty() || al.smtp.from.empty()) return err("alerting: recipients are set but smtp.host / smtp.from are missing");
        if (!validEmailAddress(addressOf(al.smtp.from))) return err("alerting.smtp.from is not a valid address");
      }
    }

    const YAML::Node targets = root["targets"];
    if (!targets || !targets.IsSequence() || targets.size() == 0) {
      return err("at least one entry in 'targets' is required");
    }
    std::set<std::string> names;
    for (const auto& tn : targets) {
      auto t = parseTarget(tn);
      if (!t) return err(t.error());
      if (!names.insert(t.value().name).second) return err("duplicate target name '" + t.value().name + "'");
      c.targets.push_back(std::move(t.value()));
    }
    if (c.threat_intel.lists.empty()) c.threat_intel.lists = defaultThreatLists();
    return c;
  } catch (const YAML::Exception& e) {
    return err(std::string("yaml error: ") + e.what());
  }
}

Result<Config> loadConfigFile(const std::string& path) {
  std::ifstream f(path);
  if (!f) return err("cannot open config file '" + path + "'");
  std::ostringstream ss;
  ss << f.rdbuf();
  return parseConfig(ss.str());
}

}  // namespace agent
