#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <iostream>

#include "analysis/rule.h"
#include "app/agent.h"
#include "app/format.h"
#include "app/synthesis.h"
#include "core/config.h"
#include "core/logger.h"
#include "core/util.h"
#include "llm/assess.h"
#include "llm/context.h"
#include "llm/http_client.h"
#include "llm/llm_client.h"
#include "llm/prompt.h"
#include "llm/reasoner.h"
#include "report/mailer.h"
#include "report/notifier.h"
#include "report/report.h"
#include "report/text_util.h"
#include "transport/factory.h"
#include "transport/gate.h"
#include "transport/local_transport.h"
#include "transport/ssh_transport.h"
#include "vuln/feed_parsers.h"
#include "vuln/feed_sync.h"
#include "vuln/intel.h"
#include "vuln/matcher.h"
#include "vuln/vuln_context.h"
#include "vuln/vuln_db.h"
#include "vuln/vuln_service.h"
#include "vuln/cvss.h"
#include "geo/geo_db.h"
#include "analysis/incident.h"
#include "intel/intel_service.h"
#include "intel/threat_intel.h"
#include "web/api.h"
#include "web/http_server.h"
#include "vuln/cwe_names.h"

namespace {

std::atomic<bool> g_stop{false};
std::atomic<bool> g_reload{false};
void onHup(int) { g_reload = true; }
void onSignal(int) { g_stop = true; }

void usage() {
  std::cerr << "usage: dyna_cyber_agent --config <file> [mode]\n"
               "modes:\n"
               "  (none)               run continuously until SIGINT/SIGTERM\n"
               "  --check              validate config and rules, run a transport self-test, exit\n"
               "  --once               run every collector once, store and print the snapshots, exit\n"
               "  --events [--all]     list open findings (all = including accepted)\n"
               "  --event <id>         show one finding in detail\n"
               "  --accept <id>        accept a finding: its drift becomes part of the baseline\n"
               "  --geo-update         download the offline IP location database (DB-IP City Lite) used by the attack map\n"
               "  --geo-import <file>  build that database from a CSV (or .csv.gz) you downloaded yourself\n"
               "  --geo-status         show the location database in use\n"
               "  --web                serve only the local web console (no collection); the daemon serves it too when web.enabled\n"
               "  --incidents          chain the open findings into incidents now and list them\n"
               "  --intel-update       download the public threat-intelligence IP lists now\n"
               "  --intel-status       show the threat lists the agent holds\n"
               "  --baseline-status    show baseline mode and size per target\n"
               "  --baseline-lock      end the learning phase now for every target\n"
               "  --analyze            ask the LLM to assess open findings that have no assessment yet\n"
               "  --llm-prompt         print the exact prompt that would be sent to the LLM (no network)\n"
               "  --llm-ping           check that llama-server is reachable and ready\n"
               "  --report-preview <alert|digest|test> [--out <dir>]\n"
               "                       render the mail as .html/.txt files; sends nothing\n"
               "  --send-test-mail     send a test mail to the configured recipients\n"
               "  --notifications      list the mails the agent sent (or failed to send)\n"
               "  --ssh-test <target|all>\n"
               "                       connect to ssh target(s), check the remote tools and privileges, collect nothing\n"
               "  --version            print the version and exit\n"
               "  --print-gate         print the remote read-only gate script (for installed/hardened mode); needs no config\n"
               "  --vuln-sync [kev|nvd|cwe|epss|all]\n"
               "                       download the CVE / CISA KEV / CWE feeds now (resumable; Ctrl+C is safe)\n"
               "  --vuln-status        state of the vulnerability database and of the matching per target\n"
               "  --vuln-search <text|CVE-id>\n"
               "                       look a CVE up in the local database\n"
               "  --vuln-check [target] match the latest software inventory of a target against the database, now\n";
}

int64_t nowTs() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// Everything needed to talk to llama-server; built only when something needs it.
struct LlmRuntime {
  agent::CurlHttpClient http;
  std::unique_ptr<agent::LlmClient> client;
  std::unique_ptr<agent::Reasoner> reasoner;
};

agent::Result<std::unique_ptr<LlmRuntime>> buildLlm(const agent::Config& cfg) {
  auto key = agent::readSecretFile(cfg.llm.api_key_file);
  if (!key) return agent::err(key.error());
  std::string focus;
  if (!cfg.llm.focus_file.empty()) {
    std::ifstream f(cfg.llm.focus_file);
    if (!f) return agent::err("cannot read llm.focus_file '" + cfg.llm.focus_file + "'");
    std::ostringstream ss;
    ss << f.rdbuf();
    focus = ss.str();
  }
  auto rt = std::make_unique<LlmRuntime>();
  rt->client = std::make_unique<agent::LlmClient>(cfg.llm, rt->http, key.value());
  agent::ReasonerOptions o;
  o.language = cfg.llm.language;
  o.admin_focus = focus;
  o.max_findings_per_call = static_cast<size_t>(cfg.llm.max_findings_per_call);
  o.context_tokens = static_cast<size_t>(cfg.llm.context_tokens);
  o.max_tokens = cfg.llm.max_tokens;
  rt->reasoner = std::make_unique<agent::Reasoner>(*rt->client, o);
  return rt;
}

// Everything the vulnerability feature needs, built only when vuln.enabled is true.
struct VulnRuntime {
  agent::CurlHttpClient http;
  std::unique_ptr<agent::VulnDb> db;
  std::unique_ptr<agent::FeedSync> sync;
  agent::VulnContext ctx;
};

agent::Result<std::unique_ptr<VulnRuntime>> buildVuln(const agent::Config& cfg, agent::Store& store) {
  auto rt = std::make_unique<VulnRuntime>();
  const std::string path = cfg.vuln.db_path.empty() ? cfg.state_dir + "/vuln.db" : cfg.vuln.db_path;
  auto db = agent::VulnDb::open(path);
  if (!db) return agent::err(db.error());
  rt->db = std::move(db.value());
  auto key = agent::readSecretFile(cfg.vuln.nvd_api_key_file);
  if (!key) return agent::err(key.error());
  agent::SyncHooks hooks;
  hooks.nvd_api_key = key.value();
  hooks.cancelled = [] { return g_stop.load(); };
  rt->sync = std::make_unique<agent::FeedSync>(*rt->db, rt->http, cfg.vuln, hooks);
  rt->ctx = agent::VulnContext{rt->db.get(), &rt->http, rt->sync.get(), cfg.vuln, &store};
  return rt;
}

std::string hostName() {
  char b[256] = {0};
  return ::gethostname(b, sizeof(b) - 1) == 0 && b[0] ? b : "unknown-host";
}

agent::ReportContext reportContext(const agent::Config& cfg, VulnRuntime* vr = nullptr, agent::Store* store = nullptr) {
  agent::ReportContext ctx;
  ctx.host_label = hostName();
  ctx.subject_prefix = cfg.alerting.subject_prefix;
  ctx.lang = cfg.alerting.language;
  ctx.llm_enabled = cfg.llm.enabled;
  // expected interval per target/collector, to spot collectors that went silent
  for (const auto& t : cfg.targets) {
    std::vector<std::string> names = t.collectors.empty() ? agent::collectorNames() : t.collectors;
    for (const auto& n : names) {
      auto c = agent::makeCollector(n);
      if (!c) continue;
      const auto it = t.intervals.find(n);
      ctx.intervals[t.name + "|" + n] = (it != t.intervals.end() ? it->second : c->defaultInterval()).count();
    }
  }
  if (vr && store) {
    ctx.intel = agent::makeIntelProvider(*vr->db, *store, cfg.alerting.language);
    ctx.cwe_name = agent::makeCweNameProvider(*vr->db);
  }
  return ctx;
}


// The local web console: its own model client (so its requests never share state with the collection loop),
// the JSON API and the HTTP server. Member order matters: the server stops first, then running jobs finish.
struct WebRuntime {
  std::unique_ptr<agent::GeoDb> geo;
  std::unique_ptr<LlmRuntime> llm;
  std::unique_ptr<agent::WebApi> api;
  agent::HttpServer server;
};

// The console token: read from web.token_file (default <state_dir>/web.token); created with mode 0600 when missing.
agent::Result<std::string> loadWebToken(const agent::Config& cfg) {
  const std::string path = cfg.web.token_file.empty() ? cfg.state_dir + "/web.token" : cfg.web.token_file;
  {
    std::ifstream in(path);
    std::string tok;
    if (in && std::getline(in, tok) && tok.size() >= 16) return tok;
  }
  unsigned char raw[24];
  std::ifstream rnd("/dev/urandom", std::ios::binary);
  if (!rnd.read(reinterpret_cast<char*>(raw), sizeof(raw))) return agent::err("cannot read /dev/urandom");
  static const char* hex = "0123456789abcdef";
  std::string tok;
  for (unsigned char b : raw) { tok += hex[b >> 4]; tok += hex[b & 15]; }
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return agent::err("cannot write " + path + ": " + std::strerror(errno));
  const std::string line = tok + "\n";
  const bool ok = ::write(fd, line.data(), line.size()) == static_cast<ssize_t>(line.size());
  ::close(fd);
  if (!ok) return agent::err("cannot write " + path);
  spdlog::info("web console token created in {}", path);
  return tok;
}

agent::Result<std::unique_ptr<WebRuntime>> startWeb(const agent::Config& cfg, agent::Store& store, VulnRuntime* vr) {
  auto tok = loadWebToken(cfg);
  if (!tok) return agent::err(tok.error());
  auto rt = std::make_unique<WebRuntime>();
  {
    auto g = agent::GeoDb::open(cfg.geo.db_path.empty() ? cfg.state_dir + "/geo.db" : cfg.geo.db_path);
    if (g) rt->geo = std::move(g.value());
    else spdlog::warn("attack map without locations: {}", g.error());
  }
  agent::WebApi::Deps d;
  d.geo = rt->geo.get();
  d.store = &store;
  d.cfg = cfg;
  d.report_ctx = reportContext(cfg, vr, &store);
  d.token = tok.value();
  d.version = AGENT_VERSION;
  if (cfg.llm.enabled) {
    auto l = buildLlm(cfg);
    if (l) {
      rt->llm = std::move(l.value());
      d.llm = rt->llm->client.get();
      d.llm_options = rt->llm->reasoner->options();
    } else {
      spdlog::warn("web console without the language model: {}", l.error());
    }
  }
  rt->api = std::make_unique<agent::WebApi>(std::move(d));
  auto* api = rt->api.get();
  auto started = rt->server.start(cfg.web.listen, cfg.web.port, [api](const agent::HttpRequest& r) { return api->handle(r); });
  if (!started) return agent::err(started.error());
  const bool loopback = cfg.web.listen == "127.0.0.1" || cfg.web.listen == "::1" || cfg.web.listen == "localhost";
  spdlog::info("web console on http://{}:{}/ (token in {})", cfg.web.listen, rt->server.port(),
               cfg.web.token_file.empty() ? cfg.state_dir + "/web.token" : cfg.web.token_file);
  if (!loopback) spdlog::warn("web console listens on {}: traffic and token travel in clear text, put a TLS reverse proxy in front", cfg.web.listen);
  return rt;
}

// SMTP password: read from a file; warn when other users can read it.
agent::Result<std::string> readSmtpPassword(const agent::SmtpConfig& smtp) {
  if (smtp.user.empty() || smtp.password_file.empty()) return std::string();  // no login: nothing to read
  struct stat st {};
  if (::stat(smtp.password_file.c_str(), &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO))) {
    spdlog::warn("{} is readable by other users: chmod 600 it", smtp.password_file);
  }
  return agent::readSecretFile(smtp.password_file);
}

int selfTest() {
  agent::LocalTransport t;
  auto up = t.readFile("/proc/uptime", 4096);
  if (!up) {
    spdlog::error("self-test: {}", up.error());
    return 1;
  }
  spdlog::info("self-test: /proc/uptime = {}", up.value().data.substr(0, up.value().data.find('\n')));
  auto r = t.run({"uname", "-sr"});
  if (!r || r.value().exit_code != 0) {
    spdlog::error("self-test: uname failed");
    return 1;
  }
  spdlog::info("self-test: kernel = {}", r.value().out.substr(0, r.value().out.find('\n')));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  std::string config_path, mode, out_dir, preview_kind, ssh_target, vuln_arg;
  int64_t id_arg = 0;
  bool all = false;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--config" && i + 1 < argc) {
      config_path = argv[++i];
    } else if (a == "--version") {
      std::cout << "dyna_cyber_agent " << AGENT_VERSION << "\n";
      return 0;
    } else if (a == "--print-gate") {
      std::cout << agent::Gate::script();
      return 0;
    } else if (a == "--ssh-test" && i + 1 < argc) {
      ssh_target = argv[++i];
      if (!mode.empty()) { usage(); return 2; }
      mode = a;
    } else if (a == "--vuln-sync" || a == "--vuln-check") {
      if (!mode.empty()) { usage(); return 2; }
      mode = a;
      if (i + 1 < argc && argv[i + 1][0] != '-') vuln_arg = argv[++i];
      if (a == "--vuln-sync" && !vuln_arg.empty() && vuln_arg != "kev" && vuln_arg != "nvd" && vuln_arg != "cwe" && vuln_arg != "epss" && vuln_arg != "all") { usage(); return 2; }
    } else if (a == "--vuln-search" && i + 1 < argc) {
      if (!mode.empty()) { usage(); return 2; }
      vuln_arg = argv[++i];
      mode = a;
    } else if (a == "--out" && i + 1 < argc) {
      out_dir = argv[++i];
    } else if (a == "--report-preview" && i + 1 < argc) {
      preview_kind = argv[++i];
      if (!mode.empty() || (preview_kind != "alert" && preview_kind != "digest" && preview_kind != "test")) { usage(); return 2; }
      mode = a;
    } else if (a == "--geo-import" && i + 1 < argc) {
      if (!mode.empty()) { usage(); return 2; }
      mode = a;
      out_dir = argv[++i];  // the file to import
    } else if (a == "--all") {
      all = true;
    } else if ((a == "--event" || a == "--accept") && i + 1 < argc) {
      const auto v = agent::util::parseUint(argv[++i]);
      if (!v) { usage(); return 2; }
      id_arg = static_cast<int64_t>(*v);
      mode = a;
    } else if (a == "--check" || a == "--once" || a == "--events" || a == "--baseline-status" || a == "--baseline-lock" ||
               a == "--analyze" || a == "--llm-prompt" || a == "--llm-ping" ||
               a == "--send-test-mail" || a == "--notifications" || a == "--vuln-status" || a == "--web" || a == "--geo-update" || a == "--geo-status" || a == "--incidents" || a == "--intel-update" || a == "--intel-status") {
      if (!mode.empty()) { usage(); return 2; }
      mode = a;
    } else {
      usage();
      return 2;
    }
  }
  if (config_path.empty()) { usage(); return 2; }

  auto cfg = agent::loadConfigFile(config_path);
  if (!cfg) {
    std::cerr << "config error: " << cfg.error() << "\n";
    return 1;
  }
  agent::logger::init(cfg.value().log_level, cfg.value().log_file);
  agent::SshTransport::setCancelFlag(&g_stop);  // SIGTERM must not wait for a slow remote host

  if (mode == "--ssh-test") {
    int bad = 0, tested = 0;
    for (const auto& t : cfg.value().targets) {
      if (ssh_target != "all" && ssh_target != t.name) continue;
      if (t.transport != "ssh") {
        if (ssh_target != "all") std::cerr << t.name << ": not an ssh target\n";
        continue;
      }
      ++tested;
      agent::SshOptions o;
      o.host = t.ssh.host; o.port = t.ssh.port; o.user = t.ssh.user; o.key_file = t.ssh.key_file;
      o.known_hosts = t.ssh.known_hosts; o.proxy_jump = t.ssh.proxy_jump; o.ssh_binary = t.ssh.ssh_binary;
      o.gate_mode = t.ssh.gate; o.gate_path = t.ssh.gate_path; o.sudo = t.ssh.sudo;
      o.connect_timeout = std::chrono::seconds(t.ssh.connect_timeout);
      o.op_timeout = std::chrono::seconds(t.ssh.op_timeout);
      agent::SshTransport tr(o);
      const auto t0 = std::chrono::steady_clock::now();
      auto host = tr.connect();
      if (!host) { std::cout << t.name << ": FAILED  " << host.error() << "\n"; ++bad; continue; }
      const auto ms_connect = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
      auto caps = tr.capabilities();
      std::cout << t.name << ": connected to '" << host.value() << "' in " << ms_connect << " ms (gate: " << t.ssh.gate << (t.ssh.sudo ? " + sudo" : "") << ")\n";
      if (!caps) { std::cout << "  capabilities: FAILED " << caps.error() << "\n"; ++bad; continue; }
      std::cout << "  remote tools: " << caps.value() << "\n";
      if (caps.value().find("MISSING") != std::string::npos) {
        std::cout << "  PROBLEM: GNU coreutils/findutils are required on the target (base64, find -printf, stat -c, sha256sum, head, grep)\n";
        ++bad;
      }
      if (caps.value().find("uid=0") == std::string::npos) {
        std::cout << "  NOTE: not running as root: other users' /proc/<pid>/exe, fd and maps are unreadable, so processes and socket\n"
                     "        owners will be partly invisible. See USAGE.md (installed gate + sudo, or pam_cap) to grant read access.\n";
      }
      // how fast is a realistic batch?
      const auto t1 = std::chrono::steady_clock::now();
      auto pids = tr.listDir("/proc");
      size_t files = 0, readable = 0;
      if (pids) {
        std::vector<agent::ReadOp> ops;
        for (const auto& e : pids.value()) if (agent::util::allDigits(e.name)) ops.push_back(agent::ReadOp::file("/proc/" + e.name + "/stat", 4096));
        files = ops.size();
        for (const auto& r : tr.bulk(ops)) readable += r.ok;
      }
      const auto ms_scan = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t1).count();
      std::cout << "  scan test: " << readable << "/" << files << " process stat files read in " << ms_scan << " ms\n";
      auto r = tr.run({"uname", "-sr"});
      std::cout << "  run test: " << (r && r.value().exit_code == 0 ? "ok (" + std::string(agent::util::trim(r.value().out)) + ")" : "FAILED " + (r ? r.value().out : r.error())) << "\n";
    }
    if (tested == 0) { std::cerr << "no matching ssh target\n"; return 1; }
    return bad ? 1 : 0;
  }

  auto rules = agent::loadRulesDir(cfg.value().rules_dir);
  if (!rules) {
    spdlog::error("{}", rules.error());
    return 1;
  }
  spdlog::info("{} rule(s) loaded from {}", rules.value().size(), cfg.value().rules_dir);
  if (mode == "--check") {
    spdlog::info("{} target(s) configured; learning window {}s", cfg.value().targets.size(), cfg.value().baseline_learning.count());
    spdlog::info("LLM: {} ({}), not contacted by --check; use --llm-ping", cfg.value().llm.enabled ? "enabled" : "disabled", cfg.value().llm.url);
    if (auto l = buildLlm(cfg.value()); !l) {
      spdlog::error("{}", l.error());
      return 1;
    }
    const auto& vu = cfg.value().vuln;
    if (vu.enabled) {
      spdlog::info("vulnerability intelligence: enabled (kev={} nvd={} cwe={} osv={} cpe_match={}), refresh every {}s; feeds are not contacted by --check", vu.kev, vu.nvd, vu.cwe,
                   vu.osv, vu.cpe_match, vu.refresh_every.count());
      if (auto k = agent::readSecretFile(vu.nvd_api_key_file); !k) { spdlog::error("{}", k.error()); return 1; }
    } else {
      spdlog::info("vulnerability intelligence: disabled");
    }
    {
      const auto& an = cfg.value().analysis;
      spdlog::info("analysis: explain_updates={} incidents={} peers={} log_templates={} beaconing={} new_countries={} traffic_spikes={} travel={}", an.explain_updates, an.incidents, an.peers,
                   an.log_templates, an.beaconing, an.outbound_countries, an.traffic_spikes, an.travel);
      std::map<std::string, std::vector<std::string>> groups;
      for (const auto& t : cfg.value().targets) if (!t.group.empty()) groups[t.group].push_back(t.name);
      for (const auto& [g, members] : groups) {
        std::string list;
        for (const auto& m : members) list += (list.empty() ? "" : ", ") + m;
        if (members.size() >= an.peer_min_group) spdlog::info("group '{}': {} -> peer analysis on", g, list);
        else spdlog::warn("group '{}': {} -> {} member(s), peer analysis needs {}: it stays off", g, list, members.size(), an.peer_min_group);
      }
      const auto& ti = cfg.value().threat_intel;
      if (ti.enabled) spdlog::info("threat lists: {} configured, refreshed every {}s into {} (nothing is sent)", ti.lists.size(), ti.refresh_every.count(), ti.dir.empty() ? cfg.value().state_dir + "/intel" : ti.dir);
      else spdlog::info("threat lists: disabled");
    }
    const auto& al = cfg.value().alerting;
    if (al.recipients.empty()) {
      spdlog::warn("alerting: no recipients configured, no mail will be sent");
    } else {
      auto pw = readSmtpPassword(al.smtp);
      if (!pw) {
        spdlog::error("{}", pw.error());
        return 1;
      }
      spdlog::info("alerting: {} recipient(s) via {}:{} ({}); alerts >= {}, digest {}", al.recipients.size(), al.smtp.host, al.smtp.port, al.smtp.tls,
                   al.min_severity, al.digest_enabled ? (al.digest_at.empty() ? "every " + std::to_string(al.digest_every.count()) + "s" : "daily at " + al.digest_at) : "off");
    }
    return selfTest();
  }

  ::umask(027);  // everything the agent creates (database, previews, log) is private to its user and group
  std::error_code ec;
  std::filesystem::create_directories(cfg.value().state_dir, ec);  // agent-side state only
  {
    struct stat sd {};
    if (::stat(cfg.value().state_dir.c_str(), &sd) == 0 && (sd.st_mode & S_IWOTH)) spdlog::warn("state_dir {} is world-writable: anyone could tamper with the baseline and the findings", cfg.value().state_dir);
    else if (::stat(cfg.value().state_dir.c_str(), &sd) == 0 && (sd.st_mode & S_IROTH)) spdlog::warn("state_dir {} is readable by everyone (it holds the baseline and evidence): chmod 750 it", cfg.value().state_dir);
  }
  if (ec) {
    spdlog::error("cannot create state_dir '{}': {}", cfg.value().state_dir, ec.message());
    return 1;
  }
  auto store = agent::Store::open(cfg.value().state_dir + "/agent.db");
  if (!store) {
    spdlog::error("{}", store.error());
    return 1;
  }
  agent::Store& st = *store.value();

  std::unique_ptr<VulnRuntime> vr;
  if (cfg.value().vuln.enabled || mode.rfind("--vuln", 0) == 0) {
    auto r = buildVuln(cfg.value(), st);
    if (!r) {
      if (mode.rfind("--vuln", 0) == 0) { spdlog::error("{}", r.error()); return 1; }
      spdlog::error("vulnerability intelligence disabled: {}", r.error());
    } else {
      vr = std::move(r.value());
    }
  }

  // ---- administration commands (no collection) ------------------------------
  if (mode == "--events") {
    auto fs = st.listFindings(all ? "" : "open", 1000);
    if (!fs) { spdlog::error("{}", fs.error()); return 1; }
    for (const auto& f : fs.value()) std::cout << agent::formatFinding(f, false) << "\n";
    std::cout << fs.value().size() << " finding(s)\n";
    return 0;
  }
  if (mode == "--event") {
    auto f = st.getFinding(id_arg);
    if (!f) { spdlog::error("{}", f.error()); return 1; }
    if (!f.value()) { std::cerr << "no such finding: " << id_arg << "\n"; return 1; }
    std::cout << agent::formatFinding(*f.value(), true);
    if (auto a = st.latestAssessment(id_arg); a && a.value()) std::cout << agent::formatAssessment(*a.value());
    return 0;
  }
  if (mode == "--accept") {
    auto r = st.acceptFinding(id_arg, nowTs());
    if (!r) { spdlog::error("{}", r.error()); return 1; }
    std::cout << "finding " << id_arg << " accepted; its drift was added to the baseline\n";
    return 0;
  }
  if (mode == "--baseline-status" || mode == "--baseline-lock") {
    for (const auto& t : cfg.value().targets) {
      if (mode == "--baseline-lock") {
        if (auto r = st.lockBaseline(t.name, nowTs()); !r) { spdlog::error("{}", r.error()); return 1; }
      }
      auto m = st.baselineMeta(t.name, nowTs());
      auto n = st.baselineSize(t.name);
      if (!m || !n) { spdlog::error("{}", !m ? m.error() : n.error()); return 1; }
      const bool learning = !m.value().locked && nowTs() < m.value().started_at + cfg.value().baseline_learning.count();
      std::cout << t.name << ": " << (learning ? "LEARNING" : "ENFORCING") << (m.value().locked ? " (locked)" : "") << ", "
                << n.value() << " identities\n";
      const int64_t ends = m.value().started_at + cfg.value().baseline_learning.count();
      std::cout << "  learning started " << agent::report::fmtTime(m.value().started_at) << ", window " << cfg.value().baseline_learning.count() / 86400 << " day(s)\n";
      if (learning) {
        std::cout << "  ends " << agent::report::fmtTime(ends) << " (" << (ends - nowTs() + 86399) / 86400
                  << " day(s) left): until then new processes/ports/users/cron jobs are learned silently, not reported; vulnerabilities and log rules are always active\n";
      } else if (m.value().locked) {
        std::cout << "  closed early with --baseline-lock\n";
      } else {
        std::cout << "  ended " << agent::report::fmtTime(ends) << ": anything new is reported\n";
      }
    }
    return 0;
  }

  // ---- vulnerability commands ---------------------------------------------------
  if (mode.rfind("--vuln", 0) == 0) {
    auto when = [&](const char* key) {
      auto m = vr->db->getMeta(key);
      return m && m.value() && !m.value()->empty() ? agent::report::fmtTime(std::stoll(*m.value())) : std::string("never");
    };
    auto lineOf = [](const agent::Observation& o) {
      std::ostringstream ss;
      const auto& d = o.data;
      ss << d.value("cve", std::string("?")) << "  " << d.value("package", std::string("?")) << " " << d.value("installed_version", std::string("?"));
      if (!d.value("fixed_version", std::string()).empty()) ss << " -> fixed in " << d.value("fixed_version", std::string());
      ss << "  cvss=";
      if (d.contains("cvss") && d["cvss"].is_number()) ss << d["cvss"].get<double>(); else ss << "n/a";
      ss << " [";
      for (size_t i = 0; i < o.tags.size(); ++i) ss << (i ? "," : "") << o.tags[i];
      ss << "]";
      return ss.str();
    };

    if (mode == "--vuln-sync") {
      struct sigaction sa {};
      sa.sa_handler = onSignal;
      sigaction(SIGINT, &sa, nullptr);
      sigaction(SIGTERM, &sa, nullptr);
      std::vector<agent::SyncReport> reps;
      if (vuln_arg.empty() || vuln_arg == "all") reps = vr->sync->syncAll();
      else if (vuln_arg == "kev") reps.push_back(vr->sync->syncKev());
      else if (vuln_arg == "nvd") reps.push_back(vr->sync->syncNvd());
      else if (vuln_arg == "epss") reps.push_back(vr->sync->syncEpss());
      else reps.push_back(vr->sync->syncCwe());
      int bad = 0;
      for (const auto& r : reps) {
        std::cout << r.feed << ": " << (r.ok ? (r.partial ? "PARTIAL" : "ok") : "FAILED") << " - " << r.message << "\n";
        if (!r.new_kev.empty()) {
          std::cout << "  newly exploited (CISA KEV):";
          for (size_t i = 0; i < r.new_kev.size() && i < 15; ++i) std::cout << " " << r.new_kev[i];
          std::cout << "\n";
        }
        bad += !r.ok;
      }
      if (reps.empty()) std::cout << "no feed enabled (vuln.kev / vuln.nvd / vuln.cwe / vuln.epss)\n";
      return bad ? 1 : 0;
    }

    if (mode == "--vuln-status") {
      const auto stt = vr->db->stats();
      std::cout << "database      : " << (cfg.value().vuln.db_path.empty() ? cfg.value().state_dir + "/vuln.db" : cfg.value().vuln.db_path) << "\n";
      if (stt) {
        std::cout << "records       : " << stt.value().cves << " CVE (" << stt.value().kev << " actively exploited), " << stt.value().cwes << " CWE descriptions, "
                  << stt.value().cpe_rows << " CPE ranges, " << stt.value().osv_vulns << " OSV advisories cached, " << stt.value().epss << " EPSS scores\n";
      }
      std::cout << "last sync     : NVD " << when("nvd_last_sync") << " | KEV " << when("kev_last_sync") << " | CWE " << when("cwe_last_sync") << " | EPSS " << when("epss_last_sync") << "\n";
      if (auto c = vr->db->getMeta("nvd_cursor"); c && c.value() && !c.value()->empty()) std::cout << "NVD position  : modifications up to " << agent::formatNvdTime(std::stoll(*c.value())) << " UTC";
      if (auto rs = vr->db->getMeta("nvd_resume"); rs && rs.value() && !rs.value()->empty()) std::cout << "  (a download is in progress and will resume)";
      std::cout << "\n";
      const auto& v = cfg.value().vuln;
      std::cout << "settings      : osv=" << v.osv << " cpe_match=" << v.cpe_match << " min_cvss=" << v.min_cvss << " new_within_days=" << v.new_within_days
                << " refresh_every=" << v.refresh_every.count() << "s match_every=" << v.match_every.count() << "s\n";
      for (const auto& t : cfg.value().targets) {
        auto pk = st.latest(t.name, "packages");
        auto vs = st.latest(t.name, "vulns");
        std::cout << "\n" << t.name << ":\n";
        if (pk && pk.value()) {
          const auto inv = agent::inventoryFromSnapshot(*pk.value());
          std::cout << "  inventory   : " << (inv ? inv->packages.size() : 0) << " packages, " << (inv ? inv->os.pretty_name + (inv->os.pretty_name.empty() ? inv->os.id + " " + inv->os.version_id : "") : "?")
                    << " (taken " << agent::report::fmtTime(pk.value()->ts) << ")\n";
          if (inv) {
            const auto eco = agent::osvEcosystem(inv->os);
            std::cout << "  matching    : " << (eco ? "OSV " + *eco + " (distribution advisories)" : "no OSV coverage for this OS: upstream-version matching only (less accurate)") << "\n";
          }
        } else {
          std::cout << "  inventory   : none yet (collector 'packages' has not run)\n";
        }
        if (vs && vs.value()) {
          for (const auto& o : vs.value()->observations) {
            if (o.type != "vuln.summary") continue;
            const auto& d = o.data;
            std::cout << "  last match  : " << agent::report::fmtTime(vs.value()->ts) << ": " << d.value("matches", 0) << " matches, " << d.value("listed", 0) << " listed, "
                      << d.value("kev_matches", 0) << " actively exploited; critical " << d["by_severity"].value("critical", 0) << ", high " << d["by_severity"].value("high", 0)
                      << ", medium " << d["by_severity"].value("medium", 0) << ", low " << d["by_severity"].value("low", 0) << ", unscored " << d["by_severity"].value("unscored", 0) << "\n";
          }
        }
      }
      return 0;
    }

    if (mode == "--vuln-search") {
      std::vector<agent::CveRow> rows;
      if (vuln_arg.rfind("CVE-", 0) == 0) {
        if (auto r = vr->db->getCve(vuln_arg); r && r.value()) rows.push_back(*r.value());
      } else if (auto r = vr->db->searchCves(vuln_arg, 20)) {
        rows = std::move(r.value());
      }
      if (rows.empty()) { std::cout << "no match in the local database (is it synchronised? see --vuln-status)\n"; return 0; }
      for (const auto& c : rows) {
        std::cout << c.id << "  cvss=";
        if (c.cvss) std::cout << *c.cvss << " (" << c.severity << ")"; else std::cout << "n/a";
        std::cout << (c.kev ? "  ACTIVELY EXPLOITED (CISA KEV, due " + agent::report::fmtDate(c.kev_due) + ")" : "") << "  published " << agent::report::fmtDate(c.published) << "\n";
        std::cout << "  " << agent::report::sanitize(c.summary, 500) << "\n";
        for (const auto& w : c.cwes) {
          std::string name;
          if (auto cw = vr->db->getCwe(w); cw && cw.value()) name = cw.value()->name;
          if (name.empty()) name = agent::builtinCweName(w);
          std::cout << "  " << w << " " << name << "\n";
        }
        if (c.kev && !c.kev_action.empty()) std::cout << "  required action: " << agent::report::sanitize(c.kev_action, 300) << "\n";
      }
      return 0;
    }

    // --vuln-check
    int checked = 0;
    for (const auto& t : cfg.value().targets) {
      if (!vuln_arg.empty() && vuln_arg != "all" && vuln_arg != t.name) continue;
      auto pk = st.latest(t.name, "packages");
      if (!pk || !pk.value()) { std::cout << t.name << ": no software inventory yet (run --once with the 'packages' collector first)\n"; continue; }
      const auto inv = agent::inventoryFromSnapshot(*pk.value());
      if (!inv) { std::cout << t.name << ": the inventory is empty\n"; continue; }
      ++checked;
      std::cout << t.name << ": matching " << inv->packages.size() << " packages (" << inv->os.id << " " << inv->os.version_id << ") ...\n";
      agent::VulnMatcher matcher(*vr->db, &vr->http, cfg.value().vuln, vr->sync.get());
      auto out = matcher.match(*inv);
      if (!out) { std::cout << "  FAILED: " << out.error() << "\n"; continue; }
      for (const auto& w : out.value().warnings) std::cout << "  ! " << w << "\n";
      for (const auto& o : out.value().observations) {
        if (o.type == "vuln.summary") {
          const auto& d = o.data;
          std::cout << "  " << d.value("matches", 0) << " matches (" << d.value("kev_matches", 0) << " actively exploited); critical " << d["by_severity"].value("critical", 0) << ", high "
                    << d["by_severity"].value("high", 0) << ", medium " << d["by_severity"].value("medium", 0) << ", low " << d["by_severity"].value("low", 0) << ", unscored "
                    << d["by_severity"].value("unscored", 0) << "; listed " << d.value("listed", 0) << " (cvss >= " << d.value("min_cvss", 0.0) << " or exploited)\n";
        }
      }
      size_t shown = 0;
      for (const auto& o : out.value().observations) {
        if (o.type != "vuln.match") continue;
        std::cout << "  * " << lineOf(o) << "\n";
        if (++shown >= 40) { std::cout << "  ... (more not shown)\n"; break; }
      }
    }
    if (checked == 0) { std::cerr << "no target checked\n"; return 1; }
    return 0;
  }

  // ---- mail commands ----------------------------------------------------------
  if (mode == "--notifications") {
    auto ns = st.listNotifications(50);
    if (!ns) { spdlog::error("{}", ns.error()); return 1; }
    for (const auto& n : ns.value()) {
      std::cout << "#" << n.id << " " << agent::report::fmtTime(n.created_at) << " " << n.kind << " " << n.status << " -> " << n.recipients << " | " << n.subject
                << (n.error.empty() ? "" : " | ERROR: " + n.error) << "\n";
    }
    std::cout << ns.value().size() << " notification(s)\n";
    return 0;
  }
  if (mode == "--report-preview") {
    const auto ctx = reportContext(cfg.value(), vr.get(), &st);
    const int64_t now = nowTs();
    const agent::Severity thr = *agent::parseSeverity(cfg.value().alerting.min_severity);
    agent::Result<agent::Report> rep = agent::err("unreachable");
    if (preview_kind == "test") {
      rep = agent::buildTestReport(ctx, now);
    } else if (preview_kind == "digest") {
      rep = agent::buildDigestReport(st, now - cfg.value().alerting.digest_every.count(), now, *agent::parseSeverity(cfg.value().alerting.digest_min_severity), ctx);
    } else {
      auto open = st.listFindings("open", 500);
      if (!open) { spdlog::error("{}", open.error()); return 1; }
      std::vector<agent::Finding> pick;
      for (auto& f : open.value()) {
        auto a = st.latestAssessment(f.id);
        if (agent::effectiveSeverity(f, a && a.value() ? a.value() : std::nullopt) >= thr) pick.push_back(std::move(f));
      }
      if (pick.empty()) {  // nothing alert-worthy: show the top open findings so the layout can still be reviewed
        for (auto& f : open.value()) if (pick.size() < 5) pick.push_back(std::move(f));
        std::cerr << "note: no finding reaches alerting.min_severity; previewing the top open findings instead\n";
      }
      rep = agent::buildAlertReport(st, pick, ctx, now);
    }
    if (!rep) { spdlog::error("{}", rep.error()); return 1; }
    const std::string dir = out_dir.empty() ? cfg.value().state_dir + "/preview" : out_dir;
    std::filesystem::create_directories(dir, ec);
    if (ec) { spdlog::error("cannot create '{}': {}", dir, ec.message()); return 1; }
    const std::string base = dir + "/" + preview_kind;
    std::ofstream(base + ".html") << agent::renderHtml(rep.value());
    std::ofstream(base + ".txt") << agent::renderText(rep.value());
    std::cout << "subject: " << agent::reportSubject(rep.value()) << "\nwrote " << base << ".html\nwrote " << base << ".txt\n";
    return 0;
  }
  if (mode == "--send-test-mail") {
    const auto& al = cfg.value().alerting;
    if (al.recipients.empty()) { std::cerr << "alerting.recipients is empty\n"; return 1; }
    auto pw = readSmtpPassword(al.smtp);
    if (!pw) { spdlog::error("{}", pw.error()); return 1; }
    agent::SmtpMailer mailer(al.smtp, pw.value());
    agent::Notifier n(st, mailer, al, reportContext(cfg.value(), vr.get(), &st));
    auto r = n.sendTest();
    if (!r) { std::cerr << "test mail FAILED: " << r.error() << "\n"; return 1; }
    std::cout << "test mail sent to " << al.recipients.size() << " recipient(s)\n";
    return 0;
  }

  // ---- threat lists and incidents ----------------------------------------------------
  if (mode == "--intel-update" || mode == "--intel-status") {
    const auto& tc = cfg.value().threat_intel;
    if (!tc.enabled) { std::cout << "threat_intel.enabled is false\n"; return 0; }
    agent::ThreatIntel ti(tc.dir.empty() ? cfg.value().state_dir + "/intel" : tc.dir, tc.lists);
    ti.load();
    if (mode == "--intel-update") {
      agent::CurlHttpClient http;
      std::cout << "downloading " << tc.lists.size() << " public list(s) (nothing about your machines is sent)...\n";
      int bad = 0;
      for (const auto& r : ti.refresh(http, nowTs(), 0, std::chrono::seconds(60))) {
        std::cout << "  " << r.list << ": " << (r.ok ? "ok" : "FAILED") << " - " << r.message << "\n";
        bad += !r.ok;
      }
      return bad ? 1 : 0;
    }
    for (const auto& i : ti.info()) {
      std::cout << i.name << " (" << i.category << "): " << i.ranges << " ranges, " << (i.fetched ? "fetched " + agent::report::fmtTime(i.fetched) : std::string("not downloaded yet")) << "\n";
    }
    if (ti.empty()) std::cout << "no list on disk yet: run --intel-update (the daemon downloads them by itself shortly after it starts)\n";
    return 0;
  }
  if (mode == "--incidents") {
    agent::IncidentEngine eng(st, agent::IncidentOptions{cfg.value().analysis.incident_window, cfg.value().analysis.incident_min_findings});
    auto n = eng.update(nowTs());
    if (!n) { spdlog::error("{}", n.error()); return 1; }
    auto list = st.listIncidents("open", 100);
    if (!list) { spdlog::error("{}", list.error()); return 1; }
    for (const auto& inc : list.value()) {
      std::cout << "incident #" << inc.id << " [" << agent::toString(inc.severity) << "] " << agent::incidentTitle(inc.stages, inc.targets, cfg.value().language) << "\n"
                << "  " << agent::report::fmtTime(inc.first_ts) << " -> " << agent::report::fmtTime(inc.last_ts) << "\n";
      for (int64_t id : inc.finding_ids) {
        if (auto f = st.getFinding(id); f && f.value()) std::cout << "    " << agent::report::fmtTime(f.value()->first_seen) << "  #" << id << " " << f.value()->rule_id << " " << f.value()->title << " (" << f.value()->target << ")\n";
      }
    }
    std::cout << list.value().size() << " open incident(s)\n";
    return 0;
  }

  // ---- attack map: location database ---------------------------------------------
  if (mode == "--geo-update" || mode == "--geo-import" || mode == "--geo-status") {
    const std::string dbp = cfg.value().geo.db_path.empty() ? cfg.value().state_dir + "/geo.db" : cfg.value().geo.db_path;
    if (mode == "--geo-status") {
      auto g = agent::GeoDb::open(dbp);
      if (!g) { spdlog::error("{}", g.error()); return 1; }
      if (g.value()->empty()) {
        std::cout << "no location database at " << dbp << ": run --geo-update (the attack map shows addresses without a position until then)\n";
        return 0;
      }
      const auto built = g.value()->meta("built_at");
      std::cout << dbp << ": " << g.value()->meta("ranges").value_or("?") << " ranges, " << g.value()->meta("source").value_or("?") << ", built "
                << (built ? agent::report::fmtTime(std::stoll(*built)) : std::string("?")) << "\n"
                << "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0. City-level positions are approximate.\n";
      return 0;
    }
    std::string csv = out_dir, label = "file " + out_dir;
    bool downloaded = false;
    if (mode == "--geo-update") {
      const std::time_t t = static_cast<std::time_t>(nowTs());
      std::tm tm{};
      gmtime_r(&t, &tm);
      int y = tm.tm_year + 1900, m = tm.tm_mon + 1;
      csv = cfg.value().state_dir + "/geo-download.csv.gz";
      bool ok = false;
      for (int attempt = 0; attempt < 2 && !ok; ++attempt) {  // the new month's file appears a few days late
        const std::string url = agent::dbipCityUrl(y, m);
        std::cout << "downloading " << url << " (about 85 MB)...\n";
        long status = 0;
        auto d = agent::downloadFile(url, csv, std::chrono::seconds(1800), &status);
        if (d) { ok = true; label = "DB-IP City Lite " + std::to_string(y) + "-" + (m < 10 ? "0" : "") + std::to_string(m); break; }
        std::cerr << "  " << d.error() << "\n";
        if (status != 404) break;
        if (--m == 0) { m = 12; --y; }
      }
      if (!ok) { std::cerr << "download failed. Download the file yourself from https://db-ip.com/db/download/ip-to-city-lite and use --geo-import <file>\n"; return 1; }
      downloaded = true;
    }
    std::cout << "importing (a few minutes: about 8 million ranges)...\n";
    auto n = agent::GeoDb::importCsv(dbp, csv, label, std::chrono::seconds(nowTs()));
    if (downloaded) std::remove(csv.c_str());
    if (!n) { std::cerr << "import failed: " << n.error() << "\n"; return 1; }
    std::cout << n.value() << " ranges imported into " << dbp << "\nIP geolocation by DB-IP (https://db-ip.com), CC BY 4.0. A running agent picks the new database up within a minute.\n";
    return 0;
  }

  if (mode == "--web") {
    auto w = startWeb(cfg.value(), st, vr.get());
    if (!w) { spdlog::error("{}", w.error()); return 1; }
    struct sigaction sw {};
    sw.sa_handler = onSignal;
    sigaction(SIGINT, &sw, nullptr);
    sigaction(SIGTERM, &sw, nullptr);
    while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(300));
    return 0;
  }

  // ---- LLM commands -----------------------------------------------------------
  if (mode == "--llm-ping" || mode == "--analyze" || mode == "--llm-prompt") {
    auto llm = buildLlm(cfg.value());
    if (!llm) { spdlog::error("{}", llm.error()); return 1; }

    if (mode == "--llm-ping") {
      auto p = llm.value()->client->ping();
      if (!p) { std::cerr << "llama-server NOT ready: " << p.error() << "\n"; return 1; }
      std::cout << "llama-server is ready at " << cfg.value().llm.url << "\n";
      if (auto n = llm.value()->client->serverContextSize()) {
        std::cout << "server context: " << *n << " tokens (configured: " << cfg.value().llm.context_tokens << ")\n";
        if (*n < cfg.value().llm.context_tokens) std::cout << "WARNING: llm.context_tokens exceeds the server context; lower it or raise llama-server -c\n";
      }
      return 0;
    }

    if (mode == "--llm-prompt") {
      auto fs = st.listUnassessed(static_cast<size_t>(cfg.value().llm.max_findings_per_call));
      if (!fs) { spdlog::error("{}", fs.error()); return 1; }
      if (fs.value().empty()) { std::cout << "no open finding waiting for an assessment\n"; return 0; }
      const std::string target = fs.value()[0].target;
      std::vector<agent::Finding> batch;
      for (auto& f : fs.value()) if (f.target == target) batch.push_back(std::move(f));
      const auto parts = agent::buildPrompt(target, batch, agent::buildHostContext(st, target), llm.value()->reasoner->options().language,
                                            llm.value()->reasoner->options().admin_focus);
      std::cout << "=== SYSTEM ===\n" << parts.system << "\n=== USER ===\n" << parts.user << "\n=== SCHEMA ===\n"
                << agent::analysisSchema(batch.size()).dump(2) << "\n=== ~" << parts.estimated_tokens << " prompt tokens, "
                << batch.size() << " finding(s) for target " << target << " ===\n";
      return 0;
    }

    auto r = agent::assessPending(st, *llm.value()->reasoner, 200);
    if (!r) { spdlog::error("{}", r.error()); return 1; }
    std::cout << "assessed " << r.value().assessed << " finding(s) in " << r.value().analyses << " call(s), " << r.value().missing << " left\n";
    return 0;
  }

  // ---- collection ------------------------------------------------------------
  // One agent per state directory: two instances would double every mail and fight over the baseline.
  const std::string lock_path = cfg.value().state_dir + "/agent.lock";
  const int lock_fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0640);
  if (lock_fd < 0) {
    spdlog::error("cannot open lock file {}: {}", lock_path, std::strerror(errno));
    return 1;
  }
  if (::flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
    spdlog::error("another dyna_cyber_agent instance is already using {} (lock {}): not starting", cfg.value().state_dir, lock_path);
    return 1;
  }

  std::unique_ptr<LlmRuntime> llm;
  if (cfg.value().llm.enabled) {
    auto l = buildLlm(cfg.value());
    if (!l) { spdlog::error("{}", l.error()); return 1; }
    llm = std::move(l.value());
    spdlog::info("LLM assessment enabled ({})", cfg.value().llm.url);
  } else {
    spdlog::info("LLM assessment disabled");
  }

  agent::Store* ag_store = store.value().get();
  agent::Agent ag(cfg.value(), std::move(store.value()), std::move(rules.value()));
  if (llm) ag.setReasoner(llm->reasoner.get());
  if (vr && cfg.value().vuln.enabled) ag.setVulnContext(&vr->ctx);

  // local databases that enrich what the targets report (nothing here ever talks to a target)
  std::unique_ptr<agent::GeoDb> ag_geo;
  if (auto g = agent::GeoDb::open(cfg.value().geo.db_path.empty() ? cfg.value().state_dir + "/geo.db" : cfg.value().geo.db_path)) {
    ag_geo = std::move(g.value());
    ag.setGeo(ag_geo.get());
  }
  std::unique_ptr<agent::ThreatIntel> ag_intel;
  agent::CurlHttpClient intel_http;
  if (cfg.value().threat_intel.enabled) {
    const auto& tc = cfg.value().threat_intel;
    ag_intel = std::make_unique<agent::ThreatIntel>(tc.dir.empty() ? cfg.value().state_dir + "/intel" : tc.dir, tc.lists);
    const size_t n = ag_intel->load();
    ag.setThreatIntel(ag_intel.get());
    spdlog::info("threat lists: {} range(s) loaded from disk{}", n, n ? "" : " (the first download starts shortly after the agent does)");
  }

  std::unique_ptr<agent::SmtpMailer> mailer;
  std::unique_ptr<agent::Notifier> notifier;
  if (!cfg.value().alerting.recipients.empty()) {
    auto pw = readSmtpPassword(cfg.value().alerting.smtp);
    if (!pw) { spdlog::error("{}", pw.error()); return 1; }
    mailer = std::make_unique<agent::SmtpMailer>(cfg.value().alerting.smtp, pw.value());
    notifier = std::make_unique<agent::Notifier>(*ag_store, *mailer, cfg.value().alerting, reportContext(cfg.value(), vr.get(), ag_store));
    ag.setNotifier(notifier.get());
    if (llm) notifier->setSynthesizer(agent::makeSynthesizer(*llm->reasoner, *ag_store));
    spdlog::info("mail alerting enabled: {} recipient(s)", cfg.value().alerting.recipients.size());
  } else {
    spdlog::info("mail alerting disabled (no recipients)");
  }
  std::unique_ptr<WebRuntime> web;
  if (cfg.value().web.enabled) {
    auto w = startWeb(cfg.value(), *ag_store, vr.get());
    if (!w) spdlog::error("web console not started: {}", w.error());  // monitoring matters more than the console
    else web = std::move(w.value());
  }
  auto n = ag.setup();
  if (!n) {
    spdlog::error("{}", n.error());
    return 1;
  }
  spdlog::info("{} target(s) ready", n.value());
  for (const auto& t : cfg.value().targets) {
    auto m = ag_store->baselineMeta(t.name, nowTs());
    if (!m) continue;
    const int64_t ends = m.value().started_at + cfg.value().baseline_learning.count();
    if (!m.value().locked && nowTs() < ends) {
      spdlog::info("{}: LEARNING phase until {} ({} day(s) left): new processes/ports/users are learned silently, not reported", t.name,
                   agent::report::fmtTime(ends), (ends - nowTs() + 86399) / 86400);
    } else {
      spdlog::info("{}: baseline enforcing (anything new is reported)", t.name);
    }
  }

  if (mode == "--once") {
    int failed = 0;
    for (const auto& s : ag.runOnce()) {
      std::cout << agent::formatSnapshot(s) << "\n";
      if (!s.error.empty()) ++failed;
    }
    const auto fresh = ag.takeNewFindings();
    if (!fresh.empty()) ag.assessNow();
    ag.updateIncidents();
    if (ag.notifier()) {
      const auto o = ag.notifier()->tick(true);
      if (!o.error.empty()) std::cerr << "mail error: " << o.error << "\n";
    }
    std::cout << "== " << fresh.size() << " new finding(s) ==\n";
    for (const auto& f : fresh) std::cout << agent::formatFinding(f, false) << "\n";
    return failed ? 1 : 0;
  }

  struct sigaction sa {};
  sa.sa_handler = onSignal;
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
  struct sigaction hup {};
  hup.sa_handler = onHup;
  sigaction(SIGHUP, &hup, nullptr);  // reload the rules without restarting
  ag.setRuleReloader(&g_reload, [dir = cfg.value().rules_dir] { return agent::loadRulesDir(dir); });
  std::unique_ptr<agent::VulnService> vuln_service;
  if (vr && cfg.value().vuln.enabled) {
    vuln_service = std::make_unique<agent::VulnService>(*vr->sync, cfg.value().vuln);
    vuln_service->start(g_stop);
    spdlog::info("vulnerability feeds: refreshed every {}s (first run in a few seconds; the NVD cold start can take several runs)", cfg.value().vuln.refresh_every.count());
  }
  std::unique_ptr<agent::IntelService> intel_service;
  if (ag_intel) {
    intel_service = std::make_unique<agent::IntelService>(*ag_intel, intel_http, cfg.value().threat_intel);
    intel_service->start(g_stop);
  }
  ag.run(g_stop);
  if (vuln_service) vuln_service->join();
  if (intel_service) intel_service->join();
  spdlog::info("stopped");
  return 0;
}
