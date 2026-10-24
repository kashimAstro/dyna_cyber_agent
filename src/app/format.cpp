#include "app/format.h"

#include <ctime>
#include <map>
#include <sstream>

namespace agent {
namespace {

std::string brief(const Observation& o) {
  const auto& d = o.data;
  auto str = [&](const char* k) { return d.contains(k) && d[k].is_string() ? d[k].get<std::string>() : std::string("-"); };
  std::ostringstream ss;
  if (o.type == "process") {
    ss << "pid " << d.value("pid", 0) << " " << str("comm") << " uid=" << d.value("uid", -1) << " exe=" << str("exe");
  } else if (o.type == "socket.inet") {
    ss << str("proto") << " " << str("local_addr") << ":" << d.value("local_port", 0) << " -> " << str("remote_addr") << ":"
       << d.value("remote_port", 0) << " " << str("state");
    for (const auto& ow : d["owners"]) ss << " [" << ow.value("pid", 0) << "/" << ow.value("comm", std::string("?")) << "]";
  } else if (o.type == "socket.unix") {
    ss << "unix " << str("type") << " " << str("path");
    for (const auto& ow : d["owners"]) ss << " [" << ow.value("pid", 0) << "/" << ow.value("comm", std::string("?")) << "]";
  } else if (o.type == "socket.packet") {
    ss << "packet type=" << str("type") << " proto=" << str("proto");
    for (const auto& ow : d["owners"]) ss << " [" << ow.value("pid", 0) << "/" << ow.value("comm", std::string("?")) << "]";
  } else if (o.type == "user") {
    ss << str("name") << " uid=" << d.value("uid", 0) << " shell=" << str("shell") << " password=" << str("password");
  } else if (o.type == "authorized_key") {
    ss << str("user") << " " << str("type") << " " << str("comment") << (str("options") == "" ? "" : " options=" + str("options"));
  } else if (o.type == "log.auth.login") {
    ss << "login " << str("user") << " from " << str("src_ip") << " (" << str("method") << ") x" << d.value("count", 1);
  } else if (o.type == "log.auth.bruteforce") {
    ss << "brute force from " << str("src_ip") << ": " << d.value("failures", 0) << " failures, " << d.value("distinct_users", 0) << " user(s)"
       << (d.contains("success_user") ? " -> SUCCESS as " + str("success_user") : "");
  } else if (o.type == "log.auth.sudo") {
    ss << "sudo " << str("user") << " -> " << str("target_user") << ": " << str("command");
  } else if (o.type == "log.auth.sudo_failure" || o.type == "log.auth.su" || o.type == "log.auth.account" || o.type == "log.auth.scan") {
    ss << o.type.substr(9) << " " << o.key;
  } else if (o.type == "log.web.attack") {
    ss << str("category") << " from " << str("src_ip") << " x" << d.value("count", 0) << ": " << str("sample_uri");
  } else if (o.type == "log.web.scan") {
    ss << "scan from " << str("src_ip") << ": " << d.value("errors_4xx", 0) << " failed requests";
  } else if (o.type == "log.kernel") {
    ss << "kernel " << str("event") << " x" << d.value("count", 1);
  } else if (o.type == "cron.entry") {
    ss << str("file") << ": " << str("schedule") << " " << str("user") << " " << str("command");
  } else if (o.type == "systemd.unit") {
    ss << str("name") << " (" << str("path") << ")";
    for (const auto& e : d["exec"]) ss << " " << e.get<std::string>();
  } else if (o.type == "startup.file" || o.type == "cron.script") {
    ss << str("path") << " sha256=" << str("sha256").substr(0, 12);
  } else if (o.type == "preload.entry") {
    ss << "ld.so.preload: " << str("library");
  } else if (o.type == "kernel.module") {
    ss << "module " << str("name") << (str("taint") == "-" || str("taint").empty() ? "" : " (" + str("taint") + ")");
  } else if (o.type == "sysctl.value") {
    ss << str("key") << " = " << str("value") << " (expected " << str("expected") << ")";
  } else if (o.type == "sshd.option") {
    ss << "sshd " << str("name") << " " << str("value");
  } else if (o.type == "net.iface") {
    ss << "interface " << str("name") << " flags " << str("flags");
  } else if (o.type == "dev.node") {
    ss << str("path") << " (" << str("type") << ")";
  } else if (o.type == "file.entry") {
    ss << str("preset") << " " << str("mode") << " " << str("user") << " " << str("path");
  } else if (o.type == "pkg.verify") {
    ss << str("path") << " flags " << str("flags");
  } else if (o.type == "mount.entry" || o.type == "net.dns" || o.type == "net.hosts_entry") {
    ss << o.key;
  } else if (o.type == "sudoers_line") {
    ss << str("file") << ": " << str("line");
  } else {
    ss << o.key;
  }
  return ss.str();
}

}  // namespace

std::string formatSnapshot(const Snapshot& s) {
  std::ostringstream out;
  char tbuf[32] = "?";
  const std::time_t tt = static_cast<std::time_t>(s.ts);
  std::tm tm{};
  if (localtime_r(&tt, &tm)) std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

  out << "== " << s.target << " / " << s.collector << " @ " << tbuf << " (" << s.duration_ms << " ms) ==\n";
  if (!s.error.empty()) {
    out << "  ERROR: " << s.error << "\n";
    return out.str();
  }
  std::map<std::string, size_t> counts;
  for (const auto& o : s.observations) ++counts[o.type];
  for (const auto& [type, n] : counts) out << "  " << type << ": " << n << "\n";
  for (const auto& w : s.warnings) out << "  ! " << w << "\n";

  // Identical lines (e.g. SO_REUSEPORT listeners) are folded into one with a count.
  std::vector<std::pair<std::string, size_t>> lines;
  std::map<std::string, size_t> index;
  for (const auto& o : s.observations) {
    if (o.tags.empty()) continue;
    std::string line = brief(o) + "  {";
    for (size_t i = 0; i < o.tags.size(); ++i) line += (i ? "," : "") + o.tags[i];
    line += "}";
    const auto [it, fresh] = index.try_emplace(line, lines.size());
    if (fresh) lines.emplace_back(line, 1);
    else ++lines[it->second].second;
  }
  if (!lines.empty()) out << "  -- tagged --\n";
  for (const auto& [line, n] : lines) out << "  * " << line << (n > 1 ? "  x" + std::to_string(n) : "") << "\n";
  return out.str();
}

namespace {
std::string when(int64_t ts) {
  char b[32] = "?";
  const std::time_t tt = static_cast<std::time_t>(ts);
  std::tm tm{};
  if (localtime_r(&tt, &tm)) std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &tm);
  return b;
}
}  // namespace

std::string formatFinding(const Finding& f, bool detailed) {
  std::ostringstream o;
  if (!detailed) {
    o << "#" << f.id << " [" << toString(f.severity) << "] " << f.rule_id << " " << f.title << " | " << f.target << " | " << f.stable_key
      << " | seen " << f.occurrences << "x, last " << when(f.last_seen) << " | " << f.status;
    return o.str();
  }
  o << "Finding #" << f.id << " (" << f.status << ")\n"
    << "  rule        : " << f.rule_id << " - " << f.title << "\n"
    << "  severity    : " << toString(f.severity) << "\n"
    << "  target      : " << f.target << " (" << f.collector << " / " << f.obs_type << ")\n"
    << "  subject     : " << f.stable_key << "\n"
    << "  first/last  : " << when(f.first_seen) << " / " << when(f.last_seen) << " (" << f.occurrences << " snapshot(s))\n";
  if (!f.mitre.empty()) {
    o << "  MITRE       : ";
    for (size_t i = 0; i < f.mitre.size(); ++i) o << (i ? ", " : "") << f.mitre[i];
    o << "\n";
  }
  if (!f.description.empty()) o << "  description : " << f.description << "\n";
  if (!f.remediation.empty()) o << "  remediation : " << f.remediation << "\n";
  if (!f.tags.empty()) {
    o << "  tags        : ";
    for (size_t i = 0; i < f.tags.size(); ++i) o << (i ? "," : "") << f.tags[i];
    o << "\n";
  }
  for (const auto& d : f.drift) o << "  not in baseline: " << d.facet << " = " << d.key << "\n";
  o << "  evidence    : " << f.evidence.dump(2) << "\n";
  return o.str();
}

std::string formatAssessment(const Assessment& a) {
  std::ostringstream o;
  o << "  LLM assessment (" << when(a.created_at) << ")\n"
    << "    verdict     : " << a.verdict << " (confidence " << a.confidence << "%)\n"
    << "    risk        : " << toString(a.risk) << "\n";
  for (const auto& f : a.flags) o << "    FLAG        : " << f << "\n";
  o << "    explanation : " << a.explanation << "\n";
  for (const auto& x : a.recommended_actions) o << "    action      : " << x << "\n";
  for (const auto& x : a.additional_checks) o << "    check       : " << x << "\n";
  return o.str();
}

}  // namespace agent
