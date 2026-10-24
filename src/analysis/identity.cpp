#include "analysis/identity.h"

#include <algorithm>

#include "core/util.h"

namespace agent {
namespace {

constexpr int64_t kEphemeralFrom = 32768;

std::string str(const nlohmann::json& d, const char* k) {
  return d.contains(k) && d[k].is_string() ? d[k].get<std::string>() : std::string();
}

std::string ownerComm(const nlohmann::json& d) {
  if (d.contains("owners") && d["owners"].is_array() && !d["owners"].empty()) {
    return d["owners"][0].value("comm", std::string("?"));
  }
  return "?";
}

bool isLoopback(const std::string& a) { return a == "::1" || util::startsWith(a, "127."); }

bool isListening(const Observation& o) {
  return std::find(o.tags.begin(), o.tags.end(), "listening") != o.tags.end();
}

// Random suffixes (pids, session ids) would make every unix socket look new.
std::string normalizeDigits(const std::string& s) {
  std::string out;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] >= '0' && s[i] <= '9') {
      while (i + 1 < s.size() && s[i + 1] >= '0' && s[i + 1] <= '9') ++i;
      out += '#';
    } else {
      out += s[i];
    }
  }
  return out;
}

std::string listenEndpoint(const nlohmann::json& d) {
  const int64_t port = d.value("local_port", 0);
  return str(d, "proto") + "|" + str(d, "local_addr") + ":" + (port >= kEphemeralFrom ? "eph|" + ownerComm(d) : std::to_string(port));
}

}  // namespace

std::string stableKey(const Observation& o) {
  const auto& d = o.data;
  if (o.type == "process") {
    const std::string exe = str(d, "exe");
    return "proc|" + (exe.empty() ? str(d, "comm") : exe) + "|" + std::to_string(d.value("uid", -1));
  }
  if (o.type == "socket.inet") {
    if (isListening(o)) return "listen|" + listenEndpoint(d);
    return "conn|" + str(d, "proto") + "|" + str(d, "remote_addr") + ":" + std::to_string(d.value("remote_port", 0)) + "|" + ownerComm(d);
  }
  if (o.type == "socket.unix") return "unix|" + normalizeDigits(str(d, "path"));
  if (o.type == "socket.packet") return "packet|" + ownerComm(d);
  return o.key;
}

std::vector<Identity> identitiesOf(const Observation& o) {
  std::vector<Identity> ids;
  const auto& d = o.data;

  if (o.type == "process") {
    if (d.value("kernel_thread", false) || !d["exe"].is_string()) return ids;  // nothing reliable to baseline
    const std::string exe = d["exe"].get<std::string>();
    ids.push_back({"process.exe", exe});
    if (d["exe_sha256"].is_string()) ids.push_back({"process.binary", exe + "|" + d["exe_sha256"].get<std::string>()});
    ids.push_back({"process.lineage", (d["parent_exe"].is_string() ? d["parent_exe"].get<std::string>() : "?") + " > " + exe});
    ids.push_back({"process.user", exe + "|" + std::to_string(d.value("uid", -1))});
  } else if (o.type == "socket.inet") {
    const std::string proto = str(d, "proto");
    if (isListening(o)) {
      ids.push_back({"net.listen", listenEndpoint(d)});
    } else if (util::startsWith(proto, "raw")) {
      ids.push_back({"net.raw", proto + "|" + ownerComm(d)});
    } else {
      const std::string st = str(d, "state");
      const std::string remote = str(d, "remote_addr");
      if ((st == "ESTABLISHED" || st == "SYN_SENT") && !isLoopback(remote)) {
        ids.push_back({"net.outbound", proto + "|" + remote + ":" + std::to_string(d.value("remote_port", 0)) + "|" + ownerComm(d)});
        if (!str(d, "remote_cc").empty()) ids.push_back({"net.country", str(d, "remote_cc")});
      }
    }
  } else if (o.type == "socket.unix") {
    ids.push_back({"net.unix", normalizeDigits(str(d, "path"))});
  } else if (o.type == "socket.packet") {
    ids.push_back({"net.packet", ownerComm(d)});
  } else if (o.type == "user") {
    ids.push_back({"user.account", str(d, "name") + "|" + std::to_string(d.value("uid", -1)) + "|" + str(d, "shell")});
    if (d.contains("privileged_groups")) {
      for (const auto& g : d["privileged_groups"]) ids.push_back({"user.privgroup", str(d, "name") + "|" + g.get<std::string>()});
    }
  } else if (o.type == "authorized_key") {
    ids.push_back({"ssh.key", str(d, "user") + "|" + str(d, "blob")});
  } else if (o.type == "sudoers_line") {
    ids.push_back({"sudo.rule", str(d, "file") + "|" + str(d, "line")});
  } else if (o.type == "log.auth.login") {
    ids.push_back({"auth.login", str(d, "user") + "|" + str(d, "src_ip")});  // a user logging in from a new place
    if (!str(d, "cc").empty()) ids.push_back({"auth.country", str(d, "user") + "|" + str(d, "cc")});
    if (d.contains("hour_bucket") && d["hour_bucket"].is_number()) ids.push_back({"auth.hour", str(d, "user") + "|" + std::to_string(d["hour_bucket"].get<int>())});
  } else if (o.type == "log.auth.sudo") {
    const std::string cmd = str(d, "command");
    ids.push_back({"auth.sudo", str(d, "user") + "|" + cmd.substr(0, cmd.find(' '))});
  } else if (o.type == "cron.entry") {
    ids.push_back({"cron.entry", o.key});
  } else if (o.type == "cron.script") {
    ids.push_back({"cron.script", str(d, "path") + "|" + str(d, "sha256")});
  } else if (o.type == "systemd.unit") {
    ids.push_back({"systemd.unit", str(d, "path") + "|" + str(d, "sha256")});
  } else if (o.type == "systemd.enabled") {
    ids.push_back({"systemd.enabled", o.key});
  } else if (o.type == "startup.file") {
    ids.push_back({"startup.file", str(d, "path") + "|" + str(d, "sha256")});
  } else if (o.type == "kernel.module") {
    ids.push_back({"kernel.module", str(d, "name")});
  } else if (o.type == "kernel.taint") {
    ids.push_back({"kernel.taint", str(d, "flags")});
  } else if (o.type == "sysctl.value") {
    ids.push_back({"sysctl.value", str(d, "key") + "=" + str(d, "value")});
  } else if (o.type == "mount.entry") {
    ids.push_back({"mount.entry", o.key});
  } else if (o.type == "net.dns") {
    ids.push_back({"net.dns", str(d, "nameserver")});
  } else if (o.type == "net.hosts_entry") {
    ids.push_back({"net.hosts", o.key});
  } else if (o.type == "sshd.option") {
    ids.push_back({"sshd.option", o.key});
  } else if (o.type == "dev.node") {
    ids.push_back({"dev.node", o.key});
  } else if (o.type == "net.beacon") {
    ids.push_back({"net.beacon", str(d, "dest") + ":" + std::to_string(d.value("port", 0)) + "|" + str(d, "comm")});
  } else if (o.type == "log.template") {
    ids.push_back({"log.template", str(d, "program") + "|" + str(d, "hash")});
  } else if (o.type == "bpf.program") {
    ids.push_back({"bpf.program", str(d, "tag") + "|" + str(d, "name")});
  } else if (o.type == "bpf.pinned") {
    ids.push_back({"bpf.pinned", str(d, "name")});
  } else if (o.type == "file.entry") {
    const std::string preset = str(d, "preset");
    if (preset == "suid") ids.push_back({"file.suid", str(d, "path") + "|" + str(d, "mode") + "|" + str(d, "user") + "|" + std::to_string(d.value("size", 0))});
    else if (preset == "localexec") ids.push_back({"file.localexec", str(d, "path") + "|" + std::to_string(d.value("size", 0)) + "|" + std::to_string(d.value("mtime", 0))});
  }
  return ids;
}

}  // namespace agent

namespace agent {
const std::vector<std::string>& knownFacets() {
  static const std::vector<std::string> f = {"process.exe", "process.binary", "process.lineage", "process.user", "net.listen",
                                             "net.raw",     "net.outbound",   "net.unix",        "net.packet",  "user.account",
                                             "user.privgroup", "ssh.key",     "sudo.rule",
                                             "auth.login",  "auth.sudo",      "cron.entry",      "cron.script", "systemd.unit",
                                             "systemd.enabled", "startup.file", "kernel.module",  "kernel.taint", "sysctl.value",
                                             "mount.entry", "net.dns",        "net.hosts",       "sshd.option", "dev.node",
                                             "file.suid",   "file.localexec", "bpf.program", "bpf.pinned", "log.template", "net.beacon", "net.country", "auth.country", "auth.hour"};
  return f;
}
const std::vector<std::string>& knownObservationTypes() {
  static const std::vector<std::string> t = {"process", "socket.inet", "socket.unix", "socket.packet",
                                             "user",    "group",       "authorized_key", "sudoers_line",
                                             "log.auth.login", "log.auth.bruteforce", "log.auth.sudo", "log.auth.sudo_failure", "log.auth.su",
                                             "log.auth.account", "log.auth.scan", "log.template", "log.web.attack", "log.web.scan", "log.kernel", "log.source",
                                             "cron.entry", "cron.script", "systemd.unit", "systemd.enabled", "startup.file", "preload.entry",
                                             "kernel.module", "kernel.taint", "sysctl.value", "mount.entry", "net.dns", "net.hosts_entry",
                                             "sshd.option", "net.iface", "dev.node", "file.entry", "pkg.verify",
                                             "os.release", "os.kernel", "os.reboot_required", "pkg.installed", "pkg.change", "peer.deviation", "crossview.hidden_pid", "crossview.hidden_module", "crossview.hidden_port", "net.beacon", "net.traffic_spike",
                                             "bpf.program", "bpf.pinned", "vuln.match", "vuln.summary"};
  return t;
}
}  // namespace agent
