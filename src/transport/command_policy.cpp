#include "transport/command_policy.h"

#include <unistd.h>

#include <algorithm>
#include <map>
#include <set>

namespace agent {
namespace {

struct Rule {
  bool no_args = false;                          // command takes no arguments at all
  std::set<std::string> skip_flags;              // leading flags ignored before the subcommand check
  std::set<std::string> allowed_first;           // if non-empty, first non-skipped arg must be one of these
  std::set<std::string> forbidden_exact;         // rejected anywhere in the args
  std::vector<std::string> forbidden_prefix;     // rejected anywhere (long options)
  std::string forbidden_short;                   // rejected inside any single-dash cluster
  bool forbid_equals = false;                    // rejects `key=value` args (e.g. sysctl)
};

const std::map<std::string, Rule>& rules() {
  static const std::map<std::string, Rule> r = {
      {"ss", {.forbidden_exact = {"--kill", "--diag"}, .forbidden_short = "KDF"}},
      {"ps", {}},
      {"lsmod", {.no_args = true}},
      {"uname", {}},
      {"id", {}},
      {"who", {}},
      {"w", {}},
      {"last", {}},
      {"lastb", {}},
      {"uptime", {}},
      {"df", {}},
      {"mount", {.no_args = true}},
      {"findmnt", {}},
      {"lsof", {.forbidden_short = "k"}},
      {"stat", {}},
      {"sha256sum", {}},
      {"ls", {}},
      {"getent", {.allowed_first = {"passwd", "group", "hosts", "services", "shadow"}}},
      {"ip",
       {.skip_flags = {"-4", "-6", "-s", "-d", "-j", "-o", "-br", "-brief", "-c", "-p", "-json", "-details", "-stats"},
        .allowed_first = {"addr", "address", "route", "link", "neigh", "neighbour", "rule", "maddr", "-s"},
        .forbidden_exact = {"add", "del", "delete", "change", "replace", "flush", "set", "append", "prepend", "exec",
                            "save", "restore", "-b", "-batch", "-n", "-netns"}}},
      {"dpkg", {.allowed_first = {"-V", "--verify", "-l", "--list", "-L", "--listfiles", "-S", "--search", "-s", "--status"}}},
      {"rpm", {.allowed_first = {"-V", "-Va", "--verify", "-qa", "-q", "-ql", "-qf", "-qi"}}},
      {"journalctl",
       {.forbidden_prefix = {"--vacuum", "--rotate", "--flush", "--sync", "--relinquish", "--smart-relinquish",
                             "--setup-keys", "--update-catalog", "--interval", "--force", "--verify-key"}}},
      {"systemctl",
       {.allowed_first = {"list-units", "list-unit-files", "list-timers", "list-sockets", "status", "show",
                          "is-active", "is-enabled", "is-failed", "cat"}}},
      {"sysctl", {.forbidden_prefix = {"--write", "--load", "--system"}, .forbidden_short = "wpa", .forbid_equals = true}},
      {"dmesg", {.forbidden_exact = {"--clear", "--read-clear"}, .forbidden_prefix = {"--console"}, .forbidden_short = "cCDEn"}},
  };
  return r;
}

const char* const kSearchDirs[] = {"/usr/bin", "/bin", "/usr/sbin", "/sbin"};

bool isSingleDashCluster(const std::string& a) { return a.size() > 1 && a[0] == '-' && a[1] != '-'; }

}  // namespace

Result<bool> CommandPolicy::checkRules(const std::vector<std::string>& argv) {
  if (argv.empty()) return err("empty command");
  if (argv.size() > kMaxArgs) return err("too many arguments");
  for (const auto& a : argv) {
    if (a.size() > kMaxArgLen) return err("argument too long");
    if (a.find('\0') != std::string::npos) return err("NUL byte in argument");
  }

  const std::string& cmd = argv[0];
  auto it = rules().find(cmd);  // exact bare name: paths like ./ss or /tmp/ss never match
  if (it == rules().end()) return err("command not whitelisted: " + cmd);
  const Rule& rule = it->second;
  const size_t nargs = argv.size() - 1;

  if (rule.no_args && nargs > 0) return err(cmd + " accepts no arguments");

  size_t first = 1;
  while (first < argv.size() && rule.skip_flags.count(argv[first])) ++first;

  if (!rule.allowed_first.empty()) {
    if (first >= argv.size() || !rule.allowed_first.count(argv[first])) {
      return err(cmd + ": subcommand not allowed");
    }
  }

  for (size_t i = 1; i < argv.size(); ++i) {
    const std::string& a = argv[i];
    if (rule.forbidden_exact.count(a)) return err(cmd + ": forbidden argument " + a);
    for (const auto& p : rule.forbidden_prefix) {
      if (a.rfind(p, 0) == 0) return err(cmd + ": forbidden option " + a);
    }
    if (isSingleDashCluster(a) && !rule.forbidden_short.empty() &&
        a.find_first_of(rule.forbidden_short, 1) != std::string::npos) {
      return err(cmd + ": forbidden flag in " + a);
    }
    if (rule.forbid_equals && a.find('=') != std::string::npos) return err(cmd + ": assignment not allowed");
  }

  return true;
}

Result<std::string> CommandPolicy::validate(const std::vector<std::string>& argv) {
  if (auto r = checkRules(argv); !r) return err(r.error());
  const std::string& cmd = argv[0];
  for (const char* dir : kSearchDirs) {
    std::string path = std::string(dir) + "/" + cmd;
    if (::access(path.c_str(), X_OK) == 0) return path;
  }
  return err("executable not found: " + cmd);
}

}  // namespace agent
