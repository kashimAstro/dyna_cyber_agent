#pragma once
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace agent {

// ---- syslog framing -----------------------------------------------------------------------------------------
// Accepts "Oct 22 20:15:01 host prog[123]: msg" (RFC 3164) and "2026-10-22T20:15:01+0200 host prog[123]: msg"
// (journalctl short-iso, rsyslog high precision).
struct SyslogLine {
  std::string time_text;
  std::string host;
  std::string program;
  int64_t pid = 0;
  std::string message;
};
std::optional<SyslogLine> parseSyslogLine(const std::string& line);

// ---- authentication log (sshd, sudo, su, account tools) ------------------------------------------------------
struct AuthEvent {
  enum class Kind { LoginOk, LoginFail, InvalidUser, PreauthClose, Scan, Sudo, SudoFail, SuOk, SuFail, Account };
  Kind kind = Kind::LoginFail;
  std::string user, src_ip, method, port, key;
  std::string target_user, command, tty, pwd;
  std::string action, name, detail, program;  // Account
  std::string time_text;
};
std::optional<AuthEvent> parseAuthLine(const SyslogLine& l);

// ---- kernel messages -----------------------------------------------------------------------------------------
struct KernelEvent {
  std::string event;  // promisc, segfault, oom_kill, syn_flood, conntrack_full, module_taint, apparmor_denied, kernel_fault
  std::map<std::string, std::string> fields;
  std::string time_text;
};
std::optional<KernelEvent> parseKernelLine(const SyslogLine& l);

// ---- web access log (nginx / apache, common and combined format) ----------------------------------------------
struct WebLine {
  std::string ip, ident, user, time_text, method, uri, proto, referer, ua;
  int status = 0;
  int64_t bytes = 0;
};
std::optional<WebLine> parseWebLine(const std::string& line);

// Attack categories seen in the request: sqli, path_traversal, rce, lfi_rfi, log4shell, shellshock, webshell,
// scanner_ua, sensitive_probe. Empty for ordinary requests.
std::vector<std::string> classifyWebRequest(const WebLine& w);

std::string urlDecode(const std::string& s);
bool looksLikeIp(const std::string& s);
// Loopback, RFC 1918, link-local, ULA: not "external".
bool isPrivateIp(const std::string& ip);

}  // namespace agent
