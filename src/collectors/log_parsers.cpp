#include "collectors/log_parsers.h"

#include <algorithm>
#include <cctype>

#include "core/util.h"

namespace agent {
namespace {

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool contains(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

bool containsAny(const std::string& s, std::initializer_list<const char*> needles) {
  for (const char* n : needles) if (s.find(n) != std::string::npos) return true;
  return false;
}

// "key" followed by a value up to the next space; empty when absent.
std::string wordAfter(const std::string& s, const std::string& key) {
  const size_t p = s.find(key);
  if (p == std::string::npos) return {};
  const size_t b = p + key.size();
  const size_t e = s.find_first_of(" \t,;", b);
  return s.substr(b, e == std::string::npos ? std::string::npos : e - b);
}

bool isMonth(const std::string& s) {
  static const char* m[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  for (const char* x : m) if (s == x) return true;
  return false;
}

}  // namespace

bool looksLikeIp(const std::string& s) {
  if (s.empty() || s.size() > 45) return false;
  bool colon = false, dot = false;
  for (unsigned char c : s) {
    if (c == ':') colon = true;
    else if (c == '.') dot = true;
    else if (!std::isxdigit(c)) return false;
  }
  return colon || (dot && std::count(s.begin(), s.end(), '.') == 3);
}

bool isPrivateIp(const std::string& ip) {
  if (ip == "::1" || util::startsWith(ip, "127.") || util::startsWith(ip, "10.") || util::startsWith(ip, "192.168.") || util::startsWith(ip, "169.254.")) return true;
  if (util::startsWith(ip, "172.")) {
    const auto p = util::split(ip, '.');
    if (p.size() > 1) {
      const auto n = util::parseUint(p[1]);
      if (n && *n >= 16 && *n <= 31) return true;
    }
  }
  const std::string l = lower(ip);
  return util::startsWith(l, "fe80:") || util::startsWith(l, "fc") || util::startsWith(l, "fd") || util::startsWith(l, "::ffff:127.") ||
         util::startsWith(l, "::ffff:10.") || util::startsWith(l, "::ffff:192.168.");
}

std::string urlDecode(const std::string& s) {
  std::string o;
  o.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) && std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
      o += static_cast<char>(util::parseUint(s.substr(i + 1, 2), 16).value());
      i += 2;
    } else if (s[i] == '+') {
      o += ' ';
    } else {
      o += s[i];
    }
  }
  return o;
}

// ---- syslog -----------------------------------------------------------------------------------------------------
std::optional<SyslogLine> parseSyslogLine(const std::string& line) {
  SyslogLine r;
  size_t pos = 0;
  if (line.size() > 20 && std::isdigit(static_cast<unsigned char>(line[0])) && line[4] == '-' && line[10] == 'T') {
    const size_t sp = line.find(' ');
    if (sp == std::string::npos) return std::nullopt;
    r.time_text = line.substr(0, sp);
    pos = sp + 1;
  } else if (line.size() > 16 && isMonth(line.substr(0, 3)) && line[3] == ' ' && line[15] == ' ') {
    r.time_text = line.substr(0, 15);
    pos = 16;
  } else {
    return std::nullopt;
  }
  const size_t hsp = line.find(' ', pos);
  if (hsp == std::string::npos) return std::nullopt;
  r.host = line.substr(pos, hsp - pos);
  pos = hsp + 1;
  const size_t colon = line.find(": ", pos);
  if (colon == std::string::npos) return std::nullopt;
  std::string tag = line.substr(pos, colon - pos);
  r.message = line.substr(colon + 2);
  const size_t lb = tag.find('[');
  if (lb != std::string::npos && tag.back() == ']') {
    r.pid = static_cast<int64_t>(util::parseUint(tag.substr(lb + 1, tag.size() - lb - 2)).value_or(0));
    tag = tag.substr(0, lb);
  }
  if (tag.empty() || tag.find(' ') != std::string::npos) return std::nullopt;
  r.program = tag;
  return r;
}

// ---- auth ------------------------------------------------------------------------------------------------------
namespace {

std::optional<AuthEvent> parseSshd(const std::string& m, const SyslogLine& l) {
  AuthEvent e;
  e.program = "sshd";
  e.time_text = l.time_text;
  const auto t = util::splitWs(m);
  auto at = [&](size_t i) { return i < t.size() ? t[i] : std::string(); };

  if (at(0) == "Failed" && at(2) == "for") {
    e.kind = AuthEvent::Kind::LoginFail;
    e.method = at(1);
    size_t i = 3;
    if (at(3) == "invalid" && at(4) == "user") i = 5;
    e.user = at(i);
    if (at(i + 1) != "from" || !looksLikeIp(at(i + 2))) return std::nullopt;
    e.src_ip = at(i + 2);
    e.port = at(i + 4);
    return e;
  }
  if (at(0) == "Accepted" && at(2) == "for" && at(4) == "from") {
    e.kind = AuthEvent::Kind::LoginOk;
    e.method = at(1);
    e.user = at(3);
    if (!looksLikeIp(at(5))) return std::nullopt;
    e.src_ip = at(5);
    e.port = at(7);
    if (at(8) == "ssh2:" && !at(10).empty()) e.key = at(9) + " " + at(10);  // "RSA SHA256:..." (key type and fingerprint)
    return e;
  }
  if (at(0) == "Invalid" && at(1) == "user") {
    const size_t f = m.find(" from ");
    if (f == std::string::npos) return std::nullopt;
    e.kind = AuthEvent::Kind::InvalidUser;
    e.user = std::string(util::trim(m.substr(13, f - 13)));
    const auto rest = util::splitWs(m.substr(f + 6));
    if (rest.empty() || !looksLikeIp(rest[0])) return std::nullopt;
    e.src_ip = rest[0];
    if (rest.size() >= 3 && rest[1] == "port") e.port = rest[2];
    return e;
  }
  if ((at(0) == "Connection" && at(1) == "closed" && at(2) == "by") && (at(3) == "authenticating" || at(3) == "invalid") && at(4) == "user" &&
      m.find("[preauth]") != std::string::npos) {
    e.kind = AuthEvent::Kind::PreauthClose;
    e.user = at(5);
    if (!looksLikeIp(at(6))) return std::nullopt;
    e.src_ip = at(6);
    e.port = at(8);
    return e;
  }
  if (contains(m, "maximum authentication attempts exceeded for")) {
    const size_t f = m.find(" for ");
    const auto rest = util::splitWs(m.substr(f + 5));
    size_t i = (rest.size() > 1 && rest[0] == "invalid" && rest[1] == "user") ? 2 : 0;
    if (rest.size() < i + 3 || rest[i + 1] != "from" || !looksLikeIp(rest[i + 2])) return std::nullopt;
    e.kind = AuthEvent::Kind::LoginFail;
    e.method = "max_attempts";
    e.user = rest[i];
    e.src_ip = rest[i + 2];
    return e;
  }
  if (util::startsWith(m, "Did not receive identification string from ") || contains(m, "banner exchange: Connection from ") ||
      util::startsWith(m, "Unable to negotiate with ") || util::startsWith(m, "Protocol major versions differ for ")) {
    for (const auto& w : t) {
      if (looksLikeIp(w)) {
        e.kind = AuthEvent::Kind::Scan;
        e.src_ip = w;
        e.detail = m.substr(0, 80);
        return e;
      }
    }
  }
  return std::nullopt;
}

std::optional<AuthEvent> parseSudo(const std::string& m, const SyslogLine& l) {
  AuthEvent e;
  e.program = "sudo";
  e.time_text = l.time_text;
  const size_t sep = m.find(" : ");
  if (sep == std::string::npos) return std::nullopt;
  e.user = std::string(util::trim(m.substr(0, sep)));
  const std::string rest = m.substr(sep + 3);
  e.tty = wordAfter(rest, "TTY=");
  e.pwd = wordAfter(rest, "PWD=");
  e.target_user = wordAfter(rest, "USER=");
  const size_t c = rest.find("COMMAND=");
  if (c != std::string::npos) e.command = std::string(util::trim(rest.substr(c + 8)));
  if (contains(rest, "incorrect password attempt")) {
    e.kind = AuthEvent::Kind::SudoFail;
    e.detail = "incorrect password";
    return e;
  }
  if (contains(rest, "NOT in sudoers")) {
    e.kind = AuthEvent::Kind::SudoFail;
    e.detail = "not in sudoers";
    return e;
  }
  if (contains(rest, "command not allowed")) {
    e.kind = AuthEvent::Kind::SudoFail;
    e.detail = "command not allowed";
    return e;
  }
  if (c != std::string::npos) {
    e.kind = AuthEvent::Kind::Sudo;
    return e;
  }
  return std::nullopt;
}

std::optional<AuthEvent> parseSu(const std::string& m, const SyslogLine& l) {
  AuthEvent e;
  e.program = "su";
  e.time_text = l.time_text;
  const auto t = util::splitWs(m);
  size_t i = 0;
  bool failed = false;
  if (t.size() > 1 && t[0] == "FAILED" && t[1] == "SU") {
    failed = true;
    i = 2;
  }
  // "(to root) bob on pts/0"
  if (i < t.size() && util::startsWith(t[i], "(to ") && t[i].back() == ')' ) {
    e.target_user = t[i].substr(4, t[i].size() - 5);
  } else if (i + 1 < t.size() && t[i] == "(to") {
    e.target_user = t[i + 1];
    if (!e.target_user.empty() && e.target_user.back() == ')') e.target_user.pop_back();
    ++i;
  } else {
    return std::nullopt;
  }
  e.user = i + 1 < t.size() ? t[i + 1] : std::string();
  e.tty = (i + 3 < t.size() && t[i + 2] == "on") ? t[i + 3] : std::string();
  e.kind = failed ? AuthEvent::Kind::SuFail : AuthEvent::Kind::SuOk;
  return e;
}

std::optional<AuthEvent> parseAccount(const std::string& m, const SyslogLine& l) {
  static const char* tools[] = {"useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod", "passwd", "chpasswd", "chage", "gpasswd", "adduser", "deluser", "addgroup", "chsh", "chfn", "newusers"};
  bool known = false;
  for (const char* t : tools) known |= l.program == t;
  if (!known) return std::nullopt;
  AuthEvent e;
  e.kind = AuthEvent::Kind::Account;
  e.program = l.program;
  e.time_text = l.time_text;
  e.action = l.program;
  e.detail = m.substr(0, 200);
  if (util::startsWith(m, "new user: ")) e.name = wordAfter(m, "name=");
  else if (util::startsWith(m, "new group: ")) e.name = wordAfter(m, "name=");
  else if (contains(m, "password changed for ")) e.name = std::string(util::trim(m.substr(m.find("password changed for ") + 21)));
  else if (util::startsWith(m, "delete user ") || util::startsWith(m, "change user ")) {
    const size_t a = m.find('\''), b = m.find('\'', a == std::string::npos ? 0 : a + 1);
    if (a != std::string::npos && b != std::string::npos) e.name = m.substr(a + 1, b - a - 1);
  } else if (util::startsWith(m, "add '") || util::startsWith(m, "user ")) {
    const size_t a = m.find('\''), b = m.find('\'', a == std::string::npos ? 0 : a + 1);
    if (a != std::string::npos && b != std::string::npos) e.name = m.substr(a + 1, b - a - 1);
  }
  return e;
}

}  // namespace

std::optional<AuthEvent> parseAuthLine(const SyslogLine& l) {
  const std::string& p = l.program;
  if (p == "sshd" || p == "sshd-session") return parseSshd(l.message, l);
  if (p == "sudo") return parseSudo(l.message, l);
  if (p == "su" || p == "su-l") return parseSu(l.message, l);
  return parseAccount(l.message, l);
}

// ---- kernel -----------------------------------------------------------------------------------------------------
std::optional<KernelEvent> parseKernelLine(const SyslogLine& l) {
  if (l.program != "kernel") return std::nullopt;
  std::string m = l.message;
  if (!m.empty() && m[0] == '[') {  // "[  123.456789] text"
    const size_t rb = m.find(']');
    if (rb != std::string::npos) m = std::string(util::trim(m.substr(rb + 1)));
  }
  KernelEvent e;
  e.time_text = l.time_text;
  const size_t dev = m.find("device ");
  if (dev != std::string::npos && contains(m, "entered promiscuous mode")) {
    e.event = "promisc";
    e.fields["iface"] = wordAfter(m, "device ");
    return e;
  }
  if (contains(m, "segfault at ")) {
    e.event = "segfault";
    const size_t sp = m.find_first_of("[: ");  // "nginx[2345]: segfault ..."
    e.fields["process"] = m.substr(0, sp == std::string::npos ? 0 : sp);
    const size_t in = m.rfind(" in ");
    if (in != std::string::npos) e.fields["object"] = wordAfter(m.substr(in), " in ");
    e.fields["ip"] = wordAfter(m, " ip ");
    return e;
  }
  if (contains(m, "Out of memory: Kill") || contains(m, "oom-kill:")) {
    e.event = "oom_kill";
    const size_t a = m.find('('), b = m.find(')', a == std::string::npos ? 0 : a);
    if (a != std::string::npos && b != std::string::npos && b > a) e.fields["process"] = m.substr(a + 1, b - a - 1);
    return e;
  }
  if (contains(m, "Possible SYN flooding on port")) {
    e.event = "syn_flood";
    e.fields["port"] = wordAfter(m, "port ");
    return e;
  }
  if (contains(m, "nf_conntrack: table full")) {
    e.event = "conntrack_full";
    return e;
  }
  if (contains(m, "module verification failed") || contains(m, "taints kernel") || contains(m, "tainting kernel")) {
    e.event = "module_taint";
    const size_t c = m.find(':');
    e.fields["module"] = c == std::string::npos ? "" : m.substr(0, c);
    e.fields["detail"] = m.substr(0, 160);
    return e;
  }
  if (contains(m, "apparmor=\"DENIED\"")) {
    e.event = "apparmor_denied";
    e.fields["operation"] = wordAfter(m, "operation=");
    e.fields["profile"] = wordAfter(m, "profile=");
    e.fields["name"] = wordAfter(m, " name=");
    return e;
  }
  if (contains(m, "Kernel panic") || contains(m, "general protection fault") || util::startsWith(m, "BUG: ") || contains(m, "Oops:")) {
    e.event = "kernel_fault";
    e.fields["detail"] = m.substr(0, 160);
    return e;
  }
  return std::nullopt;
}

// ---- web ---------------------------------------------------------------------------------------------------------
std::optional<WebLine> parseWebLine(const std::string& line) {
  WebLine w;
  size_t p = line.find(' ');
  if (p == std::string::npos || p == 0) return std::nullopt;
  w.ip = line.substr(0, p);
  if (!looksLikeIp(w.ip)) return std::nullopt;
  const size_t lb = line.find('[', p);
  const size_t rb = lb == std::string::npos ? lb : line.find(']', lb);
  if (rb == std::string::npos) return std::nullopt;
  {
    const auto pre = util::splitWs(line.substr(p, lb - p));  // ident user
    w.ident = pre.size() > 0 ? pre[0] : "-";
    w.user = pre.size() > 1 ? pre[1] : "-";
  }
  w.time_text = line.substr(lb + 1, rb - lb - 1);

  // quoted fields, honouring \" inside them
  auto quoted = [&](size_t from, std::string& out) -> size_t {
    const size_t q = line.find('"', from);
    if (q == std::string::npos) return std::string::npos;
    std::string s;
    size_t i = q + 1;
    for (; i < line.size(); ++i) {
      if (line[i] == '\\' && i + 1 < line.size()) {
        s += line[++i];
      } else if (line[i] == '"') {
        break;
      } else {
        s += line[i];
      }
    }
    if (i >= line.size()) return std::string::npos;
    out = s;
    return i + 1;
  };
  std::string req;
  size_t after = quoted(rb + 1, req);
  if (after == std::string::npos) return std::nullopt;
  {
    const size_t a = req.find(' '), b = req.rfind(' ');
    if (a != std::string::npos && b != a) {
      w.method = req.substr(0, a);
      w.uri = req.substr(a + 1, b - a - 1);
      w.proto = req.substr(b + 1);
    } else if (a != std::string::npos) {
      w.method = req.substr(0, a);
      w.uri = req.substr(a + 1);
    } else {
      w.uri = req;  // not an HTTP request line (binary garbage, TLS hello...)
    }
  }
  const size_t nq = line.find('"', after);
  const auto st = util::splitWs(line.substr(after, nq == std::string::npos ? std::string::npos : nq - after));
  if (st.empty()) return std::nullopt;
  w.status = static_cast<int>(util::parseUint(st[0]).value_or(0));
  w.bytes = st.size() > 1 ? static_cast<int64_t>(util::parseUint(st[1]).value_or(0)) : 0;
  size_t next = quoted(after, w.referer);
  if (next != std::string::npos) quoted(next, w.ua);
  return w;
}

std::vector<std::string> classifyWebRequest(const WebLine& w) {
  std::vector<std::string> cats;
  auto add = [&](const char* c) { if (std::find(cats.begin(), cats.end(), c) == cats.end()) cats.push_back(c); };

  // Decode twice (double encoding is a classic evasion) and squash whitespace and SQL comments.
  std::string u = urlDecode(urlDecode(w.uri));
  for (size_t i; (i = u.find("/**/")) != std::string::npos;) u.replace(i, 4, " ");
  std::string n;
  for (char c : lower(u)) {
    if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    if (c == ' ' && !n.empty() && n.back() == ' ') continue;
    n += c;
  }
  const std::string ua = lower(w.ua);
  const std::string raw = lower(w.uri);

  if (containsAny(n, {"union select", "union all select", "union distinct select", " or 1=1", "' or '", "\" or \"", "' or 1", "' --", "'--", "sleep(", "benchmark(",
                      "information_schema", "load_file(", "into outfile", "into dumpfile", "waitfor delay", "; drop ", "; insert ", "; update ", "; delete ", "extractvalue(",
                      "updatexml(", "pg_sleep(", "xp_cmdshell", " and 1=1", "order by 1--"}) &&
      (contains(n, "select") || contains(n, "=") || contains(n, "'") || contains(n, "sleep") || contains(n, "drop")))
    add("sqli");
  if (containsAny(n, {"../", "..\\"}) || containsAny(raw, {"%2e%2e%2f", "%2e%2e/", "..%2f", "%2e%2e%5c", "..%5c"}) ||
      containsAny(n, {"/etc/passwd", "/etc/shadow", "/proc/self/", "boot.ini", "win.ini", "/etc/hosts"}))
    add("path_traversal");
  if (containsAny(n, {"; wget ", ";wget ", "; curl ", ";curl ", "| sh", "|sh", "| bash", "|bash", "/bin/sh", "/bin/bash", "cmd.exe", "powershell", "base64 -d", "$(", "`", "; nc ", ";nc ",
                      "; bash", ";bash", "&& wget", "&& curl", "eval(", "system(", "passthru(", "shell_exec(", "exec(", "phpinfo(", "assert(", "popen(", "proc_open(", "chmod +x", "/dev/tcp/"}))
    add("rce");
  if (containsAny(n, {"php://", "data://", "expect://", "file://", "zip://", "phar://", "gopher://"}) ||
      (contains(n, "=http://") || contains(n, "=https://") || contains(n, "=ftp://")))
    add("lfi_rfi");
  if (containsAny(raw, {"${jndi:", "$%7bjndi", "%24%7bjndi"}) || containsAny(n, {"${jndi:", "${${", "${lower:", "${upper:", "${env:"}) || contains(lower(w.ua), "${jndi:") ||
      contains(lower(w.referer), "${jndi:"))
    add("log4shell");
  if (contains(w.uri, "() {") || contains(w.ua, "() {") || contains(w.referer, "() {")) add("shellshock");
  if (containsAny(n, {"c99.php", "r57.php", "wso.php", "b374k", "alfa.php", "webshell", "china chopper", "/shell.php", "/cmd.php", "/eval.php", "/backdoor", "/up.php?", "/x.php?", "?cmd=",
                      "&cmd=", "?exec=", "&exec=", "?pass=", "?c=whoami", "=whoami", "=id;"}))
    add("webshell");
  if (containsAny(ua, {"sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster", "dirb/", "gobuster", "wpscan", "nuclei", "acunetix", "nessus", "openvas", "burp", "havij", "hydra",
                       "metasploit", "fimap", "w3af", "arachni", "jaeles", "feroxbuster", "ffuf", "wfuzz", "libwww-perl", "python-requests/2.6", "masscan", "netsparker", "appscan", "skipfish"}))
    add("scanner_ua");
  if (containsAny(n, {"/.env", "/.git/", "/.git", "/.svn/", "/.hg/", "/.aws/", "/.ssh/", "/.htpasswd", "/.ds_store", "/wp-config", "/config.php.", "/configuration.php", "/settings.py", "/phpmyadmin",
                      "/pma/", "/adminer", "/manager/html", "/server-status", "/actuator", "/solr/admin", "/console/", "/jenkins", "/.bash_history", "/id_rsa", "/backup.sql", "/dump.sql", "/database.sql",
                      "/xmlrpc.php", "/vendor/phpunit", "/cgi-bin/", "/boaform", "/hudson", "/.well-known/security.txt.bak"}))
    add("sensitive_probe");
  return cats;
}

}  // namespace agent
