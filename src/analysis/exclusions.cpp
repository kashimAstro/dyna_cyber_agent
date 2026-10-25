#include "analysis/exclusions.h"

#include <arpa/inet.h>
#include <fnmatch.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace agent {
namespace {

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

bool onlyWildcards(const std::string& s) {
  return std::all_of(s.begin(), s.end(), [](char c) { return c == '*' || c == '?'; });
}

bool allowed(const std::string& s, const char* extra) {
  return std::all_of(s.begin(), s.end(), [&](char c) { return std::isalnum(static_cast<unsigned char>(c)) || std::strchr(extra, c) != nullptr; });
}

bool glob(const std::string& pattern, const std::string& text) { return fnmatch(pattern.c_str(), text.c_str(), 0) == 0; }

std::string str(const nlohmann::json& d, const char* key) {
  if (!d.is_object()) return {};
  const auto it = d.find(key);
  return it != d.end() && it->is_string() ? it->get<std::string>() : std::string();
}

int64_t num(const nlohmann::json& d, const char* key, int64_t def = -1) {
  if (!d.is_object()) return def;
  const auto it = d.find(key);
  return it != d.end() && it->is_number_integer() ? it->get<int64_t>() : def;
}

bool parseV4(const std::string& s, uint32_t* out) {
  in_addr a{};
  if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
  *out = ntohl(a.s_addr);
  return true;
}

bool ipMatches(const std::string& pattern, const std::string& ip) {
  if (ip.empty()) return false;
  const size_t slash = pattern.find('/');
  if (slash == std::string::npos) return pattern == ip;
  uint32_t net = 0, addr = 0;
  if (!parseV4(pattern.substr(0, slash), &net) || !parseV4(ip, &addr)) return false;
  const int bits = std::atoi(pattern.c_str() + slash + 1);
  const uint32_t mask = bits <= 0 ? 0 : bits >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - bits)) - 1);
  return (net & mask) == (addr & mask);
}

// "22", "tcp/22", "8000-8100", "udp/5000-5010"
struct PortSpec {
  std::string proto;
  int lo = 0, hi = 0;
};
bool parsePort(const std::string& p, PortSpec* out) {
  std::string rest = p;
  const size_t slash = p.find('/');
  PortSpec ps;
  if (slash != std::string::npos) {
    ps.proto = p.substr(0, slash);
    rest = p.substr(slash + 1);
    if (ps.proto != "tcp" && ps.proto != "udp") return false;
  }
  const size_t dash = rest.find('-');
  const auto num_ok = [](const std::string& n, int* v) {
    if (n.empty() || n.size() > 5 || !std::all_of(n.begin(), n.end(), [](unsigned char c) { return std::isdigit(c); })) return false;
    *v = std::atoi(n.c_str());
    return *v >= 1 && *v <= 65535;
  };
  if (dash == std::string::npos) {
    if (!num_ok(rest, &ps.lo)) return false;
    ps.hi = ps.lo;
  } else if (!num_ok(rest.substr(0, dash), &ps.lo) || !num_ok(rest.substr(dash + 1), &ps.hi) || ps.hi < ps.lo) {
    return false;
  }
  *out = ps;
  return true;
}

bool anyOf(const nlohmann::json& d, std::initializer_list<const char*> keys, const std::string& pattern) {
  for (const char* k : keys) {
    const std::string v = str(d, k);
    if (!v.empty() && glob(pattern, v)) return true;
  }
  return false;
}

}  // namespace

const std::vector<std::string>& exclusionKinds() {
  static const std::vector<std::string> kinds = {"rule", "package", "cve", "port", "user", "ip", "path", "process"};
  return kinds;
}

Result<std::string> normalizeExclusionPattern(const std::string& kind, const std::string& raw) {
  std::string p = trim(raw);
  if (p.empty()) return err("the pattern is empty");
  if (p.size() > 200) return err("the pattern is too long (200 characters at most)");
  if (std::any_of(p.begin(), p.end(), [](unsigned char c) { return c < 0x20 || c == 0x7F; })) return err("the pattern contains control characters");
  if (std::find(exclusionKinds().begin(), exclusionKinds().end(), kind) == exclusionKinds().end()) return err("unknown kind of filter: " + kind);
  if (onlyWildcards(p)) return err("a pattern made only of wildcards would exclude everything");

  if (kind == "rule") {
    std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (!allowed(p, "-*?") || p.find('-') == std::string::npos) return err("a rule id looks like LOG-050 (wildcards allowed: LOG-05*)");
    if (p.find('-') < 2 || p.find('-') > 8) return err("a rule id looks like LOG-050 (wildcards allowed: LOG-05*)");
  } else if (kind == "package") {
    if (!allowed(p, "+.-_:*?")) return err("a package name has letters, digits and + . - _ : (wildcards allowed: linux-*)");
  } else if (kind == "cve") {
    std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (p.rfind("CVE-", 0) != 0 || !allowed(p, "-*?")) return err("a CVE id looks like CVE-2026-1234 (wildcards allowed: CVE-2024-*)");
  } else if (kind == "port") {
    std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    PortSpec ps;
    if (!parsePort(p, &ps)) return err("a port is 22, tcp/22, udp/53 or a range such as 8000-8100 (1-65535)");
  } else if (kind == "user") {
    if (!allowed(p, "._-$*?")) return err("an account name has letters, digits and . _ - $ (wildcards allowed)");
    if (glob(p, "root")) return err("the root account cannot be excluded: it is the account an intruder wants. Exclude a rule instead");
  } else if (kind == "ip") {
    const size_t slash = p.find('/');
    if (slash == std::string::npos) {
      in_addr a4{};
      in6_addr a6{};
      if (inet_pton(AF_INET, p.c_str(), &a4) != 1 && inet_pton(AF_INET6, p.c_str(), &a6) != 1) return err("not an IP address");
    } else {
      uint32_t net = 0;
      const std::string bits = p.substr(slash + 1);
      if (!parseV4(p.substr(0, slash), &net) || bits.empty() || bits.size() > 2 || !std::all_of(bits.begin(), bits.end(), [](unsigned char c) { return std::isdigit(c); }))
        return err("a network looks like 192.168.1.0/24 (IPv4)");
      if (std::atoi(bits.c_str()) < 8 || std::atoi(bits.c_str()) > 32) return err("the network is too wide: /8 to /32 only");
    }
  } else if (kind == "path") {
    if (p[0] != '/') return err("a path starts with /");
    if (p.find("..") != std::string::npos) return err("a path cannot contain ..");
    if (p.back() == '/') p += "*";  // a directory means everything below it
    const size_t second = p.find('/', 1);
    const std::string first = p.substr(1, second == std::string::npos ? std::string::npos : second - 1);
    if (first.empty() || onlyWildcards(first)) return err("the path must start with a real directory, not a wildcard");
    if (p == "/" + first + "/*" && (first == "usr" || first == "bin" || first == "sbin" || first == "lib" || first == "etc" || first == "boot"))
      return err("excluding a whole system directory would hide real tampering: name a narrower path");
  } else if (kind == "process") {
    if (std::any_of(p.begin(), p.end(), [](char c) { return c == ' '; })) return err("a program is a path (/usr/bin/foo) or a name (foo); no spaces");
  }
  return p;
}

bool exclusionMatches(const Exclusion& x, const std::string& target, const std::string& rule_id, const std::string& obs_type, const nlohmann::json& data) {
  if (!x.target.empty() && x.target != target) return false;
  const auto starts = [&](const char* p) { return obs_type.rfind(p, 0) == 0; };
  if (x.kind == "rule") return glob(x.pattern, rule_id);
  if (x.kind == "package") {
    if (!starts("vuln.") && !starts("pkg.")) return false;
    if (anyOf(data, {"package", "name"}, x.pattern)) return true;
    if (data.is_object() && data.contains("binaries") && data["binaries"].is_array()) {
      for (const auto& b : data["binaries"]) if (b.is_string() && glob(x.pattern, b.get<std::string>())) return true;
    }
    return false;
  }
  if (x.kind == "cve") return obs_type == "vuln.match" && anyOf(data, {"cve"}, x.pattern);
  if (x.kind == "port") {
    PortSpec ps;
    if (!parsePort(x.pattern, &ps)) return false;
    int64_t port = -1;
    std::string proto;
    if (obs_type == "socket.inet") {
      if (num(data, "remote_port", 0) != 0) return false;  // a connection to somewhere: not a service of this machine
      port = num(data, "local_port");
      proto = str(data, "proto");
      if (proto.rfind("tcp", 0) == 0) proto = "tcp";
      else if (proto.rfind("udp", 0) == 0) proto = "udp";
    } else if (obs_type == "crossview.hidden_port") {
      port = num(data, "port");
    } else {
      return false;
    }
    if (!ps.proto.empty() && !proto.empty() && ps.proto != proto) return false;
    return port >= ps.lo && port <= ps.hi;
  }
  if (x.kind == "user") {
    if (obs_type == "file.entry" || obs_type == "process" || starts("socket.")) return false;  // an owner or a uid is not an account activity
    if (obs_type == "user") return anyOf(data, {"name"}, x.pattern);
    return anyOf(data, {"user", "target_user", "from", "to", "owner"}, x.pattern);
  }
  if (x.kind == "ip") {
    for (const char* k : {"src_ip", "remote_addr", "ip"}) {
      if (ipMatches(x.pattern, str(data, k))) return true;
    }
    return false;
  }
  if (x.kind == "path") return anyOf(data, {"path", "file", "exe", "library", "wants_dir"}, x.pattern);
  if (x.kind == "process") return obs_type == "process" && (anyOf(data, {"exe"}, x.pattern) || anyOf(data, {"comm"}, x.pattern));
  return false;
}

const Exclusion* ExclusionSet::find(const std::string& target, const std::string& rule_id, const std::string& obs_type, const nlohmann::json& data) const {
  for (const auto& x : rows_) if (exclusionMatches(x, target, rule_id, obs_type, data)) return &x;
  return nullptr;
}

bool ExclusionSet::excludesAddress(const std::string& target, const std::string& ip) const {
  for (const auto& x : rows_) {
    if (x.kind == "ip" && (x.target.empty() || x.target == target) && ipMatches(x.pattern, ip)) return true;
  }
  return false;
}

}  // namespace agent
