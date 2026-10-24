#include "collectors/content_scan.h"

#include <algorithm>
#include <cctype>

#include "core/util.h"

namespace agent {
namespace {

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }

bool hasAny(const std::string& s, std::initializer_list<const char*> ns) {
  for (const char* n : ns) if (has(s, n)) return true;
  return false;
}

}  // namespace

bool inVolatileDir(const std::string& p) { return util::startsWith(p, "/tmp/") || util::startsWith(p, "/var/tmp/") || util::startsWith(p, "/dev/shm/"); }

bool inSystemBinaryDir(const std::string& p) {
  for (const char* d : {"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/usr/libexec/", "/usr/local/bin/", "/usr/local/sbin/"}) {
    if (util::startsWith(p, d)) return true;
  }
  return false;
}

std::vector<std::string> suspiciousContentTags(const std::string& text) {
  std::vector<std::string> tags;
  auto add = [&](const char* t) { if (std::find(tags.begin(), tags.end(), t) == tags.end()) tags.push_back(t); };
  for (const auto& raw : util::split(text, '\n')) {
    const std::string l = lower(std::string(util::trim(raw)));
    if (l.empty() || l[0] == '#') continue;  // comments do not execute
    if (hasAny(l, {"curl ", "wget ", "fetch "}) && hasAny(l, {"| sh", "|sh", "| bash", "|bash", "| python", "|python", "| perl", "| zsh", "bash <(", "sh <("})) add("pipe_to_shell");
    if (has(l, "base64") && hasAny(l, {"-d", "--decode"}) && hasAny(l, {"| sh", "|sh", "| bash", "|bash", "eval", "| python", "| perl"})) add("base64_exec");
    if (hasAny(l, {"/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "nc.traditional -e", "bash -i >&", "sh -i >&", "socat exec", "socat tcp", "0<&196", "exec 5<>/dev/tcp"}) ||
        (has(l, "python") && has(l, "socket") && has(l, "-c") && hasAny(l, {"connect", "dup2"})) || (has(l, "perl") && has(l, "socket") && has(l, "-e")) ||
        (has(l, "mkfifo") && hasAny(l, {" nc ", "ncat", "telnet"})))
      add("reverse_shell");
    if (hasAny(l, {"ld_preload=", "ld_preload ", "/etc/ld.so.preload", "ld_library_path=/tmp", "ld_library_path=/dev/shm"})) add("ld_preload");
    if (hasAny(l, {"histfile=/dev/null", "unset histfile", "history -c", "chattr +i", "shred -", "rm -rf /var/log", "rm -f /var/log", "> /var/log/", "truncate -s 0 /var/log", "histsize=0", "histfilesize=0"})) add("anti_forensics");
    if (hasAny(l, {"alias sudo=", "alias ssh=", "alias su=", "alias passwd=", "alias scp="})) add("alias_hijack");
    if (hasAny(l, {" /tmp/", " /var/tmp/", " /dev/shm/", "=/tmp/", "=/dev/shm/", "\"/tmp/", "'/tmp/", ">/tmp/", "(/tmp/"}) || util::startsWith(l, "/tmp/") || util::startsWith(l, "/dev/shm/")) add("volatile_dir_reference");
  }
  return tags;
}

}  // namespace agent
