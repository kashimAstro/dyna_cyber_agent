#pragma once
#include <string>

namespace agent {

// The values below end up on the ssh command line or inside the remote command. They are validated
// strictly (not just quoted): nothing starting with '-' (option injection), no whitespace, no shell syntax.

inline bool sshChars(const std::string& s, const char* extra) {
  if (s.empty() || s.size() > 253 || s[0] == '-') return false;
  for (unsigned char c : s) {
    const bool alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    if (!alnum && c != '.' && c != '_' && c != '-' && std::string(extra).find(static_cast<char>(c)) == std::string::npos) return false;
  }
  return true;
}

inline bool validSshHost(const std::string& s) { return sshChars(s, ":"); }                 // names, IPv4, IPv6
inline bool validSshUser(const std::string& s) { return sshChars(s, ""); }
inline bool validSshJump(const std::string& s) { return sshChars(s, "@:,"); }               // user@host:port,...
inline bool validGatePath(const std::string& s) {
  if (s.size() < 2 || s.size() > 200 || s[0] != '/' || s.find("..") != std::string::npos) return false;
  for (unsigned char c : s) {
    const bool alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    if (!alnum && c != '.' && c != '_' && c != '-' && c != '/') return false;
  }
  return true;
}

}  // namespace agent
