#pragma once
#include <optional>

#include "collectors/collector.h"

namespace agent {

struct PasswdEntry {
  std::string name, home, shell;
  uint64_t uid = 0, gid = 0;
};

struct AuthorizedKey {
  std::string options;  // raw option string (may contain command="...")
  std::string type;
  std::string blob;
  std::string comment;
};

// Pure parsers (exposed for tests).
std::vector<PasswdEntry> parsePasswd(const std::string& text);
bool isLoginShell(const std::string& shell);
// "locked" | "empty" | "set" | "none" -- the hash itself is never kept.
std::string passwordState(const std::string& shadow_field);
std::vector<AuthorizedKey> parseAuthorizedKeys(const std::string& text);

class UserCollector final : public ICollector {
 public:
  std::string name() const override { return "users"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::minutes(5); }
  Result<CollectOutput> collect(ITransport& t) override;
};

}  // namespace agent
