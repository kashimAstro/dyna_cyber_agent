#pragma once
#include <string>
#include <vector>

#include "core/result.h"

namespace agent {

// Compile-time whitelist of read-only commands. The policy lives in code, not
// in configuration, so a config mistake cannot widen what the agent may run.
class CommandPolicy {
 public:
  // Validates argv and returns the absolute path of the executable to run.
  static Result<std::string> validate(const std::vector<std::string>& argv);

  // Only the rules (command whitelisted, arguments allowed), without looking for the executable on disk.
  static Result<bool> checkRules(const std::vector<std::string>& argv);

  static constexpr size_t kMaxArgs = 64;
  static constexpr size_t kMaxArgLen = 4096;
};

}  // namespace agent
