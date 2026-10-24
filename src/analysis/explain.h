#pragma once
#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "store/store.h"

namespace agent {

// A finding that appeared because a package was installed or upgraded: the new program, the restarted service, the
// changed executable. The agent cannot call that benign for certain (an attacker can also time things), so it says
// what it found and lets the rules of the mail decide how loudly to speak (see USAGE.md "Explained by an update").
struct Explanation {
  std::string package, kind, old_version, new_version, path;
  int64_t changed_at = 0;
};

// Absolute paths mentioned in a finding's evidence ("(deleted)" suffix removed), at most 30.
std::vector<std::string> evidencePaths(const nlohmann::json& evidence);

// The most recent package change that owns one of the evidence paths and happened at most `window` before the
// finding appeared (a few minutes after is tolerated: clocks and collection cycles do not line up exactly).
// Never explains a path that `dpkg -V` / `rpm -Va` reports as modified: the package would not vouch for it.
std::optional<Explanation> explainByUpdate(Store& store, const std::string& target, const nlohmann::json& evidence, int64_t first_seen,
                                           std::chrono::seconds window);

// Stores the explanation in the finding: tag `explained_by_update` and evidence.explained_by.
void applyExplanation(Finding& f, const Explanation& e);

}  // namespace agent
