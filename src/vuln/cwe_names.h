#pragma once
#include <string>

namespace agent {

// Names of the weakness classes seen most often, built in so reports are readable even before the first CWE
// download (and offline). The downloaded MITRE catalog takes precedence when it has the entry.
// Returns "" for an unknown id.
std::string builtinCweName(const std::string& id);  // "CWE-79" -> "Cross-site Scripting"

}  // namespace agent
