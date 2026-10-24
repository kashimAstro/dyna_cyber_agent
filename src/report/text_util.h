#pragma once
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace agent::report {

// Everything that comes from the monitored machine (or from the LLM) is untrusted when it lands in a mail.
// This removes control and bidi-override characters (which can visually reorder text) and defangs URLs
// (http:// -> hxxp://) so a careless click or auto-linking mail client cannot reach an attacker's server.
std::string sanitize(const std::string& s, size_t max_len = 600);

std::string htmlEscape(const std::string& s);

// Word-wraps to `width` columns; continuation lines get `indent` spaces. Long unbreakable tokens are cut.
std::string wrap(const std::string& text, size_t width, size_t indent = 0);

std::string fmtTime(int64_t unix_seconds);   // "2026-10-22 20:15:00 UTC"
std::string fmtDate(int64_t unix_seconds);   // "2026-10-22"
std::string fmtAge(int64_t seconds);         // "5 min", "3 h", "2 d"

// Flattens evidence JSON into "path: value" rows (nulls skipped, arrays joined), all sanitised.
std::vector<std::pair<std::string, std::string>> flattenEvidence(const nlohmann::json& j, size_t max_rows = 40, size_t max_val = 300);

}  // namespace agent::report
