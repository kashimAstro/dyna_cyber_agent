#pragma once
#include <optional>
#include <string>

namespace agent {

// line_len 0 = a single line without line ends (used in headers and in the SSH protocol).
std::string base64Encode(const std::string& in, size_t line_len = 76);
// Tolerates whitespace and missing padding; returns nullopt on any other invalid character.
std::optional<std::string> base64Decode(const std::string& in);

}  // namespace agent
