#pragma once
#include <string>

namespace agent::logger {

// Initialises the global logger. An empty file path logs to stderr only.
void init(const std::string& level, const std::string& file = "");

}  // namespace agent::logger
