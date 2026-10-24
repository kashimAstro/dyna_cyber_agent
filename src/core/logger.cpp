#include "core/logger.h"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <vector>

namespace agent::logger {

void init(const std::string& level, const std::string& file) {
  std::vector<spdlog::sink_ptr> sinks;
  sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
  if (!file.empty()) {
    sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(file));
  }
  auto lg = std::make_shared<spdlog::logger>("agent", sinks.begin(), sinks.end());
  lg->set_pattern("%Y-%m-%dT%H:%M:%S.%e [%^%l%$] %v");
  lg->set_level(spdlog::level::from_str(level));
  spdlog::set_default_logger(std::move(lg));
}

}  // namespace agent::logger
