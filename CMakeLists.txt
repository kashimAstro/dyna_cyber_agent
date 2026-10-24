cmake_minimum_required(VERSION 3.20)
project(dyna_cyber_agent VERSION 0.9.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(AGENT_BUILD_TESTS "Build unit tests" ON)

include(cmake/Dependencies.cmake)

# The console page is embedded in the binary (nothing to install or serve from disk).
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/web/index.html)
file(READ ${CMAKE_SOURCE_DIR}/web/index.html CONSOLE_TEXT)
file(READ ${CMAKE_SOURCE_DIR}/web/world_data.js WORLD_TEXT)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/web/world_data.js)
string(REPLACE "/*WORLD_DATA*/" "${WORLD_TEXT}" CONSOLE_TEXT "${CONSOLE_TEXT}")
string(HEX "${CONSOLE_TEXT}" CONSOLE_HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," CONSOLE_BYTES "${CONSOLE_HEX}")
file(WRITE ${CMAKE_BINARY_DIR}/generated/console_html.cpp
"namespace agent {
extern const char* const kConsoleHtml;
static const unsigned char kConsoleBytes[] = {${CONSOLE_BYTES}0x00};
const char* const kConsoleHtml = reinterpret_cast<const char*>(kConsoleBytes);
}
")

add_library(agent_core STATIC
  src/core/config.cpp
  src/core/logger.cpp
  src/core/util.cpp
  src/core/sha256.cpp
  src/core/base64.cpp
  src/core/gzip.cpp
  src/analysis/identity.cpp
  src/analysis/rule.cpp
  src/analysis/analyzer.cpp
  src/analysis/explain.cpp
  src/analysis/incident.cpp
  src/transport/transport.cpp
  src/transport/scan_presets.cpp
  src/transport/command_policy.cpp
  src/transport/local_transport.cpp
  src/transport/gate.cpp
  src/transport/ssh_transport.cpp
  src/transport/factory.cpp
  src/collectors/collector.cpp
  src/collectors/process_collector.cpp
  src/collectors/network_collector.cpp
  src/collectors/netflow_collector.cpp
  src/enrich/conn_tracker.cpp
  src/enrich/enrich.cpp
  src/intel/threat_intel.cpp
  src/intel/intel_service.cpp
  src/collectors/user_collector.cpp
  src/collectors/log_parsers.cpp
  src/collectors/log_templates.cpp
  src/collectors/log_analyzer.cpp
  src/collectors/log_collector.cpp
  src/collectors/content_scan.cpp
  src/collectors/persistence_collector.cpp
  src/collectors/system_collector.cpp
  src/collectors/crossview_collector.cpp
  src/collectors/file_collector.cpp
  src/collectors/integrity_collector.cpp
  src/collectors/packages_collector.cpp
  src/collectors/peer_collector.cpp
  src/collectors/vuln_collector.cpp
  src/store/store.cpp
  src/store/store_ext.cpp
  src/llm/http_client.cpp
  src/llm/llm_client.cpp
  src/llm/analysis.cpp
  src/llm/synthesis.cpp
  src/app/synthesis.cpp
  src/llm/prompt.cpp
  src/llm/context.cpp
  src/llm/reasoner.cpp
  src/llm/assess.cpp
  src/vuln/version.cpp
  src/vuln/cvss.cpp
  src/vuln/feed_parsers.cpp
  src/vuln/vuln_db.cpp
  src/vuln/feed_sync.cpp
  src/vuln/cwe_names.cpp
  src/vuln/matcher.cpp
  src/vuln/vuln_service.cpp
  src/vuln/intel.cpp
  src/vuln/exposure.cpp
  src/report/mime.cpp
  src/report/mailer.cpp
  src/report/text_util.cpp
  src/report/labels.cpp
  src/report/mitre_names.cpp
  src/report/view.cpp
  src/report/report_builder.cpp
  src/report/render_text.cpp
  src/report/render_html.cpp
  src/report/notifier.cpp
  src/app/agent.cpp
  src/app/format.cpp
  src/geo/geo_db.cpp
  src/web/http_server.cpp
  src/web/api.cpp
  ${CMAKE_BINARY_DIR}/generated/console_html.cpp
)
target_include_directories(agent_core PUBLIC src)
target_compile_options(agent_core PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-missing-field-initializers)
find_package(ZLIB REQUIRED)
target_link_libraries(agent_core PUBLIC spdlog::spdlog yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json SQLite::SQLite3 CURL::libcurl ZLIB::ZLIB)

add_executable(dyna_cyber_agent src/main.cpp)
target_compile_options(dyna_cyber_agent PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-missing-field-initializers)
target_link_libraries(dyna_cyber_agent PRIVATE agent_core)
target_compile_definitions(dyna_cyber_agent PRIVATE AGENT_VERSION="${PROJECT_VERSION}")

if(AGENT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()


# ---- installation and packaging ---------------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS dyna_cyber_agent RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY rules/default/ DESTINATION ${CMAKE_INSTALL_DATADIR}/dyna_cyber_agent/rules FILES_MATCHING PATTERN "*.yaml")
install(FILES config/agent.example.yaml USAGE.md USAGE.it.md README.md README.it.md DESTINATION ${CMAKE_INSTALL_DATADIR}/dyna_cyber_agent)
install(FILES deploy/dyna_cyber_agent.service DESTINATION lib/systemd/system)
install(FILES deploy/dyna_cyber_agent-sudoers.example deploy/authorized_keys.example deploy/dyna_cyber_agent.logrotate DESTINATION ${CMAKE_INSTALL_DATADIR}/dyna_cyber_agent/deploy)

set(CPACK_PACKAGE_NAME "dyna-cyber-agent")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "administrator@localhost")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Read-only security monitoring agent with LLM assessment")
set(CPACK_GENERATOR "TGZ;DEB")
set(CPACK_STRIP_FILES ON)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssh-client")
set(CPACK_DEBIAN_PACKAGE_SECTION "admin")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/deploy/debian/postinst")
include(CPack)
