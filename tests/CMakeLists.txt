add_executable(agent_tests
  test_main.cpp
  test_config.cpp
  test_command_policy.cpp
  test_local_transport.cpp
  test_collectors.cpp
  test_store.cpp
  test_analysis.cpp
  test_llm.cpp
  test_report.cpp
  test_ssh.cpp
  test_logs.cpp
  test_log_collector.cpp
  test_collectors2.cpp
  test_rules_phase6.cpp
  test_vuln_basics.cpp
  test_vuln_feeds.cpp
  test_feed_sync.cpp
  test_vuln_matcher.cpp
  test_vuln_integration.cpp
  test_web.cpp
  test_geo.cpp
  test_explain.cpp
  test_incident.cpp
  test_exposure.cpp
  test_peers.cpp
  test_crossview.cpp
  test_logtemplates.cpp
  test_netflow.cpp
  test_enrich.cpp
)
target_link_libraries(agent_tests PRIVATE agent_core Catch2::Catch2)
add_test(NAME agent_tests COMMAND agent_tests)
target_compile_definitions(agent_tests PRIVATE DEFAULT_RULES_DIR="${CMAKE_SOURCE_DIR}/rules/default")
