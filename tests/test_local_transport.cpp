#include <catch2/catch.hpp>
#include <unistd.h>

#include <fstream>

#include "transport/local_transport.h"

using namespace agent;

TEST_CASE("readFile on /proc and truncation") {
  LocalTransport t;
  auto r = t.readFile("/proc/self/status", 1 << 20);
  REQUIRE(r.ok());
  REQUIRE(r.value().data.find("Name:") != std::string::npos);
  REQUIRE_FALSE(r.value().truncated);

  auto small = t.readFile("/proc/self/status", 10);
  REQUIRE(small.ok());
  REQUIRE(small.value().data.size() == 10);
  REQUIRE(small.value().truncated);
}

TEST_CASE("readFile rejects bad targets") {
  LocalTransport t;
  REQUIRE_FALSE(t.readFile("relative/path", 10).ok());
  REQUIRE_FALSE(t.readFile("/nonexistent", 10).ok());
  REQUIRE_FALSE(t.readFile("/etc", 10).ok());        // directory
  REQUIRE_FALSE(t.readFile("/dev/null", 10).ok());   // char device
}

TEST_CASE("readLink, listDir, stat") {
  LocalTransport t;
  auto exe = t.readLink("/proc/self/exe");
  REQUIRE(exe.ok());
  REQUIRE(exe.value().find("agent_tests") != std::string::npos);

  auto dir = t.listDir("/proc/self");
  REQUIRE(dir.ok());
  bool found = false;
  for (const auto& e : dir.value()) found |= e.name == "status";
  REQUIRE(found);

  auto st = t.stat("/proc/self/exe");
  REQUIRE(st.ok());
  REQUIRE(st.value().is_symlink);
}

TEST_CASE("run executes whitelisted commands") {
  LocalTransport t;
  auto r = t.run({"uname", "-s"});
  REQUIRE(r.ok());
  REQUIRE(r.value().exit_code == 0);
  REQUIRE(r.value().out == "Linux\n");

  auto bad = t.run({"rm", "-rf", "/tmp/x"});
  REQUIRE_FALSE(bad.ok());
}

TEST_CASE("run reports non-zero exit and output cap") {
  LocalTransport t;
  auto r = t.run({"ls", "/nonexistent-dir"});
  REQUIRE(r.ok());
  REQUIRE(r.value().exit_code != 0);
  REQUIRE_FALSE(r.value().err.empty());

  RunLimits lim;
  lim.max_output = 100;
  auto big = t.run({"ls", "-l", "/usr/bin"}, lim);
  REQUIRE(big.ok());
  REQUIRE(big.value().truncated);
  REQUIRE(big.value().out.size() == 100);
}

TEST_CASE("run enforces timeout") {
  LocalTransport t;
  RunLimits lim;
  lim.timeout = std::chrono::seconds(1);
  auto r = t.run({"journalctl", "-f", "-n", "0"}, lim);
  // journalctl may be missing or lack permission; when it runs it must be killed by the timeout.
  if (r.ok() && r.value().exit_code == 128 + 9) REQUIRE(r.value().timed_out);
}
