#include <catch2/catch.hpp>

#include "transport/command_policy.h"

using namespace agent;
using V = std::vector<std::string>;

TEST_CASE("whitelisted read-only commands pass") {
  REQUIRE(CommandPolicy::validate(V{"ss", "-tulpn"}).ok());
  REQUIRE(CommandPolicy::validate(V{"ip", "-j", "addr", "show"}).ok());
  REQUIRE(CommandPolicy::validate(V{"ip", "route"}).ok());
  REQUIRE(CommandPolicy::validate(V{"journalctl", "-u", "ssh", "--since", "today"}).ok());
  REQUIRE(CommandPolicy::validate(V{"systemctl", "list-timers"}).ok());
  REQUIRE(CommandPolicy::validate(V{"sysctl", "net.ipv4.ip_forward"}).ok());
  REQUIRE(CommandPolicy::validate(V{"dpkg", "-V"}).ok());
}

TEST_CASE("unknown commands and paths are rejected") {
  REQUIRE_FALSE(CommandPolicy::validate(V{}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"rm", "-rf", "/"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"sh", "-c", "id"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"/bin/ls"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"./ss"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"find", "/", "-delete"}).ok());
}

TEST_CASE("mutating variants of allowed commands are rejected") {
  REQUIRE_FALSE(CommandPolicy::validate(V{"ss", "-K"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"ss", "-tK"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"ip", "addr", "add", "1.2.3.4/24", "dev", "lo"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"ip", "route", "flush", "all"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"ip", "netns", "exec", "x", "sh"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"ip", "-batch", "/tmp/x"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"journalctl", "--vacuum-size=1M"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"journalctl", "--rotate"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"systemctl", "stop", "ssh"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"systemctl"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"sysctl", "-w", "net.ipv4.ip_forward=1"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"sysctl", "net.ipv4.ip_forward=1"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"dmesg", "-c"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"dmesg", "--clear"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"mount", "/dev/sda1", "/mnt"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"dpkg", "-i", "x.deb"}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"dpkg", "--purge", "x"}).ok());
}

TEST_CASE("malformed arguments are rejected") {
  REQUIRE_FALSE(CommandPolicy::validate(V{"ls", std::string("a\0b", 3)}).ok());
  REQUIRE_FALSE(CommandPolicy::validate(V{"ls", std::string(5000, 'a')}).ok());
  V many(100, "x");
  many[0] = "ls";
  REQUIRE_FALSE(CommandPolicy::validate(many).ok());
}
