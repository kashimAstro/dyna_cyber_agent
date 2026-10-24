#include <catch2/catch.hpp>

#include "vuln/cvss.h"
#include "vuln/version.h"

using namespace agent;

TEST_CASE("dpkg version ordering") {
  auto lt = [](const char* a, const char* b) { return compareDebVersion(a, b) < 0 && compareDebVersion(b, a) > 0; };
  REQUIRE(lt("1.0", "1.1"));
  REQUIRE(lt("1.9", "1.10"));                       // numeric, not lexical
  REQUIRE(lt("1.0~rc1", "1.0"));                    // tilde sorts before everything
  REQUIRE(lt("1.0", "1.0-1"));
  REQUIRE(lt("1.0-1", "1.0-1ubuntu1"));
  REQUIRE(lt("1.0-1ubuntu1", "1.0-1ubuntu1.1"));
  REQUIRE(lt("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.12"));
  REQUIRE(lt("3.0.2-0ubuntu1.12", "3.0.2-0ubuntu1.12+b1"));
  REQUIRE(lt("3.0", "1:1.0"));                      // epoch wins
  REQUIRE(lt("2.4.52-1", "2.4.54-1"));
  REQUIRE(lt("1.0a", "1.0b"));
  REQUIRE(lt("1.0", "1.0a"));
  REQUIRE(compareDebVersion("1.0", "1.0") == 0);
  REQUIRE(compareDebVersion("1.00", "1.0") == 0);   // leading zeros do not matter
  REQUIRE(compareDebVersion("0:1.0", "1.0") == 0);  // missing epoch is zero
  REQUIRE(lt("5.10.0-1", "5.10.0-2"));
  REQUIRE(lt("7.88.1-10+deb12u4", "7.88.1-10+deb12u5"));
}

TEST_CASE("upstream version ordering and extraction") {
  REQUIRE(compareUpstream("1.0.2", "1.0.2k") < 0);
  REQUIRE(compareUpstream("1.0.2k", "1.0.2l") < 0);
  REQUIRE(compareUpstream("2.10", "2.9") > 0);
  REQUIRE(compareUpstream("2.4.52", "2.4.52") == 0);
  REQUIRE(compareUpstream("3.0.0", "3.0.10") < 0);

  REQUIRE(upstreamVersion("1:2.4.52-1ubuntu4.6") == "2.4.52");
  REQUIRE(upstreamVersion("3.0.2-0ubuntu1.12") == "3.0.2");
  REQUIRE(upstreamVersion("7.88.1-10+deb12u5") == "7.88.1");
  REQUIRE(upstreamVersion("1.2.3+dfsg-4") == "1.2.3");
  REQUIRE(upstreamVersion("5.1.8-6.el9_1") == "5.1.8");
  REQUIRE(upstreamVersion("2.36") == "2.36");
}

TEST_CASE("CVSS v3 base scores match the specification") {
  auto s = [](const char* v) { return cvssV3Score(v); };
  REQUIRE(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").value() == Approx(10.0));   // Log4Shell
  REQUIRE(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").value() == Approx(9.8));
  REQUIRE(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").value() == Approx(6.1));    // classic XSS
  REQUIRE(s("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").value() == Approx(7.8));    // local privilege escalation
  REQUIRE(s("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N").value() == Approx(5.9));
  REQUIRE(s("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H").value() == Approx(7.5));    // v3.0 works too
  REQUIRE(s("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N").value() == Approx(1.6));
  REQUIRE(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").value() == Approx(0.0));
  REQUIRE_FALSE(s("AV:N/AC:L/Au:N/C:C/I:C/A:C"));                                         // v2: not computed here
  REQUIRE_FALSE(s("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
  REQUIRE_FALSE(s("CVSS:3.1/AV:N/AC:L"));
  REQUIRE_FALSE(s(""));

  REQUIRE(cvssSeverity(10.0) == "critical");
  REQUIRE(cvssSeverity(9.0) == "critical");
  REQUIRE(cvssSeverity(8.9) == "high");
  REQUIRE(cvssSeverity(7.0) == "high");
  REQUIRE(cvssSeverity(6.9) == "medium");
  REQUIRE(cvssSeverity(3.9) == "low");
  REQUIRE(cvssSeverity(0.0) == "none");
}
