#pragma once
#include <string>

namespace agent {

// Debian/Ubuntu version ordering (epoch:upstream-revision, '~' sorts before everything), as dpkg does it.
// Also a good approximation of RPM's ordering for the version strings we meet here.
// Returns <0, 0, >0.
int compareDebVersion(const std::string& a, const std::string& b);

// Ordering of upstream versions as found in CPE ranges ("1.0.2k" > "1.0.2", "2.10" > "2.9").
int compareUpstream(const std::string& a, const std::string& b);

// "1:2.4.52-1ubuntu4.6" -> "2.4.52"; strips epoch, distribution revision and "+dfsg"-like suffixes.
std::string upstreamVersion(const std::string& version);

}  // namespace agent
