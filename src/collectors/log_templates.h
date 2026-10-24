#pragma once
#include <string>

namespace agent {

// The "shape" of a log message: every part that varies from one occurrence to the next (numbers, addresses, paths,
// identifiers, quoted text) is replaced by a placeholder, so "Accepted publickey for 1001 from 10.0.0.5 port 4211"
// and the same line with other values are one template. A message that fits no known template is new behaviour,
// whatever it says, without anyone having written a parser for it.
std::string logTemplate(const std::string& message);

// Stable short identifier of (program, template).
std::string logTemplateId(const std::string& program, const std::string& tmpl);

// True when the template contains words that mean trouble ("denied", "segfault", "corrupt"...).
bool logAlarming(const std::string& tmpl);

// Messages that carry no information ("-- MARK --", "last message repeated N times").
bool logNoise(const std::string& program, const std::string& message);

}  // namespace agent
