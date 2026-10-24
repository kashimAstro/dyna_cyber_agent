#pragma once
#include <optional>
#include <string>

namespace agent {

// Base score of a CVSS v3.0/v3.1 vector ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), per the FIRST specification.
std::optional<double> cvssV3Score(const std::string& vector);

// Qualitative rating: none (0), low (<4), medium (<7), high (<9), critical.
std::string cvssSeverity(double score);

}  // namespace agent
