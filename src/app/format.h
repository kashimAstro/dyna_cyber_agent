#pragma once
#include <string>

#include "analysis/finding.h"
#include "collectors/collector.h"
#include "llm/analysis.h"

namespace agent {

// Human-readable text rendering of a snapshot: counts per type plus every tagged observation.
std::string formatSnapshot(const Snapshot& s);

// One line per finding, or a full multi-line view with `detailed`.
std::string formatFinding(const Finding& f, bool detailed);
std::string formatAssessment(const Assessment& a);

}  // namespace agent
