#pragma once
#include <string>
#include <vector>

#include "analysis/finding.h"
#include "collectors/collector.h"

namespace agent {

// Facets of an observation that make up the "normal" state of a machine.
// Unstable parts (pids, inodes, ephemeral ports) are normalised away.
std::vector<Identity> identitiesOf(const Observation& o);

// Stable identity of an observation, used to deduplicate findings across snapshots.
std::string stableKey(const Observation& o);

}  // namespace agent

namespace agent {
const std::vector<std::string>& knownFacets();
const std::vector<std::string>& knownObservationTypes();
}  // namespace agent
