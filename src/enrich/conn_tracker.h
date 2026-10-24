#pragma once
#include <map>
#include <string>
#include <vector>

#include "collectors/collector.h"
#include "store/store.h"

namespace agent {

// Turns the stream of `network` snapshots into a list of NEW outbound connections (one event per connection, not per
// poll). A connection that is still open in the next snapshot is the same connection; a TIME_WAIT socket left behind by
// a short one still counts, so short beacons are seen even if the poll lands after they closed.
class ConnTracker {
 public:
  // The first snapshot only primes the memory: connections that were already open when the agent started are not new.
  std::vector<Store::ConnEvent> update(const Snapshot& net);

 private:
  std::map<std::string, int64_t> seen_;  // "proto|raddr:rport|lport" -> last time seen
  bool primed_ = false;
};

}  // namespace agent
