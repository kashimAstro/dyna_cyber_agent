#pragma once
#include "core/config.h"
#include "llm/http_client.h"
#include "vuln/feed_sync.h"
#include "vuln/vuln_db.h"

namespace agent {

class Store;

// What the `vulns` collector needs besides the target's own data. Owned by main; collectors only borrow it.
struct VulnContext {
  VulnDb* db = nullptr;
  IHttpClient* http = nullptr;
  FeedSync* sync = nullptr;  // optional: enriches matches the incremental feed has not delivered yet
  VulnConfig cfg;
  Store* store = nullptr;    // where the `packages` snapshots live
};

}  // namespace agent
