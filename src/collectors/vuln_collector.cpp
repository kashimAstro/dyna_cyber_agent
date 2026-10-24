#include "collectors/vuln_collector.h"

#include <chrono>

#include "store/store.h"
#include "vuln/exposure.h"
#include "vuln/matcher.h"
#include "vuln/vuln_context.h"

namespace agent {

void VulnCollector::configure(const CollectorOptions& o) {
  opts_ = o;
  if (o.vuln) interval_ = o.vuln->cfg.match_every;
}

Result<CollectOutput> VulnCollector::collect(ITransport&) {
  const VulnContext* ctx = opts_.vuln;
  if (!ctx || !ctx->db || !ctx->store) return err("vulnerability matching is not configured (vuln.enabled)");

  auto snap = ctx->store->latest(opts_.target, "packages");
  if (!snap) return err(snap.error());
  if (!snap.value()) return err("no software inventory yet: the 'packages' collector has not completed for this target");
  const auto inv = inventoryFromSnapshot(*snap.value());
  if (!inv) return err("the latest 'packages' snapshot has no packages");

  VulnMatcher matcher(*ctx->db, ctx->http, ctx->cfg, ctx->sync);
  auto out = matcher.match(*inv);
  if (!out) return out;

  // reachability and priority (needs what the processes / network / packages collectors have recorded)
  annotateMatches(out.value().observations, ctx->cfg.exposure ? computeExposure(*ctx->store, opts_.target) : Exposure{});

  const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  if (now - snap.value()->ts > 48 * 3600) out.value().warnings.push_back("the software inventory is older than 48 hours: the 'packages' collector may be failing");
  if (auto st = ctx->db->stats(); st && st.value().cves == 0) {
    out.value().warnings.push_back("the vulnerability database is empty: the first feed synchronisation has not finished (see --vuln-status)");
  }
  return out;
}

}  // namespace agent
