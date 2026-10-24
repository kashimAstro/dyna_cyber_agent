#pragma once
#include "collectors/collector.h"
#include "core/config.h"
#include "geo/geo_db.h"
#include "intel/threat_intel.h"
#include "store/store.h"

namespace agent {

// Adds what the agent knows to observations before they are analysed and stored: where an address is (country,
// coordinates), whether it is on a threat list, whether a login makes physical sense. Rules then match on the
// result like on any other field. Everything here runs on the agent's machine, from local databases.
class Enricher {
 public:
  Enricher(Store& store, AnalysisConfig cfg) : store_(store), cfg_(cfg) {}
  void setGeo(GeoDb* g) { geo_ = g; }
  void setThreatIntel(ThreatIntel* t) { intel_ = t; }

  void apply(Snapshot& s);

  // Great-circle distance in kilometres.
  static double distanceKm(double lat1, double lon1, double lat2, double lon2);

 private:
  std::optional<GeoPoint> locate(const std::string& ip);
  void tagThreats(Snapshot& s);
  void tagOutbound(Snapshot& s);
  void tagLogins(Snapshot& s);

  Store& store_;
  AnalysisConfig cfg_;
  GeoDb* geo_ = nullptr;
  ThreatIntel* intel_ = nullptr;
};

}  // namespace agent
