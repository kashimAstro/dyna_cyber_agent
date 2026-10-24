#include "enrich/enrich.h"

#include <cmath>

#include "collectors/log_parsers.h"
#include "core/util.h"

namespace agent {
namespace {

constexpr double kPi = 3.14159265358979323846;
constexpr int64_t kTravelLookback = 24 * 3600;

bool publicIp(const std::string& ip) { return looksLikeIp(ip) && !GeoDb::isLocalAddress(ip); }

}  // namespace

double Enricher::distanceKm(double lat1, double lon1, double lat2, double lon2) {
  const double r = 6371.0, d2r = kPi / 180.0;
  const double dlat = (lat2 - lat1) * d2r, dlon = (lon2 - lon1) * d2r;
  const double a = std::sin(dlat / 2) * std::sin(dlat / 2) + std::cos(lat1 * d2r) * std::cos(lat2 * d2r) * std::sin(dlon / 2) * std::sin(dlon / 2);
  return 2 * r * std::asin(std::min(1.0, std::sqrt(a)));
}

std::optional<GeoPoint> Enricher::locate(const std::string& ip) {
  if (!geo_ || !publicIp(ip)) return std::nullopt;
  return geo_->lookup(ip);
}

void Enricher::apply(Snapshot& s) {
  if (!s.error.empty()) return;
  if (intel_) tagThreats(s);
  if (s.collector == "network") tagOutbound(s);
  if (s.collector == "logs") tagLogins(s);
}

void Enricher::tagThreats(Snapshot& s) {
  if (intel_->empty()) return;
  auto mark = [&](Observation& o, const std::string& ip, bool attacker_context) {
    if (!publicIp(ip)) return;
    const auto hit = intel_->lookup(ip);
    if (!hit) return;
    o.data["ti"] = {{"list", hit->list}, {"category", hit->category}};
    o.tags.push_back(attacker_context ? "ti_known_attacker" : "ti_malicious");
    if (hit->category == "c2") o.tags.push_back("ti_c2");
  };
  for (auto& o : s.observations) {
    if (o.type == "socket.inet") {
      const std::string st = o.data.value("state", std::string());
      if (st == "ESTABLISHED" || st == "SYN_SENT") mark(o, o.data.value("remote_addr", std::string()), false);
    } else if (o.type == "log.auth.login") {
      mark(o, o.data.value("src_ip", std::string()), false);  // someone from a blocklisted address got in
    } else if (o.type == "log.auth.bruteforce" || o.type == "log.auth.scan" || o.type == "log.web.attack" || o.type == "log.web.scan") {
      mark(o, o.data.value("src_ip", std::string()), true);   // already an attack: the list only adds confidence
    }
  }
}

void Enricher::tagOutbound(Snapshot& s) {
  if (!cfg_.outbound_countries || !geo_ || geo_->empty()) return;
  std::map<std::string, std::string> cache;
  for (auto& o : s.observations) {
    if (o.type != "socket.inet") continue;
    const std::string st = o.data.value("state", std::string());
    if (st != "ESTABLISHED" && st != "SYN_SENT") continue;
    const std::string ip = o.data.value("remote_addr", std::string());
    auto it = cache.find(ip);
    if (it == cache.end()) {
      const auto g = locate(ip);
      it = cache.emplace(ip, g ? g->cc : std::string()).first;
    }
    if (!it->second.empty()) o.data["remote_cc"] = it->second;
  }
}

void Enricher::tagLogins(Snapshot& s) {
  if (!cfg_.travel) return;
  const int bucket = static_cast<int>((s.ts % 86400) / 3600 / 3);  // 3-hour slot of the day, UTC
  for (auto& o : s.observations) {
    if (o.type != "log.auth.login") continue;
    const std::string user = o.data.value("user", std::string());
    const std::string ip = o.data.value("src_ip", std::string());
    if (user.empty()) continue;
    o.data["hour_bucket"] = bucket;
    const auto g = locate(ip);
    if (!g) continue;
    o.data["cc"] = g->cc;
    o.data["city"] = g->city;
    o.data["lat"] = g->lat;
    o.data["lon"] = g->lon;

    auto prev = store_.lastLocatedLogin(user, s.ts);
    if (prev && prev.value()) {
      const auto& p = *prev.value();
      const double km = distanceKm(p.lat, p.lon, g->lat, g->lon);
      const int64_t dt = std::max<int64_t>(60, s.ts - p.ts);
      if (km >= cfg_.travel_min_km && dt <= kTravelLookback) {
        const double kmh = km / (static_cast<double>(dt) / 3600.0);
        if (kmh > cfg_.travel_max_kmh) {
          o.tags.push_back("impossible_travel");
          o.data["travel"] = {{"from_ip", p.ip}, {"from_cc", p.cc}, {"from_ts", p.ts}, {"distance_km", std::round(km)}, {"minutes", dt / 60}, {"speed_kmh", std::round(kmh)}};
        }
      }
      // keep the history compact: a new row only when the place changed or some time has passed
      if (km < 50 && s.ts - p.ts < 1800) continue;
    }
    store_.recordLogin({s.ts, s.target, user, ip, g->cc, g->lat, g->lon, true});
  }
}

}  // namespace agent
