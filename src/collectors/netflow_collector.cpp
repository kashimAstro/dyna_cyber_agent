#include "collectors/netflow_collector.h"

#include <algorithm>
#include <chrono>
#include <cmath>

#include "collectors/log_parsers.h"
#include "core/util.h"

namespace agent {
namespace {

constexpr int64_t kWindow = 6 * 3600;
constexpr int64_t kWarmup = 180;          // samples (6 hours at the default pace) before a spike can be called
constexpr double kMinSpikeRate = 512 * 1024.0;

double median(std::vector<double> v) {
  std::sort(v.begin(), v.end());
  const size_t n = v.size();
  return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

bool skipInterface(const std::string& n) {
  return n == "lo" || util::startsWith(n, "docker") || util::startsWith(n, "veth") || util::startsWith(n, "br-") || util::startsWith(n, "virbr") || util::startsWith(n, "cni") ||
         util::startsWith(n, "flannel") || util::startsWith(n, "cali");
}

}  // namespace

std::optional<Beacon> detectBeacon(const Store::ConnSeries& s, const BeaconParams& p) {
  // connections opened within a few seconds of each other are one burst (a page load, a retry), not two beats
  std::vector<int64_t> t;
  for (int64_t x : s.times) if (t.empty() || x - t.back() > std::max<int64_t>(3, p.sample / 2)) t.push_back(x);
  if (t.size() < p.min_events || t.back() - t.front() < p.min_span) return std::nullopt;
  std::vector<double> d;
  for (size_t i = 1; i < t.size(); ++i) d.push_back(static_cast<double>(t[i] - t[i - 1]));
  const double m = median(d);
  if (m < static_cast<double>(p.min_period) || m > static_cast<double>(p.max_period)) return std::nullopt;
  const double tol = std::max(p.max_jitter * m, 2.0 * static_cast<double>(p.sample));
  size_t on_beat = 0;
  std::vector<double> dev;
  for (double x : d) {
    if (std::fabs(x - m) <= tol) ++on_beat;
    dev.push_back(std::fabs(x - m));
  }
  if (static_cast<double>(on_beat) / static_cast<double>(d.size()) < 0.8) return std::nullopt;
  Beacon b;
  b.dest = s.dest;
  b.comm = s.comm;
  b.port = s.port;
  b.events = t.size();
  b.period = m;
  b.jitter = median(dev) / m;
  b.first = t.front();
  b.last = t.back();
  return b;
}

bool trafficSpike(TrafficModel& m, double rate) {
  const bool warm = m.samples >= kWarmup;
  const double sd = std::sqrt(std::max(0.0, m.var));
  const bool spike = warm && rate > kMinSpikeRate && rate > std::max(5.0 * m.ewma, m.ewma + 8.0 * sd);
  const double alpha = spike ? 0.01 : 0.1;  // a spike must not teach the model that it is normal
  if (m.samples == 0) {
    m.ewma = rate;
  } else {
    const double diff = rate - m.ewma;
    m.ewma += alpha * diff;
    m.var = (1 - alpha) * (m.var + alpha * diff * diff);
  }
  ++m.samples;
  return spike;
}

std::map<std::string, std::pair<uint64_t, uint64_t>> NetflowCollector::parseNetDev(const std::string& text) {
  std::map<std::string, std::pair<uint64_t, uint64_t>> out;
  for (const auto& line : util::split(text, '\n')) {
    const size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    const std::string iface(util::trim(line.substr(0, colon)));
    const auto f = util::splitWs(line.substr(colon + 1));
    if (f.size() < 9 || iface.empty()) continue;
    const auto rx = util::parseUint(f[0]), tx = util::parseUint(f[8]);
    if (rx && tx) out[iface] = {*rx, *tx};
  }
  return out;
}

Result<CollectOutput> NetflowCollector::collect(ITransport& t) {
  CollectOutput out;
  const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  // ---- beaconing -----------------------------------------------------------------------------------------------------
  if (opts_.beaconing && opts_.store) {
    BeaconParams p;
    p.sample = std::max<int64_t>(5, opts_.network_interval);
    auto series = opts_.store->connectionSeries(opts_.target, now - kWindow, p.min_events);
    if (series) {
      for (const auto& s : series.value()) {
        const auto b = detectBeacon(s, p);
        if (!b) continue;
        const bool ext = !isPrivateIp(b->dest);
        const bool common = b->port == 80 || b->port == 443 || b->port == 53;
        Observation o;
        o.type = "net.beacon";
        o.key = "beacon|" + b->dest + ":" + std::to_string(b->port);
        o.tags.push_back("beacon");
        if (ext) o.tags.push_back("external_dest");
        o.data = {{"dest", b->dest}, {"port", b->port}, {"comm", b->comm}, {"events", b->events}, {"period_s", std::round(b->period)},
                  {"jitter", std::round(b->jitter * 100) / 100}, {"first_ts", b->first}, {"last_ts", b->last}, {"uncommon_external", ext && !common}};
        out.observations.push_back(std::move(o));
      }
    }
  }

  // ---- outbound traffic ---------------------------------------------------------------------------------------------
  if (opts_.traffic_spikes) {
    auto dev = t.readFile("/proc/net/dev", 1 << 20);
    if (dev) {
      for (const auto& [iface, bytes] : parseNetDev(dev.value().data)) {
        if (skipInterface(iface)) continue;
        const auto prev = last_.find(iface);
        const uint64_t tx = bytes.second;
        if (prev != last_.end() && now > prev->second.ts && tx >= prev->second.tx) {
          const double rate = static_cast<double>(tx - prev->second.tx) / static_cast<double>(now - prev->second.ts);
          TrafficModel m;
          const std::string key = "txmodel|" + opts_.target + "|" + iface;
          if (opts_.state) {
            if (const auto v = opts_.state->get(key)) {
              const auto f = util::split(*v, ';');
              if (f.size() == 3) {
                try { m.ewma = std::stod(f[0]); m.var = std::stod(f[1]); m.samples = std::stoll(f[2]); } catch (...) {}
              }
            }
          }
          const bool spike = trafficSpike(m, rate);
          if (opts_.state) opts_.state->set(key, std::to_string(m.ewma) + ";" + std::to_string(m.var) + ";" + std::to_string(m.samples));
          int& hot = hot_[iface];
          hot = spike ? hot + 1 : 0;
          if (hot >= 2) {  // two samples in a row: a single burst (a backup, an upload) is not enough
            Observation o;
            o.type = "net.traffic_spike";
            o.key = "traffic|" + iface;
            o.tags.push_back("traffic_spike");
            o.data = {{"interface", iface}, {"rate_kbps", std::round(rate * 8 / 1000)}, {"usual_kbps", std::round(m.ewma * 8 / 1000)}, {"samples", m.samples}};
            out.observations.push_back(std::move(o));
          }
        }
        last_[iface] = {tx, now};
      }
    } else {
      out.warnings.push_back("/proc/net/dev not readable: traffic check skipped");
    }
  }
  return out;
}

}  // namespace agent
