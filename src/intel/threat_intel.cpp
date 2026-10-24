#include "intel/threat_intel.h"

#include <spdlog/spdlog.h>
#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/util.h"

namespace agent {
namespace {

int rank(const std::string& category) {
  if (category == "c2") return 4;
  if (category == "compromised") return 3;
  if (category == "attacker") return 2;
  return 1;
}

}  // namespace

std::optional<uint32_t> ThreatIntel::parseIpv4(const std::string& s) {
  const auto p = util::split(s, '.');
  if (p.size() != 4) return std::nullopt;
  uint32_t v = 0;
  for (const auto& part : p) {
    if (part.empty() || part.size() > 3 || !util::allDigits(part)) return std::nullopt;
    const auto n = util::parseUint(part);
    if (!n || *n > 255) return std::nullopt;
    v = (v << 8) | static_cast<uint32_t>(*n);
  }
  return v;
}

std::vector<ThreatIntel::Range> ThreatIntel::merge(std::vector<Range> r) {
  std::sort(r.begin(), r.end());
  std::vector<Range> out;
  for (const auto& x : r) {
    if (!out.empty() && static_cast<uint64_t>(x.lo) <= static_cast<uint64_t>(out.back().hi) + 1) out.back().hi = std::max(out.back().hi, x.hi);
    else out.push_back(x);
  }
  return out;
}

std::vector<ThreatIntel::Range> ThreatIntel::parseList(const std::string& text) {
  std::vector<Range> out;
  for (const auto& raw : util::split(text, '\n')) {
    std::string line = raw;
    const size_t c = line.find_first_of("#;");
    if (c != std::string::npos) line.resize(c);
    const auto t = util::splitWs(line);
    if (t.empty()) continue;
    const std::string tok = t[0];
    const size_t slash = tok.find('/');
    const auto ip = parseIpv4(tok.substr(0, slash));
    if (!ip) continue;
    int bits = 32;
    if (slash != std::string::npos) {
      const auto b = util::parseUint(tok.substr(slash + 1));
      if (!b || *b > 32) continue;
      bits = static_cast<int>(*b);
    }
    const uint32_t mask = bits == 0 ? 0u : (0xFFFFFFFFu << (32 - bits));
    out.push_back({*ip & mask, (*ip & mask) | ~mask});
  }
  return merge(std::move(out));
}

bool ThreatIntel::loadOne(Loaded& l) {
  std::ifstream in(pathOf(l.cfg.name));
  if (!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  l.ranges = parseList(ss.str());
  struct stat st {};
  l.fetched = ::stat(pathOf(l.cfg.name).c_str(), &st) == 0 ? static_cast<int64_t>(st.st_mtime) : 0;
  return !l.ranges.empty();
}

size_t ThreatIntel::load() {
  std::lock_guard<std::mutex> lock(mu_);
  lists_.clear();
  size_t total = 0;
  for (const auto& c : configured_) {
    Loaded l;
    l.cfg = c;
    loadOne(l);
    total += l.ranges.size();
    lists_.push_back(std::move(l));
  }
  return total;
}

// A list with a header and no entries (a C2 tracker with nothing active) is valid and must replace the old copy;
// an HTML error page or an empty body is not.
static bool onlyComments(const std::string& body) {
  bool comment = false;
  size_t i = 0;
  while (i < body.size()) {
    size_t e = body.find('\n', i);
    if (e == std::string::npos) e = body.size();
    size_t b = i;
    while (b < e && std::isspace(static_cast<unsigned char>(body[b]))) ++b;
    if (b < e) {
      if (body[b] != '#' && body[b] != ';') return false;
      comment = true;
    }
    i = e + 1;
  }
  return comment;
}

bool ThreatIntel::empty() const {
  std::lock_guard<std::mutex> lock(mu_);
  return std::all_of(lists_.begin(), lists_.end(), [](const Loaded& l) { return l.ranges.empty(); });
}

std::optional<ThreatHit> ThreatIntel::lookup(const std::string& ip) const {
  const auto v = parseIpv4(ip);
  if (!v) return std::nullopt;
  std::lock_guard<std::mutex> lock(mu_);
  std::optional<ThreatHit> best;
  for (const auto& l : lists_) {
    auto it = std::upper_bound(l.ranges.begin(), l.ranges.end(), Range{*v, 0});
    if (it == l.ranges.begin()) continue;
    --it;
    if (*v < it->lo || *v > it->hi) continue;
    if (!best || rank(l.cfg.category) > rank(best->category)) best = ThreatHit{l.cfg.name, l.cfg.category};
  }
  return best;
}

std::vector<ThreatIntel::ListInfo> ThreatIntel::info() const {
  std::lock_guard<std::mutex> lock(mu_);
  std::vector<ListInfo> out;
  for (const auto& l : lists_) out.push_back({l.cfg.name, l.cfg.category, l.ranges.size(), l.fetched});
  return out;
}

std::vector<ThreatIntel::Report> ThreatIntel::refresh(IHttpClient& http, int64_t now, int64_t max_age, std::chrono::seconds timeout) {
  std::vector<Report> reports;
  std::error_code ec;
  std::filesystem::create_directories(dir_, ec);
  for (size_t i = 0; i < configured_.size(); ++i) {
    const auto& c = configured_[i];
    Report rep;
    rep.list = c.name;
    int64_t fetched = 0;
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (i < lists_.size()) fetched = lists_[i].fetched;
    }
    if (max_age > 0 && fetched > 0 && now - fetched < max_age) {
      rep.ok = true;
      rep.message = "up to date";
      {
        std::lock_guard<std::mutex> lock(mu_);
        rep.ranges = i < lists_.size() ? lists_[i].ranges.size() : 0;
      }
      reports.push_back(std::move(rep));
      continue;
    }
    auto r = http.get(c.url, {"User-Agent: dyna_cyber_agent (security monitor; read-only)"}, timeout);
    if (!r) {
      rep.message = r.error();
    } else if (r.value().status != 200) {
      rep.message = "HTTP " + std::to_string(r.value().status);
    } else {
      auto ranges = parseList(r.value().body);
      if (ranges.empty() && !onlyComments(r.value().body)) {
        rep.message = "no addresses found in the download (format changed?): keeping the previous copy";
      } else {
        const std::string tmp = pathOf(c.name) + ".tmp";
        {
          std::ofstream out(tmp, std::ios::trunc);
          out << r.value().body;
          if (!out) rep.message = "cannot write " + tmp;
        }
        if (rep.message.empty()) {
          if (std::rename(tmp.c_str(), pathOf(c.name).c_str()) != 0) {
            rep.message = "cannot replace " + pathOf(c.name);
          } else {
            std::lock_guard<std::mutex> lock(mu_);
            if (i >= lists_.size()) lists_.resize(configured_.size());
            lists_[i].cfg = c;
            lists_[i].ranges = std::move(ranges);
            lists_[i].fetched = now;
            rep.ok = true;
            rep.ranges = lists_[i].ranges.size();
            rep.message = std::to_string(rep.ranges) + " range(s)";
          }
        }
      }
    }
    if (!rep.ok) spdlog::warn("threat list {}: {}", c.name, rep.message);
    reports.push_back(std::move(rep));
  }
  return reports;
}

}  // namespace agent
