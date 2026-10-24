#include "vuln/version.h"

#include <cctype>

namespace agent {
namespace {

int order(int c) {
  if (c == '~') return -1;
  if (std::isdigit(c)) return 0;
  if (std::isalpha(c)) return c;
  if (c == 0) return 0;
  return c + 256;
}

// dpkg's verrevcmp: alternating non-digit and digit runs.
int verrevcmp(const std::string& a, const std::string& b) {
  size_t i = 0, j = 0;
  while (i < a.size() || j < b.size()) {
    int first_diff = 0;
    while ((i < a.size() && !std::isdigit(static_cast<unsigned char>(a[i]))) || (j < b.size() && !std::isdigit(static_cast<unsigned char>(b[j])))) {
      const int ac = i < a.size() ? order(static_cast<unsigned char>(a[i])) : 0;
      const int bc = j < b.size() ? order(static_cast<unsigned char>(b[j])) : 0;
      if (ac != bc) return ac - bc;
      ++i;
      ++j;
    }
    while (i < a.size() && a[i] == '0') ++i;
    while (j < b.size() && b[j] == '0') ++j;
    while (i < a.size() && std::isdigit(static_cast<unsigned char>(a[i])) && j < b.size() && std::isdigit(static_cast<unsigned char>(b[j]))) {
      if (!first_diff) first_diff = a[i] - b[j];
      ++i;
      ++j;
    }
    if (i < a.size() && std::isdigit(static_cast<unsigned char>(a[i]))) return 1;
    if (j < b.size() && std::isdigit(static_cast<unsigned char>(b[j]))) return -1;
    if (first_diff) return first_diff;
  }
  return 0;
}

struct Parts {
  long epoch = 0;
  std::string upstream, revision;
};

Parts split(const std::string& v) {
  Parts p;
  std::string rest = v;
  const size_t colon = rest.find(':');
  if (colon != std::string::npos && colon > 0 && rest.find_first_not_of("0123456789") >= colon) {
    p.epoch = std::stol(rest.substr(0, colon));
    rest = rest.substr(colon + 1);
  }
  const size_t dash = rest.rfind('-');
  if (dash != std::string::npos) {
    p.upstream = rest.substr(0, dash);
    p.revision = rest.substr(dash + 1);
  } else {
    p.upstream = rest;
  }
  return p;
}

int sign(int x) { return x < 0 ? -1 : x > 0 ? 1 : 0; }

}  // namespace

int compareDebVersion(const std::string& a, const std::string& b) {
  const Parts pa = split(a), pb = split(b);
  if (pa.epoch != pb.epoch) return pa.epoch < pb.epoch ? -1 : 1;
  if (int r = verrevcmp(pa.upstream, pb.upstream)) return sign(r);
  return sign(verrevcmp(pa.revision, pb.revision));
}

int compareUpstream(const std::string& a, const std::string& b) { return sign(verrevcmp(a, b)); }

std::string upstreamVersion(const std::string& version) {
  std::string u = split(version).upstream;
  for (const char* suffix : {"+dfsg", "+ds", "+git", "+really", "~dfsg", "+repack", "+nmu"}) {
    const size_t p = u.find(suffix);
    if (p != std::string::npos && p > 0) u = u.substr(0, p);
  }
  return u;
}

}  // namespace agent
