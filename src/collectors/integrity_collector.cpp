#include "collectors/integrity_collector.h"

#include <algorithm>

#include "collectors/content_scan.h"
#include "core/util.h"

namespace agent {

std::vector<PackageDiff> parsePackageVerify(const std::string& text) {
  std::vector<PackageDiff> out;
  for (const auto& line : util::split(text, '\n')) {
    if (line.size() < 12) continue;
    PackageDiff d;
    // "??5??????   /usr/bin/x"  or  "??5?????? c /etc/x"  or  "missing     /usr/bin/y"  or  "missing   c /etc/z"
    if (util::startsWith(line, "missing")) {
      d.flags = "missing";
    } else {
      d.flags = line.substr(0, 9);
      bool ok = true;
      for (char c : d.flags) ok &= (c == '?' || c == '.' || std::isalnum(static_cast<unsigned char>(c)));
      if (!ok) continue;
    }
    const size_t path_at = line.find(" /");
    if (path_at == std::string::npos) continue;
    d.config = path_at >= 2 && line[path_at - 1] == 'c' && line[path_at - 2] == ' ';
    d.path = line.substr(path_at + 1);
    out.push_back(std::move(d));
  }
  return out;
}

Result<CollectOutput> IntegrityCollector::collect(ITransport& t) {
  const auto st = t.bulk({ReadOp::stat("/usr/bin/dpkg"), ReadOp::stat("/usr/bin/rpm")});
  std::vector<std::string> cmd;
  std::string manager;
  if (st[0].ok) {
    cmd = {"dpkg", "-V"};
    manager = "dpkg";
  } else if (st[1].ok) {
    cmd = {"rpm", "-Va"};
    manager = "rpm";
  } else {
    return err("no supported package manager (dpkg or rpm) found");
  }

  RunLimits lim;
  lim.timeout = std::chrono::seconds(900);  // verifying every installed file takes a while
  lim.max_output = 16u << 20;
  auto r = t.run(cmd, lim);
  if (!r) return err(r.error());
  if (r.value().timed_out) return err(manager + " verification timed out");
  // dpkg -V / rpm -Va exit non-zero when something differs; only a real failure has no output at all
  if (r.value().exit_code > 1 && r.value().out.empty()) return err(manager + " failed (exit " + std::to_string(r.value().exit_code) + "): " + r.value().err.substr(0, 150));

  CollectOutput out;
  auto diffs = parsePackageVerify(r.value().out);
  // the interesting ones first: binaries and libraries whose content changed
  auto rank = [](const PackageDiff& d) {
    const bool content = d.flags == "missing" || (d.flags.size() >= 3 && d.flags[2] == '5');
    return (inSystemBinaryDir(d.path) && !d.config && content) ? 0 : d.config ? 2 : 1;
  };
  std::stable_sort(diffs.begin(), diffs.end(), [&](const PackageDiff& a, const PackageDiff& b) { return rank(a) < rank(b); });
  constexpr size_t kMax = 500;
  if (diffs.size() > kMax) {
    out.warnings.push_back(std::to_string(diffs.size() - kMax) + " more differing file(s) not listed");
    diffs.resize(kMax);
  }
  for (const auto& d : diffs) {
    Observation o;
    o.type = "pkg.verify";
    o.key = d.path + "|" + d.flags;
    const bool missing = d.flags == "missing";
    const bool content = !missing && d.flags.size() >= 3 && d.flags[2] == '5';
    if (missing) o.tags.push_back("missing");
    if (content) o.tags.push_back("content_changed");
    if (d.config) o.tags.push_back("config_file");
    if (!d.config && inSystemBinaryDir(d.path) && content) o.tags.push_back("system_binary_modified");
    if (!d.config && inSystemBinaryDir(d.path) && missing) o.tags.push_back("system_file_missing");  // usually a broken install, rarely tampering
    if (!missing && d.flags.size() >= 2 && d.flags[1] == 'M' && !d.config) o.tags.push_back("permissions_changed");
    o.data = {{"path", util::toValidUtf8(d.path)}, {"flags", d.flags}, {"config", d.config}, {"manager", manager}};
    out.observations.push_back(std::move(o));
  }
  if (!r.value().err.empty() && r.value().err.find("ermission denied") != std::string::npos) {
    out.warnings.push_back("package verification could not read some files (insufficient privileges?)");
  }
  return out;
}

}  // namespace agent
