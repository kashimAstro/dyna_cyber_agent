#include "collectors/packages_collector.h"

#include <algorithm>
#include <chrono>
#include <map>

#include "core/util.h"

namespace agent {

std::vector<InstalledPackage> parseDpkgStatus(const std::string& text) {
  std::vector<InstalledPackage> out;
  std::map<std::string, std::string> f;
  std::string last_key;
  auto flush = [&]() {
    if (f.count("Package") && f.count("Version") && f.count("Status")) {
      const auto st = util::splitWs(f["Status"]);  // "install ok installed"
      if (st.size() == 3 && st[2] == "installed") {
        InstalledPackage p;
        p.name = f["Package"];
        p.version = f["Version"];
        p.arch = f.count("Architecture") ? f["Architecture"] : "";
        p.manager = "dpkg";
        p.multiarch_same = f.count("Multi-Arch") && f["Multi-Arch"] == "same";
        p.source = p.name;
        p.source_version = p.version;
        if (f.count("Source")) {
          // "Source: name" or "Source: name (version)": the version of the source differs from the binary's when binNMUs happened
          const std::string src = f["Source"];
          const size_t lp = src.find(" (");
          p.source = std::string(util::trim(src.substr(0, lp)));
          if (lp != std::string::npos && src.back() == ')') p.source_version = src.substr(lp + 2, src.size() - lp - 3);
        }
        out.push_back(std::move(p));
      }
    }
    f.clear();
    last_key.clear();
  };
  for (const auto& raw : util::split(text, '\n')) {
    if (raw.empty()) {
      flush();
      continue;
    }
    if (raw[0] == ' ' || raw[0] == '\t') continue;  // continuation of a long field (Description...)
    const size_t c = raw.find(':');
    if (c == std::string::npos) continue;
    const std::string k = raw.substr(0, c);
    if (k == "Package" || k == "Status" || k == "Version" || k == "Architecture" || k == "Source" || k == "Multi-Arch") f[k] = std::string(util::trim(raw.substr(c + 1)));
  }
  flush();
  return out;
}

std::vector<InstalledPackage> parseRpmList(const std::string& text) {
  std::vector<InstalledPackage> out;
  for (const auto& raw : util::split(text, '\n')) {
    const std::string line(util::trim(raw));
    if (line.empty() || util::startsWith(line, "gpg-pubkey")) continue;
    // name-version-release.arch  (the name itself may contain dashes: split from the right)
    const size_t dot = line.rfind('.');
    if (dot == std::string::npos) continue;
    const std::string arch = line.substr(dot + 1);
    const std::string nvr = line.substr(0, dot);
    const size_t d2 = nvr.rfind('-');
    if (d2 == std::string::npos || d2 == 0) continue;
    const size_t d1 = nvr.rfind('-', d2 - 1);
    if (d1 == std::string::npos || d1 == 0) continue;
    InstalledPackage p;
    p.name = nvr.substr(0, d1);
    p.version = nvr.substr(d1 + 1);  // "version-release"
    p.arch = arch;
    p.manager = "rpm";
    p.source = p.name;
    p.source_version = p.version;
    out.push_back(std::move(p));
  }
  return out;
}

OsRelease parseOsRelease(const std::string& text) {
  OsRelease r;
  for (const auto& line : util::split(text, '\n')) {
    const size_t eq = line.find('=');
    if (eq == std::string::npos || line[0] == '#') continue;
    const std::string k = line.substr(0, eq);
    std::string v(util::trim(line.substr(eq + 1)));
    if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front()) v = v.substr(1, v.size() - 2);
    if (k == "ID") r.id = v;
    else if (k == "VERSION_ID") r.version_id = v;
    else if (k == "VERSION_CODENAME") r.codename = v;
    else if (k == "PRETTY_NAME") r.pretty_name = v;
    else if (k == "ID_LIKE") r.id_like = v;
  }
  return r;
}

std::string kernelUpstreamVersion(const std::string& release) {
  size_t i = 0;
  while (i < release.size() && (std::isdigit(static_cast<unsigned char>(release[i])) || release[i] == '.')) ++i;
  std::string v = release.substr(0, i);
  while (!v.empty() && v.back() == '.') v.pop_back();
  return v;
}

bool interestingOwnedPath(const std::string& p) {
  if (p.empty() || p[0] != '/' || p.back() == '/') return false;
  for (const char* pre : {"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/", "/opt/", "/etc/", "/lib/systemd/", "/usr/lib/systemd/", "/lib/modules/",
                          "/usr/lib/modules/", "/usr/local/"}) {
    if (util::startsWith(p, pre)) return true;
  }
  if (util::startsWith(p, "/usr/lib/") || util::startsWith(p, "/lib/")) {
    // helpers and daemons live here, but so do libraries and whole language trees
    for (const char* skip : {".so", "/python", "/perl", "/ruby", "/node_modules", "/lua", "/pkgconfig/", "/cmake/", "/gcc/", "/jvm/", "/debug/", "/dri/", "/gconv/"}) {
      if (p.find(skip) != std::string::npos) return false;
    }
    for (const char* ext : {".py", ".pyc", ".pm", ".h", ".a", ".la", ".rb", ".lua", ".js", ".png", ".svg", ".txt", ".md", ".gz", ".mo", ".json"}) {
      if (util::endsWith(p, ext)) return false;
    }
    return true;
  }
  return false;
}

std::vector<std::string> parseDpkgFileList(const std::string& list_file, size_t max) {
  std::vector<std::string> out;
  for (const auto& line : util::split(list_file, '\n')) {
    if (!interestingOwnedPath(line)) continue;
    out.push_back(line);
    if (out.size() >= max) break;
  }
  return out;
}

namespace {

using VersionMap = std::map<std::string, std::string>;  // "name:arch" -> version

VersionMap loadVersions(IStateStore* st, const std::string& key) {
  VersionMap m;
  if (!st) return m;
  const auto v = st->get(key);
  if (!v) return m;
  for (const auto& line : util::split(*v, '\n')) {
    const size_t tab = line.find('\t');
    if (tab != std::string::npos) m[line.substr(0, tab)] = line.substr(tab + 1);
  }
  return m;
}

void saveVersions(IStateStore* st, const std::string& key, const VersionMap& m) {
  if (!st) return;
  std::string s;
  for (const auto& [k, v] : m) s += k + "\t" + v + "\n";
  st->set(key, s);
}

}  // namespace

Result<CollectOutput> PackagesCollector::collect(ITransport& t) {
  constexpr uint64_t kMaxDb = 96u << 20;
  const auto r = t.bulk({ReadOp::file("/etc/os-release", 64 * 1024), ReadOp::file("/proc/sys/kernel/osrelease", 256), ReadOp::file("/var/lib/dpkg/status", kMaxDb),
                         ReadOp::file("/var/run/reboot-required", 4096), ReadOp::file("/var/run/reboot-required.pkgs", 16384)});
  CollectOutput out;

  if (r[0].ok) {
    const OsRelease os = parseOsRelease(r[0].file.data);
    Observation o;
    o.type = "os.release";
    o.key = "os";
    o.data = {{"id", os.id}, {"version_id", os.version_id}, {"codename", os.codename}, {"pretty_name", util::toValidUtf8(os.pretty_name)}, {"id_like", os.id_like}};
    out.observations.push_back(std::move(o));
  } else {
    out.warnings.push_back("/etc/os-release not readable: the operating system is unknown");
  }
  if (r[1].ok) {
    const std::string rel(util::trim(r[1].file.data));
    Observation o;
    o.type = "os.kernel";
    o.key = "kernel";
    o.data = {{"release", rel}, {"upstream", kernelUpstreamVersion(rel)}};
    out.observations.push_back(std::move(o));
  }

  std::vector<InstalledPackage> pkgs;
  if (r[2].ok) {
    if (r[2].file.truncated) out.warnings.push_back("dpkg database larger than the read limit: inventory incomplete");
    pkgs = parseDpkgStatus(r[2].file.data);
  } else {
    auto rpm = t.run({"rpm", "-qa"}, RunLimits{std::chrono::seconds(120), 32u << 20});
    if (!rpm) return err("no package database readable (dpkg status: " + r[2].error.substr(0, 60) + "; rpm: " + rpm.error().substr(0, 60) + ")");
    if (rpm.value().exit_code != 0 && rpm.value().out.empty()) return err("rpm -qa failed: " + rpm.value().err.substr(0, 120));
    pkgs = parseRpmList(rpm.value().out);
  }
  if (pkgs.empty()) return err("package database is empty or unreadable");

  // A reboot that is waiting for a kernel or library update (Debian family writes this marker).
  {
    Observation o;
    o.type = "os.reboot_required";
    o.key = "reboot";
    nlohmann::json pk = nlohmann::json::array();
    if (r[3].ok && r[4].ok) {
      for (const auto& line : util::split(r[4].file.data, '\n')) if (!util::trim(line).empty() && pk.size() < 20) pk.push_back(std::string(util::trim(line)));
    }
    o.data = {{"required", r[3].ok}, {"packages", pk}};
    if (r[3].ok) o.tags.push_back("reboot_pending");
    out.observations.push_back(std::move(o));
  }

  for (const auto& p : pkgs) {
    Observation o;
    o.type = "pkg.installed";
    o.key = p.name + ":" + p.arch;
    o.data = {{"name", p.name}, {"version", p.version}, {"arch", p.arch}, {"source", p.source}, {"source_version", p.source_version}, {"manager", p.manager}};
    out.observations.push_back(std::move(o));
  }

  trackChanges(t, pkgs, out);
  return out;
}

void PackagesCollector::trackChanges(ITransport& t, const std::vector<InstalledPackage>& pkgs, CollectOutput& out) {
  if (!opts_.state) return;  // without memory there is nothing to compare with
  const std::string vkey = "pkgs|" + opts_.target, fkey = "pkgfiles|" + opts_.target;
  const VersionMap prev = loadVersions(opts_.state, vkey);
  VersionMap files_done = loadVersions(opts_.state, fkey);
  const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  struct Work {
    const InstalledPackage* pkg = nullptr;
    std::string key, kind, old_version;
  };
  VersionMap cur;
  std::vector<Work> changed, fill;
  for (const auto& p : pkgs) {
    const std::string k = p.name + ":" + p.arch;
    cur[k] = p.version;
    const auto it = prev.find(k);
    if (!prev.empty() && it == prev.end()) changed.push_back({&p, k, "installed", ""});
    else if (!prev.empty() && it->second != p.version) changed.push_back({&p, k, "upgraded", it->second});
    else if (p.manager == "dpkg") {
      const auto fd = files_done.find(k);
      if (fd == files_done.end() || fd->second != p.version) fill.push_back({&p, k, "inventory", ""});
    }
  }
  for (const auto& [k, v] : prev) {
    if (cur.count(k)) continue;
    Observation o;
    o.type = "pkg.change";
    o.key = "pkgchg|" + k + "|removed";
    o.data = {{"package", k.substr(0, k.find(':'))}, {"arch", k.substr(k.find(':') + 1)}, {"kind", "removed"}, {"old_version", v}, {"new_version", ""}, {"ts", now}, {"files", nlohmann::json::array()}};
    out.observations.push_back(std::move(o));
    files_done.erase(k);
  }

  // File lists: the changed packages first, then as many unseen ones as this run may read.
  std::vector<Work> todo;
  for (auto& w : changed) if (w.pkg->manager == "dpkg" && todo.size() < kMaxListReadsPerRun) todo.push_back(w);
  for (auto& w : fill) if (todo.size() < kMaxListReadsPerRun) todo.push_back(w);

  std::map<std::string, size_t> idx;  // key -> position in todo
  std::vector<ReadOp> ops;
  for (size_t i = 0; i < todo.size(); ++i) {
    const InstalledPackage& p = *todo[i].pkg;
    const std::string path = "/var/lib/dpkg/info/" + p.name + (p.multiarch_same ? ":" + p.arch : std::string()) + ".list";
    ops.push_back(ReadOp::file(path, 2u << 20));
    ops.push_back(ReadOp::stat(path));
  }
  const auto res = ops.empty() ? std::vector<OpResult>() : t.bulk(ops);
  for (size_t i = 0; i < todo.size(); ++i) {
    const Work& w = todo[i];
    const OpResult& rd = res[i * 2];
    const OpResult& st = res[i * 2 + 1];
    std::vector<std::string> files;
    if (rd.ok) files = parseDpkgFileList(rd.file.data);
    int64_t ts = 0;
    if (w.kind != "inventory") ts = st.ok && st.info.mtime > 0 ? st.info.mtime : now;
    Observation o;
    o.type = "pkg.change";
    o.key = "pkgchg|" + w.key + "|" + w.kind;
    o.data = {{"package", w.pkg->name}, {"arch", w.pkg->arch}, {"kind", w.kind}, {"old_version", w.old_version}, {"new_version", w.pkg->version}, {"ts", ts}, {"files", files}};
    out.observations.push_back(std::move(o));
    files_done[w.key] = w.pkg->version;
  }
  // RPM and the changed packages whose list could not be read still get their event.
  for (const auto& w : changed) {
    if (w.pkg->manager == "dpkg" && std::any_of(todo.begin(), todo.end(), [&](const Work& x) { return x.key == w.key; })) continue;
    Observation o;
    o.type = "pkg.change";
    o.key = "pkgchg|" + w.key + "|" + w.kind;
    o.data = {{"package", w.pkg->name}, {"arch", w.pkg->arch}, {"kind", w.kind}, {"old_version", w.old_version}, {"new_version", w.pkg->version}, {"ts", now}, {"files", nlohmann::json::array()}};
    out.observations.push_back(std::move(o));
  }
  // forget the file-list bookkeeping of packages that are gone
  for (auto it = files_done.begin(); it != files_done.end();) it = cur.count(it->first) ? std::next(it) : files_done.erase(it);

  saveVersions(opts_.state, vkey, cur);
  saveVersions(opts_.state, fkey, files_done);
}

}  // namespace agent
