#include "transport/scan_presets.h"

#include <cstdlib>

#include "core/util.h"

namespace agent {

const char* const kScanFormat = "%y\\t%m\\t%u\\t%g\\t%s\\t%T@\\t%p\\0";

namespace {

// Virtual / remote / container filesystems and runtime directories nobody wants in a SUID or tmp audit.
std::vector<std::string> pruneExpr() {
  std::vector<std::string> a = {"("};
  bool first = true;
  for (const char* fs : {"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "debugfs", "tracefs", "securityfs", "bpf", "fusectl",
                         "configfs", "pstore", "mqueue", "hugetlbfs", "binfmt_misc", "autofs", "rpc_pipefs", "nfs", "nfs4", "cifs", "efivarfs"}) {
    if (!first) a.push_back("-o");
    a.push_back("-fstype");
    a.push_back(fs);
    first = false;
  }
  for (const char* path : {"/var/lib/docker", "/var/lib/containers", "/var/lib/lxc", "/var/lib/lxd", "/var/snap"}) {
    a.push_back("-o");
    a.push_back("-path");
    a.push_back(path);
  }
  a.push_back(")");
  a.push_back("-prune");
  return a;
}

std::vector<ScanPreset> build() {
  std::vector<ScanPreset> v;

  {  // setuid / setgid files
    std::vector<std::string> a = {"/"};
    const auto p = pruneExpr();
    a.insert(a.end(), p.begin(), p.end());
    for (const char* x : {"-o", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-printf"}) a.push_back(x);
    a.push_back(kScanFormat);
    v.push_back({"suid", a});
  }
  {  // things lying around in world-writable temp locations
    std::vector<std::string> a = {"/tmp", "/var/tmp", "/dev/shm", "-mindepth", "1", "-maxdepth", "6", "(", "-type", "f", "-o", "-type", "l", "-o",
                                  "-type", "s", "-o", "-type", "p", ")", "-printf"};
    a.push_back(kScanFormat);
    v.push_back({"volatile", a});
  }
  {  // world-writable files in system locations
    std::vector<std::string> a = {"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/opt", "(", "-fstype", "proc", "-o", "-fstype", "sysfs", ")", "-prune",
                                  "-o", "-perm", "-0002", "(", "-type", "f", "-o", "(", "-type", "d", "!", "-perm", "-1000", ")", ")", "-printf"};
    a.push_back(kScanFormat);
    v.push_back({"writable", a});
  }
  {  // executables dropped into non-package locations
    std::vector<std::string> a = {"/usr/local", "/opt", "/srv", "-mindepth", "1", "-maxdepth", "4", "-type", "f", "-perm", "/111", "-printf"};
    a.push_back(kScanFormat);
    v.push_back({"localexec", a});
  }
  return v;
}

}  // namespace

const std::vector<ScanPreset>& scanPresets() {
  static const std::vector<ScanPreset> p = build();
  return p;
}

const ScanPreset* findScanPreset(const std::string& name) {
  for (const auto& p : scanPresets()) if (p.name == name) return &p;
  return nullptr;
}

std::vector<ScanEntry> parseScanOutput(const std::string& raw) {
  std::vector<ScanEntry> out;
  size_t i = 0;
  while (i < raw.size()) {
    size_t z = raw.find('\0', i);
    if (z == std::string::npos) z = raw.size();
    const std::string rec = raw.substr(i, z - i);
    i = z + 1;
    // type \t mode \t user \t group \t size \t mtime \t path   (the path is the rest, it may contain tabs)
    std::vector<std::string> f;
    size_t p = 0;
    for (int k = 0; k < 6; ++k) {
      const size_t t = rec.find('\t', p);
      if (t == std::string::npos) break;
      f.push_back(rec.substr(p, t - p));
      p = t + 1;
    }
    if (f.size() != 6 || f[0].size() != 1) continue;
    const auto mode = util::parseUint(f[1], 8), size = util::parseUint(f[4]);
    if (!mode || !size) continue;
    ScanEntry e;
    e.type = f[0][0];
    e.mode = static_cast<uint32_t>(*mode);
    e.user = f[2];
    e.group = f[3];
    e.size = *size;
    e.mtime = static_cast<int64_t>(std::atof(f[5].c_str()));
    e.path = rec.substr(p);
    out.push_back(std::move(e));
  }
  return out;
}

std::string shellQuote(const std::string& s) {
  std::string o = "'";
  for (char c : s) {
    if (c == '\'') o += "'\\''";
    else o += c;
  }
  return o + "'";
}

bool validJournalCursor(const std::string& c) {
  if (c.size() > 300) return false;
  for (unsigned char ch : c) {
    const bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '=' || ch == ';' || ch == '_' ||
                    ch == '.' || ch == ':' || ch == '+' || ch == '/' || ch == '-';
    if (!ok) return false;
  }
  return true;
}

JournalResult parseJournalOutput(const std::string& raw) {
  JournalResult r;
  size_t end = raw.size();
  // the cursor trailer is the last line: "-- cursor: s=...;i=..."
  size_t start = raw.rfind("-- cursor: ");
  if (start != std::string::npos && (start == 0 || raw[start - 1] == '\n')) {
    size_t nl = raw.find('\n', start);
    r.cursor = std::string(util::trim(raw.substr(start + 11, (nl == std::string::npos ? raw.size() : nl) - start - 11)));
    end = start;
  }
  r.text = raw.substr(0, end);
  return r;
}

}  // namespace agent
