#include "collectors/file_collector.h"

#include <algorithm>
#include <set>

#include "collectors/content_scan.h"
#include "core/util.h"

namespace agent {
namespace {

constexpr size_t kMagicCandidates = 300;

// Programs that give a shell, or read/write arbitrary files, when they are setuid (see gtfobins.github.io).
const std::set<std::string> kGtfoBins = {"bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "python", "python2", "python3", "perl", "ruby", "php", "node", "lua", "vim", "vi", "nano",
                                         "less", "more", "awk", "gawk", "mawk", "find", "env", "cp", "mv", "dd", "nmap", "tar", "zip", "tcpdump", "strace", "gdb", "docker",
                                         "systemctl", "busybox", "base64", "xxd", "tee", "cat", "head", "tail", "sed", "ed", "ftp", "telnet", "nc", "ncat", "socat", "taskset", "nice",
                                         "ionice", "stdbuf", "timeout", "expect", "make", "gcc", "git", "rsync", "ssh", "scp", "wget", "curl"};

bool systemPath(const std::string& p) {
  for (const char* d : {"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/lib/", "/lib64/", "/usr/local/bin/", "/usr/local/sbin/", "/snap/",
                        "/var/lib/snapd/"}) {
    if (util::startsWith(p, d)) return true;
  }
  return false;
}

// True when any path component is a dot-name ("/tmp/.x/run" hides in a hidden directory).
bool hiddenPath(const std::string& path) {
  for (const auto& c : util::split(path, '/')) {
    if (c.size() > 1 && c[0] == '.' && c != "..") return true;
  }
  return false;
}

std::string baseNoVersion(const std::string& path) {
  std::string b = util::baseName(path);
  while (!b.empty() && (std::isdigit(static_cast<unsigned char>(b.back())) || b.back() == '.')) b.pop_back();  // python3.10 -> python
  return b;
}

}  // namespace

Result<CollectOutput> FileCollector::collect(ITransport& t) {
  CollectOutput out;
  const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  const bool do_suid = now - last_suid_ >= suid_interval_.count();
  std::vector<const char*> presets;
  if (do_suid) presets.push_back("suid");
  for (const char* p : {"volatile", "writable", "localexec"}) presets.push_back(p);
  std::vector<ReadOp> ops;
  for (const char* p : presets) ops.push_back(ReadOp::scan(p));
  const auto res = t.bulk(ops);
  if (do_suid) last_suid_ = now;  // a failed or timed-out walk is not retried at once either

  int failed = 0;
  std::string last_error;
  std::vector<std::pair<const char*, const std::vector<ScanEntry>*>> sets;
  for (size_t i = 0; i < presets.size(); ++i) {
    if (!res[i].ok) {
      ++failed;
      last_error = res[i].error;
      out.warnings.push_back(std::string("scan '") + presets[i] + "' failed: " + res[i].error.substr(0, 100));
      continue;
    }
    sets.emplace_back(presets[i], &res[i].scan);
  }
  if (static_cast<size_t>(failed) == presets.size()) return err("all filesystem scans failed: " + last_error);
  // Between two SUID walks the last result is carried over, so the snapshot is complete and nothing looks "resolved".
  if (do_suid && res[0].ok) suid_cache_ = res[0].scan;
  else if (!suid_cache_.empty()) sets.insert(sets.begin(), {"suid", &suid_cache_});  // not walked now, or the walk failed

  // Temporary directories hold plenty of harmless data (build trees, caches): only what could run, hide or
  // escalate is kept. Everything else is merely counted.
  std::vector<std::vector<ScanEntry>> filtered;
  filtered.reserve(sets.size());
  for (auto& [preset, entries] : sets) {
    if (std::string(preset) != "volatile") {
      filtered.emplace_back(*entries);
    } else {
      std::vector<ScanEntry> keep;
      size_t skipped = 0;
      for (const auto& e : *entries) {
        const bool interesting = (e.mode & 06000) || e.type == 's' || e.type == 'p' || (e.type == 'f' && (e.mode & 0111)) || hiddenPath(e.path);
        if (interesting) keep.push_back(e);
        else ++skipped;
      }
      if (skipped) out.warnings.push_back("info: " + std::to_string(skipped) + " ordinary file(s)/link(s) in temporary directories not listed");
      filtered.push_back(std::move(keep));
    }
    constexpr size_t kMaxPerPreset = 3000;
    if (filtered.back().size() > kMaxPerPreset) {
      out.warnings.push_back("scan '" + std::string(preset) + "': " + std::to_string(filtered.back().size() - kMaxPerPreset) + " more entries not listed");
      filtered.back().resize(kMaxPerPreset);
    }
  }
  for (size_t i = 0; i < sets.size(); ++i) sets[i].second = &filtered[i];

  // Look at the first bytes of executables and hidden files in the temp dirs: is it a binary or a script?
  std::vector<const ScanEntry*> cand;
  for (const auto& [preset, entries] : sets) {
    if (std::string(preset) != "volatile") continue;
    for (const auto& e : *entries) {
      if (e.type != 'f' || cand.size() >= kMagicCandidates) continue;
      if ((e.mode & 0111) || hiddenPath(e.path)) cand.push_back(&e);
    }
  }
  std::vector<ReadOp> mops;
  for (const auto* e : cand) mops.push_back(ReadOp::file(e->path, 4));
  const auto mres = t.bulk(mops);
  std::map<std::string, std::string> magic;
  for (size_t i = 0; i < cand.size(); ++i) {
    if (!mres[i].ok) continue;
    const std::string& d = mres[i].file.data;
    if (d.size() >= 4 && d.compare(0, 4, "\x7f" "ELF") == 0) magic[cand[i]->path] = "elf";
    else if (d.size() >= 2 && d.compare(0, 2, "#!") == 0) magic[cand[i]->path] = "script";
    else if (d.size() >= 2 && d.compare(0, 2, "MZ") == 0) magic[cand[i]->path] = "pe";
    else magic[cand[i]->path] = "data";
  }

  for (const auto& [preset, entries] : sets) {
    const std::string pn = preset;
    for (const auto& e : *entries) {
      Observation o;
      o.type = "file.entry";
      o.key = pn + "|" + e.path;
      const bool exec = (e.mode & 0111) != 0;
      char modebuf[8];
      std::snprintf(modebuf, sizeof(modebuf), "%04o", e.mode & 07777);

      if (pn == "suid") {
        if (e.mode & 04000) o.tags.push_back("suid");
        if (e.mode & 02000) o.tags.push_back("sgid");
        if ((e.mode & 04000) && e.user == "root") o.tags.push_back("suid_root");
        if (!systemPath(e.path)) o.tags.push_back("outside_system_dirs");
        if (kGtfoBins.count(baseNoVersion(e.path))) o.tags.push_back("suid_gtfobin");
      } else if (pn == "volatile") {
        if (e.type == 'f' && exec) o.tags.push_back("executable");
        if (hiddenPath(e.path)) o.tags.push_back("hidden");
        if (e.mode & 06000) o.tags.push_back("setuid_or_setgid");
        if (e.type == 's') o.tags.push_back("unix_socket");
        if (e.type == 'p') o.tags.push_back("fifo");
        if (e.type == 'l') o.tags.push_back("symlink");
        const auto m = magic.find(e.path);
        if (m != magic.end()) {
          if (m->second == "elf" || m->second == "pe") o.tags.push_back("binary_executable_format");
          if (m->second == "script") o.tags.push_back("script_file");
        }
      } else if (pn == "writable") {
        o.tags.push_back(e.type == 'd' ? "world_writable_dir" : "world_writable_file");
        if (inSystemBinaryDir(e.path)) o.tags.push_back("in_binary_dir");
      }
      o.data = {{"preset", pn}, {"type", std::string(1, e.type)}, {"mode", modebuf}, {"mode_num", e.mode}, {"user", e.user}, {"group", e.group},
                {"size", e.size}, {"mtime", e.mtime}, {"path", util::toValidUtf8(e.path)}};
      const auto m = magic.find(e.path);
      if (pn == "volatile" && m != magic.end()) o.data["magic"] = m->second;
      out.observations.push_back(std::move(o));
    }
  }
  return out;
}

}  // namespace agent
