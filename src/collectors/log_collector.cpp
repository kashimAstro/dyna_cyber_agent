#include "collectors/log_collector.h"

#include <algorithm>
#include <chrono>

#include "core/sha256.h"
#include "core/util.h"

namespace agent {
namespace {

constexpr uint64_t kHeadBytes = 128;
constexpr int kRedetectEvery = 20;

int64_t systemNow() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

bool wildcard(const std::string& p, const std::string& s) {
  size_t pi = 0, si = 0, star = std::string::npos, mark = 0;
  while (si < s.size()) {
    if (pi < p.size() && (p[pi] == '?' || p[pi] == s[si])) {
      ++pi;
      ++si;
    } else if (pi < p.size() && p[pi] == '*') {
      star = pi++;
      mark = si;
    } else if (star != std::string::npos) {
      pi = star + 1;
      si = ++mark;
    } else {
      return false;
    }
  }
  while (pi < p.size() && p[pi] == '*') ++pi;
  return pi == p.size();
}

std::string headHash(const std::string& bytes) { return Sha256::hex(bytes).substr(0, 16); }

std::vector<std::string> splitLines(const std::string& data) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < data.size()) {
    size_t e = data.find('\n', i);
    if (e == std::string::npos) e = data.size();
    size_t end = e;
    if (end > i && data[end - 1] == '\r') --end;
    if (end > i) out.push_back(data.substr(i, end - i));
    i = e + 1;
  }
  return out;
}

}  // namespace

std::optional<LogCollector::FileState> LogCollector::loadState(const std::string& path) {
  const std::string key = "log|" + opts_.target + "|" + path;
  if (!opts_.state) {
    const auto it = mem_state_.find(key);
    return it == mem_state_.end() ? std::nullopt : std::optional<FileState>(it->second);
  }
  const auto v = opts_.state->get(key);
  if (!v) return std::nullopt;
  const auto f = util::split(*v, ';');  // inode;offset;head_len;head_hash
  if (f.size() != 4) return std::nullopt;
  const auto ino = util::parseUint(f[0]), off = util::parseUint(f[1]), hl = util::parseUint(f[2]);
  if (!ino || !off || !hl) return std::nullopt;
  return FileState{*ino, *off, *hl, f[3]};
}

void LogCollector::saveState(const std::string& path, const FileState& s) {
  const std::string key = "log|" + opts_.target + "|" + path;
  if (!opts_.state) {
    mem_state_[key] = s;
    return;
  }
  opts_.state->set(key, std::to_string(s.inode) + ";" + std::to_string(s.offset) + ";" + std::to_string(s.head_len) + ";" + s.head_hash);
}

std::vector<std::string> LogCollector::expand(ITransport& t, const std::string& pattern) {
  const size_t slash = pattern.rfind('/');
  if (slash == std::string::npos || (pattern.find('*') == std::string::npos && pattern.find('?') == std::string::npos)) return {pattern};
  const std::string dir = pattern.substr(0, slash), base = pattern.substr(slash + 1);
  std::vector<std::string> out;
  if (auto d = t.listDir(dir.empty() ? "/" : dir)) {
    for (const auto& e : d.value()) {
      if (!e.is_dir && wildcard(base, e.name) && !util::endsWith(e.name, ".gz") && !util::endsWith(e.name, ".xz") && !util::endsWith(e.name, ".1") &&
          !util::endsWith(e.name, ".bz2")) {
        out.push_back(dir + "/" + e.name);
      }
    }
  }
  std::sort(out.begin(), out.end());
  if (out.size() > 20) out.resize(20);
  return out;
}

void LogCollector::detect(ITransport& t, std::vector<std::string>& warnings) {
  struct Cand { std::string path; Kind kind; };
  std::vector<Cand> cands;
  if (!opts_.log_paths.empty()) {
    for (std::string p : opts_.log_paths) {
      std::optional<Kind> forced;
      for (const auto& [prefix, k] : std::initializer_list<std::pair<const char*, Kind>>{{"auth:", Kind::Auth}, {"web:", Kind::Web}, {"kernel:", Kind::Kernel}, {"syslog:", Kind::Syslog}}) {
        if (util::startsWith(p, prefix)) {
          forced = k;
          p = p.substr(std::string(prefix).size());
        }
      }
      for (const auto& path : expand(t, p)) {
        Kind k = Kind::Syslog;
        const std::string b = util::baseName(path);
        if (forced) k = *forced;
        else if (b.find("auth") != std::string::npos || b == "secure") k = Kind::Auth;
        else if (b.find("access") != std::string::npos) k = Kind::Web;
        else if (b.find("kern") != std::string::npos) k = Kind::Kernel;
        cands.push_back({path, k});
      }
    }
  } else {
    for (const char* p : {"/var/log/auth.log", "/var/log/secure"}) cands.push_back({p, Kind::Auth});
    for (const char* p : {"/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/apache2/other_vhosts_access.log", "/var/log/httpd/access_log"}) cands.push_back({p, Kind::Web});
    cands.push_back({"/var/log/kern.log", Kind::Kernel});
    for (const char* p : {"/var/log/syslog", "/var/log/messages"}) cands.push_back({p, Kind::Syslog});
  }

  // A cheap read of one byte tells "exists and is readable" apart from the rest.
  std::vector<ReadOp> probes;
  for (const auto& c : cands) probes.push_back(ReadOp::tail(c.path, 0, 1));
  const auto res = t.bulk(probes);
  bool auth = false, kern = false;
  std::vector<Source> found;
  for (size_t i = 0; i < cands.size(); ++i) {
    if (!res[i].ok) {
      if (!opts_.log_paths.empty() || res[i].error.find("ermission") != std::string::npos) warnings.push_back("log not readable: " + cands[i].path + " (" + res[i].error.substr(0, 80) + ")");
      continue;
    }
    Source s;
    s.path = cands[i].path;
    s.kind = cands[i].kind;
    s.parse_auth = s.kind == Kind::Auth;
    s.parse_kernel = s.kind == Kind::Kernel;
    auth |= s.kind == Kind::Auth;
    kern |= s.kind == Kind::Kernel;
    found.push_back(std::move(s));
  }
  // The combined syslog only fills the gaps left by the dedicated logs (otherwise every event would count twice).
  sources_.clear();
  for (auto& s : found) {
    if (s.kind == Kind::Syslog) {
      s.parse_auth = !auth;
      s.parse_kernel = !kern;
      if (!s.parse_auth && !s.parse_kernel && !opts_.log_templates) continue;  // already covered, unless every message shape is being learned
      auth = auth || s.parse_auth;
      kern = kern || s.parse_kernel;
    }
    sources_.push_back(std::move(s));
  }
  journal_auth_ = !auth;
  journal_kernel_ = !kern;
  use_journal_ = false;
  if ((journal_auth_ || journal_kernel_) && runs_ - journal_probe_run_ >= 50) {
    journal_probe_run_ = runs_;
    use_journal_ = t.journal("sys", "", 1).ok();
  } else if (journal_auth_ || journal_kernel_) {
    use_journal_ = false;
  }
  if (sources_.empty() && !use_journal_) warnings.push_back("no readable log source found (set log_paths, or give this user access to the logs / journal)");
}

void LogCollector::feed(const Source& s, const std::string& data, int64_t now) {
  const auto lines = splitLines(data);
  if (s.kind == Kind::Web) {
    analyzer_.feedWeb(s.path, lines, now);
    return;
  }
  if (s.parse_auth) analyzer_.feedAuth(s.path, lines, now);
  if (s.parse_kernel) analyzer_.feedKernel(s.path, lines, now);
  if (!s.parse_auth && !s.parse_kernel) analyzer_.feedGeneric(s.path, lines, now);
}

Result<CollectOutput> LogCollector::collect(ITransport& t) {
  CollectOutput out;
  const int64_t now = clock_ ? clock_() : systemNow();
  if (runs_ % kRedetectEvery == 0 || (sources_.empty() && !use_journal_)) detect(t, out.warnings);

  // ---- files. Stage 1: head fingerprint + everything after the saved offset, for all files in one batch.
  std::vector<ReadOp> ops;
  std::vector<std::optional<FileState>> states;
  for (const auto& s : sources_) {
    states.push_back(loadState(s.path));
    ops.push_back(ReadOp::tail(s.path, 0, kHeadBytes));
    ops.push_back(ReadOp::tail(s.path, states.back() ? states.back()->offset : 0, states.back() ? kChunk : 0));
  }
  const auto res = t.bulk(ops);

  // One unit of work per file: data chunks to analyse, and the state to save once they were.
  struct Chunk {
    std::string data;
    uint64_t base = 0;            // file offset of data[0]
    bool main = true;             // false: the tail of a rotated file (does not move our offset)
    bool drop_partial = false;    // data starts mid-line: skip up to the first newline
    bool filled = false;
  };
  struct Work {
    size_t src;
    FileState next;
    std::vector<Chunk> chunks;
  };
  struct Need { size_t work, chunk; std::string path; uint64_t offset; };
  std::vector<Work> works;
  std::vector<Need> needs;

  for (size_t i = 0; i < sources_.size(); ++i) {
    const Source& s = sources_[i];
    const OpResult &head = res[i * 2], &body = res[i * 2 + 1];
    if (!head.ok) {
      out.warnings.push_back("cannot read " + s.path + ": " + head.error.substr(0, 80));
      continue;
    }
    const uint64_t size = head.tail.size;
    const std::string& hb = head.tail.data;
    Work w;
    w.src = i;
    w.next.inode = head.tail.inode;
    w.next.head_len = hb.size();
    w.next.head_hash = headHash(hb);

    auto need = [&](const std::string& path, uint64_t off, bool main, bool drop) {
      w.chunks.push_back({{}, off, main, drop, false});
      needs.push_back({works.size(), w.chunks.size() - 1, path, off});
    };

    if (!states[i]) {  // first time we see this log: start at the end (or a little before, if asked)
      const uint64_t back = static_cast<uint64_t>(std::max(0, opts_.log_backfill_kb)) * 1024;
      const uint64_t from = size > back ? size - back : 0;
      w.next.offset = from;
      if (back > 0 && size > 0) need(s.path, from, true, from > 0);
    } else {
      const FileState& st = *states[i];
      const bool head_ok = hb.size() >= st.head_len && headHash(hb.substr(0, st.head_len)) == st.head_hash;
      if (st.inode != head.tail.inode || size < st.offset || !head_ok) {
        // rotated: the lines written between our last read and the rotation are in the renamed file
        need(s.path + ".1", st.offset, false, false);
        need(s.path, 0, true, false);
        w.next.offset = 0;
      } else if (!body.ok) {
        out.warnings.push_back("cannot read " + s.path + ": " + body.error.substr(0, 80));
        continue;
      } else if (size - st.offset > kChunk * 8) {
        // far behind: jump to the freshest chunk instead of replaying hours of old logs
        out.warnings.push_back("skipped " + std::to_string(size - st.offset - kChunk) + " byte(s) of " + s.path + " (log grew faster than it can be read)");
        need(s.path, size - kChunk, true, true);
      } else {
        w.next.offset = st.offset;
        w.chunks.push_back({body.tail.data, st.offset, true, false, true});
      }
    }
    works.push_back(std::move(w));
  }

  // Stage 2: the extra reads (rotation, backfill, jumps), in one more batch.
  if (!needs.empty()) {
    std::vector<ReadOp> rops;
    for (const auto& n : needs) rops.push_back(ReadOp::tail(n.path, n.offset, kChunk));
    const auto rres = t.bulk(rops);
    for (size_t k = 0; k < needs.size(); ++k) {
      Chunk& c = works[needs[k].work].chunks[needs[k].chunk];
      const auto& old = states[works[needs[k].work].src];
      if (!rres[k].ok) continue;
      // a renamed file counts only if it really is the file we were reading
      if (!c.main && (!old || rres[k].tail.inode != old->inode)) continue;
      c.data = rres[k].tail.data;
      c.filled = true;
    }
  }

  // Stage 3: analyse complete lines, then (and only then) remember how far we got.
  for (auto& w : works) {
    const Source& s = sources_[w.src];
    bool main_ok = true;
    for (auto& c : w.chunks) {
      if (!c.filled) {
        if (c.main) main_ok = false;
        continue;
      }
      std::string& d = c.data;
      size_t begin = 0;
      if (c.drop_partial) {
        const size_t nl = d.find('\n');
        begin = nl == std::string::npos ? d.size() : nl + 1;
      }
      // only complete lines are consumed; a partial last line waits for the next run
      size_t end = d.size();
      if (!d.empty() && d.back() != '\n') {
        const size_t nl = d.rfind('\n');
        end = nl == std::string::npos ? (d.size() >= kChunk ? d.size() : begin) : nl + 1;
      }
      if (end > begin) feed(s, d.substr(begin, end - begin), now);
      if (c.main) w.next.offset = c.base + end;
    }
    if (main_ok) saveState(s.path, w.next);
  }

  // ---- journal
  if (use_journal_) {
    const std::string key = "journal|" + opts_.target;
    const auto cursor = opts_.state ? opts_.state->get(key) : std::optional<std::string>();
    const std::string cur = cursor ? *cursor : std::string();
    auto j = t.journal("sys", cur, cur.empty() ? 1 : 5000);
    if (!j) {
      out.warnings.push_back("journal: " + j.error().substr(0, 100));
      use_journal_ = false;
    } else {
      if (!cur.empty()) {
        Source js;
        js.path = "journal";
        js.kind = Kind::Syslog;
        js.parse_auth = journal_auth_;
        js.parse_kernel = journal_kernel_;
        feed(js, j.value().text, now);
      }
      if (!j.value().cursor.empty() && opts_.state) opts_.state->set(key, j.value().cursor);
    }
  }

  ++runs_;
  out.observations = analyzer_.drain(now, &out.warnings);
  return out;
}

}  // namespace agent
