#include "transport/ssh_transport.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

#include "core/base64.h"
#include "core/util.h"
#include "transport/command_policy.h"
#include "transport/gate.h"
#include "transport/scan_presets.h"
#include "transport/ssh_validate.h"

namespace agent {
namespace {

constexpr size_t kFrameOps = 256;            // requests per round trip
constexpr size_t kMaxLine = 700u << 20;      // a single reply line cap (base64 of a capped file)
constexpr size_t kErrTail = 4096;

const std::atomic<bool>* g_cancel = nullptr;

void setNonBlocking(int fd) { ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK); }

std::string b64(const std::string& s) { return base64Encode(s, 0); }

}  // namespace

void SshTransport::setCancelFlag(const std::atomic<bool>* flag) { g_cancel = flag; }

std::string SshTransport::remoteCommand(const SshOptions& o) {
  if (o.gate_mode == "installed") {
    return std::string("exec ") + (o.sudo ? "sudo -n " : "") + o.gate_path;
  }
  // stream: ship the script inside the command line (base64: only [A-Za-z0-9+/=], safe in single quotes).
  // The script is an argument, so stdin stays free for the request stream.
  return "exec sh -c \"$(printf %s '" + b64(Gate::script()) + "' | base64 -d)\"";
}

std::vector<std::string> SshTransport::buildArgv(const SshOptions& o) {
  std::vector<std::string> a = {o.ssh_binary, "-T", "-F", "/dev/null"};
  auto opt = [&](const std::string& kv) {
    a.push_back("-o");
    a.push_back(kv);
  };
  opt("BatchMode=yes");                      // never prompt: a prompt would hang a daemon
  opt("StrictHostKeyChecking=yes");          // no trust on first use
  if (!o.known_hosts.empty()) opt("UserKnownHostsFile=" + o.known_hosts);
  opt("IdentitiesOnly=yes");
  opt("IdentityAgent=none");
  opt("PasswordAuthentication=no");
  opt("KbdInteractiveAuthentication=no");
  opt("PubkeyAuthentication=yes");
  opt("ForwardAgent=no");
  opt("ForwardX11=no");
  opt("ClearAllForwardings=yes");
  opt("PermitLocalCommand=no");
  opt("ControlMaster=no");
  opt("ControlPath=none");
  opt("Compression=yes");                    // the payload is base64 text: it compresses well
  opt("LogLevel=ERROR");
  opt("ServerAliveInterval=15");
  opt("ServerAliveCountMax=3");
  opt("ConnectTimeout=" + std::to_string(o.connect_timeout.count()));
  a.push_back("-i");
  a.push_back(o.key_file);
  a.push_back("-p");
  a.push_back(std::to_string(o.port));
  a.push_back("-l");
  a.push_back(o.user);
  if (!o.proxy_jump.empty()) {
    a.push_back("-J");
    a.push_back(o.proxy_jump);
  }
  a.push_back("--");
  a.push_back(o.host);
  a.push_back(remoteCommand(o));
  return a;
}

SshTransport::SshTransport(SshOptions o) : o_(std::move(o)) { ::signal(SIGPIPE, SIG_IGN); }

SshTransport::~SshTransport() { disconnect(); }

void SshTransport::disconnect() {
  for (int* fd : {&in_, &out_, &err_}) {
    if (*fd >= 0) ::close(*fd);
    *fd = -1;
  }
  if (pid_ > 0) {
    ::kill(-pid_, SIGKILL);
    int st = 0;
    while (::waitpid(pid_, &st, 0) < 0 && errno == EINTR) {}
    pid_ = -1;
  }
  rbuf_.clear();
}

std::string SshTransport::stderrTail() const {
  std::string t(util::trim(errtail_));
  for (auto& c : t) if (c == '\n' || c == '\r') c = ' ';
  return t;
}

Result<bool> SshTransport::ensureConnected() {
  if (pid_ > 0) return true;
  if (std::chrono::steady_clock::now() < retry_after_) {
    return err("ssh " + o_.host + " unreachable (" + last_connect_error_ + "); retrying later");
  }
  // Defence in depth: the values were validated by the config, never trust them blindly at exec time.
  if (!validSshHost(o_.host) || !validSshUser(o_.user) || (!o_.proxy_jump.empty() && !validSshJump(o_.proxy_jump)) ||
      (o_.gate_mode == "installed" && !validGatePath(o_.gate_path)) || (o_.gate_mode != "installed" && o_.gate_mode != "stream") ||
      (o_.sudo && o_.gate_mode != "installed") || o_.key_file.empty() || o_.ssh_binary.empty() || o_.ssh_binary[0] != '/') {
    return err("invalid ssh transport options");
  }
  auto r = connect();
  if (!r) return err(r.error());
  return true;
}

Result<std::string> SshTransport::connect() {
  if (pid_ > 0) return remote_host_;
  const auto argv_s = buildArgv(o_);
  std::vector<char*> argv;
  for (const auto& s : argv_s) argv.push_back(const_cast<char*>(s.c_str()));
  argv.push_back(nullptr);
  const char* home = ::getenv("HOME");
  const std::string home_env = std::string("HOME=") + (home ? home : "/");
  std::string path_env = "PATH=/usr/bin:/bin";  // ProxyJump makes ssh spawn `ssh` itself
  std::string lang_env = "LANG=C";
  char* const envp[] = {const_cast<char*>(home_env.c_str()), path_env.data(), lang_env.data(), nullptr};

  int to_child[2], from_child[2], err_child[2];
  if (::pipe2(to_child, O_CLOEXEC) != 0 || ::pipe2(from_child, O_CLOEXEC) != 0 || ::pipe2(err_child, O_CLOEXEC) != 0) {
    return err(std::string("pipe: ") + std::strerror(errno));
  }
  const pid_t pid = ::fork();
  if (pid < 0) return err(std::string("fork: ") + std::strerror(errno));
  if (pid == 0) {
    ::setpgid(0, 0);
    ::dup2(to_child[0], 0);
    ::dup2(from_child[1], 1);
    ::dup2(err_child[1], 2);
    ::close_range(3, ~0U, 0);
    ::execve(o_.ssh_binary.c_str(), argv.data(), envp);
    ::_exit(127);
  }
  ::setpgid(pid, pid);
  ::close(to_child[0]);
  ::close(from_child[1]);
  ::close(err_child[1]);
  pid_ = pid;
  in_ = to_child[1];
  out_ = from_child[0];
  err_ = err_child[0];
  setNonBlocking(in_);
  setNonBlocking(out_);
  setNonBlocking(err_);
  errtail_.clear();
  rbuf_.clear();

  auto fail = [&](const std::string& why) -> Result<std::string> {
    const std::string tail = stderrTail();
    disconnect();
    last_connect_error_ = why + (tail.empty() ? "" : ": " + tail);
    retry_after_ = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    return err("ssh " + o_.user + "@" + o_.host + ": " + last_connect_error_);
  };

  auto hello = pump({}, 1, std::max(o_.connect_timeout * 2, std::chrono::seconds(2)));  // TCP + key exchange + auth + gate start
  if (!hello) return fail(hello.error());
  const std::string& line = hello.value()[0];
  const std::string want = "AGENT-GATE " + std::to_string(Gate::kProtocolVersion);
  if (!util::startsWith(line, want)) return fail("unexpected greeting '" + line.substr(0, 80) + "' (is the gate installed and up to date?)");
  remote_host_ = std::string(util::trim(line.substr(want.size())));
  last_connect_error_.clear();
  return remote_host_;
}

Result<std::vector<std::string>> SshTransport::pump(const std::vector<std::string>& lines, size_t expect, std::chrono::seconds timeout) {
  std::string wbuf;
  for (const auto& l : lines) wbuf += l + "\n";
  size_t woff = 0;
  std::vector<std::string> replies;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  if (!lines.empty()) expect = lines.size();

  auto take_lines = [&]() {
    size_t nl;
    while (replies.size() < expect && (nl = rbuf_.find('\n')) != std::string::npos) {
      replies.push_back(rbuf_.substr(0, nl));
      rbuf_.erase(0, nl + 1);
    }
  };
  take_lines();

  char buf[256 * 1024];
  while (replies.size() < expect) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (g_cancel && g_cancel->load()) return err("cancelled");
    if (left.count() <= 0) return err("timeout waiting for the remote machine");
    struct pollfd p[3];
    p[0] = {out_, POLLIN, 0};
    p[1] = {err_, POLLIN, 0};
    p[2] = {woff < wbuf.size() ? in_ : -1, POLLOUT, 0};
    const int pr = ::poll(p, 3, static_cast<int>(std::min<long long>(left.count(), 1000)));
    if (pr < 0 && errno != EINTR) return err(std::string("poll: ") + std::strerror(errno));

    if (p[1].revents & (POLLIN | POLLHUP)) {
      const ssize_t n = ::read(err_, buf, sizeof(buf));
      if (n > 0) {
        errtail_.append(buf, static_cast<size_t>(n));
        if (errtail_.size() > kErrTail) errtail_.erase(0, errtail_.size() - kErrTail);
      }
    }
    if (p[2].revents & (POLLOUT | POLLERR | POLLHUP)) {
      const ssize_t n = ::write(in_, wbuf.data() + woff, std::min<size_t>(wbuf.size() - woff, 64 * 1024));
      if (n > 0) woff += static_cast<size_t>(n);
      else if (n < 0 && errno != EAGAIN && errno != EINTR) return err("connection closed while sending");
    }
    if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
      const ssize_t n = ::read(out_, buf, sizeof(buf));
      if (n > 0) {
        rbuf_.append(buf, static_cast<size_t>(n));
        if (rbuf_.size() > kMaxLine && rbuf_.find('\n') == std::string::npos) return err("reply line too long");
        take_lines();
      } else if (n == 0) {
        // The remote side hung up: let the stderr reader catch the last words first.
        const ssize_t m = ::read(err_, buf, sizeof(buf));
        if (m > 0) errtail_.append(buf, static_cast<size_t>(m));
        return err("connection closed by the remote side");
      } else if (errno != EAGAIN && errno != EINTR) {
        return err(std::string("read: ") + std::strerror(errno));
      }
    }
  }
  return replies;
}

namespace {

struct Req {
  std::string line;
  bool ok = true;
  std::string error;
};

Req makeRequest(const ReadOp& op) {
  Req r;
  auto bad = [&](const std::string& why) {
    r.ok = false;
    r.error = why;
    return r;
  };
  if (op.kind == ReadOp::Kind::Scan) {
    if (!findScanPreset(op.path)) return bad("unknown scan preset: " + op.path.substr(0, 40));
    r.line = "scan " + op.path;
    return r;
  }
  if (op.kind == ReadOp::Kind::Journal) {
    if ((op.path != "sys" && op.path != "kernel") || !validJournalCursor(op.arg)) return bad("invalid journal request");
    r.line = "journal " + op.path + " " + std::to_string(op.limit) + " " + b64(op.arg.empty() ? "-" : op.arg);
    return r;
  }
  if (op.path.empty() || op.path[0] != '/' || op.path.find('\n') != std::string::npos || op.path.find('\0') != std::string::npos) {
    return bad("invalid path: " + op.path.substr(0, 80));
  }
  const std::string p = b64(op.path);
  switch (op.kind) {
    case ReadOp::Kind::ReadFile: r.line = "read " + std::to_string(op.limit + 1) + " " + p; break;  // +1 tells "truncated" apart
    case ReadOp::Kind::ReadLink: r.line = "readlink " + p; break;
    case ReadOp::Kind::ListDir: r.line = "ls " + p; break;
    case ReadOp::Kind::Stat: r.line = "stat " + p; break;
    case ReadOp::Kind::Sha256: r.line = "sha256 " + std::to_string(op.limit) + " " + p; break;
    case ReadOp::Kind::RwxMapCount: r.line = "rwx " + p; break;
    case ReadOp::Kind::SocketInodes: r.line = "sockets " + p; break;
    case ReadOp::Kind::Tail: r.line = "tail " + std::to_string(op.offset) + " " + std::to_string(op.limit) + " " + p; break;
    case ReadOp::Kind::Journal:
    case ReadOp::Kind::Scan: break;  // handled above
  }
  return r;
}

// Turns one gate reply line into the result of `op`.
OpResult parseReply(const ReadOp& op, const std::string& line) {
  OpResult r;
  if (line.size() < 2 || (line.compare(0, 3, "OK ") != 0 && line.compare(0, 3, "ER ") != 0 && line != "OK" && line != "ER")) {
    r.error = "malformed reply from the gate";
    return r;
  }
  const bool good = line[0] == 'O';
  const auto payload = base64Decode(line.size() > 3 ? line.substr(3) : std::string());
  if (!payload) {
    r.error = "malformed reply payload";
    return r;
  }
  if (!good) {
    r.error = *payload;
    return r;
  }
  r.ok = true;
  switch (op.kind) {
    case ReadOp::Kind::ReadFile:
      r.file.data = *payload;
      if (r.file.data.size() > op.limit) {
        r.file.data.resize(op.limit);
        r.file.truncated = true;
      }
      break;
    case ReadOp::Kind::ReadLink:
    case ReadOp::Kind::Sha256:
      r.text = *payload;
      break;
    case ReadOp::Kind::ListDir: {
      size_t i = 0;
      const std::string& d = *payload;
      while (i < d.size()) {
        size_t z = d.find('\0', i);
        if (z == std::string::npos) z = d.size();
        if (z > i + 1) {
          DirEntry e;
          e.is_dir = d[i] == 'd';
          e.is_symlink = d[i] == 'l';
          e.name = d.substr(i + 1, z - i - 1);
          r.entries.push_back(std::move(e));
        }
        i = z + 1;
      }
      break;
    }
    case ReadOp::Kind::Stat: {
      const auto f = util::splitWs(*payload);  // %f %u %g %s %X %Y %Z
      if (f.size() < 7) {
        r.ok = false;
        r.error = "malformed stat reply";
        break;
      }
      const auto mode = util::parseUint(f[0], 16), uid = util::parseUint(f[1]), gid = util::parseUint(f[2]), size = util::parseUint(f[3]),
                 at = util::parseUint(f[4]), mt = util::parseUint(f[5]), ct = util::parseUint(f[6]);
      if (!mode || !uid || !gid || !size || !at || !mt || !ct) {
        r.ok = false;
        r.error = "malformed stat reply";
        break;
      }
      r.info.mode = static_cast<uint32_t>(*mode);
      r.info.uid = static_cast<uint32_t>(*uid);
      r.info.gid = static_cast<uint32_t>(*gid);
      r.info.size = *size;
      r.info.atime = static_cast<int64_t>(*at);
      r.info.mtime = static_cast<int64_t>(*mt);
      r.info.ctime = static_cast<int64_t>(*ct);
      r.info.is_symlink = (*mode & 0170000) == 0120000;
      break;
    }
    case ReadOp::Kind::RwxMapCount:
      r.count = static_cast<int64_t>(util::parseUint(std::string(util::trim(*payload))).value_or(0));
      break;
    case ReadOp::Kind::Tail: {
      const size_t nl = payload->find('\n');
      const auto meta = util::splitWs(nl == std::string::npos ? *payload : payload->substr(0, nl));  // size inode mtime
      const auto size = meta.size() >= 3 ? util::parseUint(meta[0]) : std::nullopt;
      const auto inode = meta.size() >= 3 ? util::parseUint(meta[1]) : std::nullopt;
      const auto mtime = meta.size() >= 3 ? util::parseUint(meta[2]) : std::nullopt;
      if (!size || !inode || !mtime) {
        r.ok = false;
        r.error = "malformed tail reply";
        break;
      }
      r.tail.size = *size;
      r.tail.inode = *inode;
      r.tail.mtime = static_cast<int64_t>(*mtime);
      if (nl != std::string::npos) r.tail.data = payload->substr(nl + 1);
      if (r.tail.data.size() > op.limit) r.tail.data.resize(op.limit);
      break;
    }
    case ReadOp::Kind::Journal:
      r.journal = parseJournalOutput(*payload);
      break;
    case ReadOp::Kind::Scan:
      r.scan = parseScanOutput(*payload);
      break;
    case ReadOp::Kind::SocketInodes:
      for (const auto& l : util::split(*payload, '\n')) {
        if (util::startsWith(l, "socket:[") && l.size() > 9) {
          if (const auto inode = util::parseUint(l.substr(8, l.size() - 9))) r.inodes.push_back(*inode);
        }
      }
      break;
  }
  return r;
}

}  // namespace

std::vector<OpResult> SshTransport::bulk(const std::vector<ReadOp>& ops) {
  std::vector<OpResult> out(ops.size());
  for (size_t start = 0; start < ops.size(); start += kFrameOps) {
    const size_t end = std::min(ops.size(), start + kFrameOps);
    std::vector<std::string> lines;
    std::vector<size_t> idx;  // frame position -> op index
    for (size_t i = start; i < end; ++i) {
      Req r = makeRequest(ops[i]);
      if (!r.ok) {
        out[i].error = r.error;
        continue;
      }
      lines.push_back(std::move(r.line));
      idx.push_back(i);
    }
    if (lines.empty()) continue;

    auto fail_all = [&](const std::string& why) {
      for (size_t i : idx) {
        out[i] = OpResult{};
        out[i].error = why;
      }
    };
    if (auto c = ensureConnected(); !c) {
      fail_all(c.error());
      continue;
    }
    // scans and journal reads walk disks or large files: give them a generous, fixed budget
    bool slow = false;
    for (size_t i : idx) slow |= ops[i].kind == ReadOp::Kind::Scan || ops[i].kind == ReadOp::Kind::Journal;
    auto timeout = o_.op_timeout + std::chrono::milliseconds(20 * lines.size());
    if (slow) timeout = std::max<std::chrono::milliseconds>(timeout, std::chrono::seconds(3700));
    auto replies = pump(lines, 0, std::chrono::duration_cast<std::chrono::seconds>(timeout) + std::chrono::seconds(1));
    if (!replies) {
      const std::string tail = stderrTail();
      const std::string why = "ssh " + o_.host + ": " + replies.error() + (tail.empty() ? "" : " (" + tail + ")");
      disconnect();  // the stream is in an unknown state: start clean next time
      last_connect_error_ = replies.error();
      retry_after_ = std::chrono::steady_clock::now() + std::chrono::seconds(15);
      fail_all(why);
      continue;
    }
    for (size_t k = 0; k < idx.size(); ++k) out[idx[k]] = parseReply(ops[idx[k]], replies.value()[k]);
  }
  return out;
}

Result<FileContent> SshTransport::readFile(const std::string& path, size_t max_bytes) {
  auto r = bulk({ReadOp::file(path, max_bytes)});
  if (!r[0].ok) return err(r[0].error);
  return std::move(r[0].file);
}

Result<std::string> SshTransport::readLink(const std::string& path) {
  auto r = bulk({ReadOp::link(path)});
  if (!r[0].ok) return err(r[0].error);
  return std::move(r[0].text);
}

Result<std::vector<DirEntry>> SshTransport::listDir(const std::string& path) {
  auto r = bulk({ReadOp::list(path)});
  if (!r[0].ok) return err(r[0].error);
  return std::move(r[0].entries);
}

Result<FileInfo> SshTransport::stat(const std::string& path) {
  auto r = bulk({ReadOp::stat(path)});
  if (!r[0].ok) return err(r[0].error);
  return r[0].info;
}

Result<std::string> SshTransport::sha256File(const std::string& path, uint64_t max_bytes) {
  auto r = bulk({ReadOp::sha256(path, max_bytes)});
  if (!r[0].ok) return err(r[0].error);
  return std::move(r[0].text);
}

Result<TailResult> SshTransport::tailFile(const std::string& path, uint64_t offset, uint64_t max_bytes) {
  auto r = bulk({ReadOp::tail(path, offset, max_bytes)});
  if (!r[0].ok) return err(r[0].error);
  return std::move(r[0].tail);
}

Result<JournalResult> SshTransport::journal(const std::string& scope, const std::string& after_cursor, uint64_t max_lines) {
  auto r = bulk({ReadOp::journal(scope, after_cursor, max_lines)});
  if (!r[0].ok) return err(r[0].error);
  return std::move(r[0].journal);
}

Result<std::vector<ScanEntry>> SshTransport::scan(const std::string& preset) {
  auto r = bulk({ReadOp::scan(preset)});
  if (!r[0].ok) return err(r[0].error);
  return std::move(r[0].scan);
}

Result<CommandResult> SshTransport::run(const std::vector<std::string>& argv, const RunLimits& limits) {
  auto exe = CommandPolicy::validate(argv);  // same rules as locally...
  if (!exe) return err(exe.error());
  std::string joined;
  for (const auto& a : argv) {
    if (a.empty()) return err("empty argument");
    joined += (joined.empty() ? "" : " ") + a;
  }
  const auto& allowed = Gate::commands();  // ...plus the gate's own, stricter list
  if (std::find(allowed.begin(), allowed.end(), joined) == allowed.end()) return err("command not available over ssh: " + joined);
  if (auto c = ensureConnected(); !c) return err(c.error());

  std::string line = "run";
  for (const auto& a : argv) line += " " + b64(a);
  auto replies = pump({line}, 0, limits.timeout + std::chrono::seconds(2));
  if (!replies) {
    const std::string why = replies.error();
    disconnect();
    last_connect_error_ = why;
    retry_after_ = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    return err("ssh " + o_.host + ": " + why);
  }
  const std::string& rep = replies.value()[0];
  const auto payload = base64Decode(rep.size() > 3 ? rep.substr(3) : std::string());
  if (!payload || rep.compare(0, 3, "OK ") != 0) {
    return err(payload && rep.compare(0, 3, "ER ") == 0 ? *payload : "malformed reply from the gate");
  }
  const size_t nl = payload->find('\n');
  CommandResult r;
  r.exit_code = nl == std::string::npos ? -1 : static_cast<int>(util::parseUint(payload->substr(0, nl)).value_or(255));
  r.out = nl == std::string::npos ? std::string() : payload->substr(nl + 1);
  if (r.out.size() > limits.max_output) {
    r.out.resize(limits.max_output);
    r.truncated = true;
  }
  return r;
}

Result<std::string> SshTransport::capabilities() {
  if (auto c = ensureConnected(); !c) return err(c.error());
  auto replies = pump({"caps"}, 0, o_.op_timeout);
  if (!replies) {
    disconnect();
    return err(replies.error());
  }
  const std::string& rep = replies.value()[0];
  const auto payload = base64Decode(rep.size() > 3 ? rep.substr(3) : std::string());
  if (!payload || rep.compare(0, 3, "OK ") != 0) return err("malformed reply from the gate");
  return std::string(util::trim(*payload));
}

}  // namespace agent
