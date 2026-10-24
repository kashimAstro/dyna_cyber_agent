#include "transport/local_transport.h"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "core/sha256.h"
#include "transport/command_policy.h"
#include "transport/scan_presets.h"

namespace agent {
namespace {

std::string errnoMsg(const std::string& what) { return what + ": " + std::strerror(errno); }

Result<bool> requireAbsolute(const std::string& p) {
  if (p.empty() || p[0] != '/') return err("path must be absolute: " + p);
  if (p.find('\0') != std::string::npos) return err("NUL byte in path");
  return true;
}

struct Fd {
  int fd = -1;
  explicit Fd(int f) : fd(f) {}
  ~Fd() { if (fd >= 0) ::close(fd); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
};

}  // namespace

Result<FileContent> LocalTransport::readFile(const std::string& path, size_t max_bytes) {
  if (auto a = requireAbsolute(path); !a) return err(a.error());
  // O_NONBLOCK: never hang on a FIFO/special file; O_NOCTTY: never grab a tty.
  Fd f(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY));
  if (f.fd < 0) return err(errnoMsg("open " + path));
  struct stat st {};
  if (::fstat(f.fd, &st) != 0) return err(errnoMsg("fstat " + path));
  if (!S_ISREG(st.st_mode)) return err("not a regular file: " + path);

  FileContent out;
  char buf[64 * 1024];
  // /proc files report size 0, so read until EOF instead of trusting st_size.
  while (out.data.size() < max_bytes) {
    const size_t want = std::min(sizeof(buf), max_bytes - out.data.size());
    const ssize_t n = ::read(f.fd, buf, want);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN) break;
      return err(errnoMsg("read " + path));
    }
    if (n == 0) return out;
    out.data.append(buf, static_cast<size_t>(n));
  }
  char probe;
  out.truncated = ::read(f.fd, &probe, 1) > 0;
  return out;
}

Result<std::string> LocalTransport::sha256File(const std::string& path, uint64_t max_bytes) {
  if (auto a = requireAbsolute(path); !a) return err(a.error());
  Fd f(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY));
  if (f.fd < 0) return err(errnoMsg("open " + path));
  struct stat st {};
  if (::fstat(f.fd, &st) != 0) return err(errnoMsg("fstat " + path));
  if (!S_ISREG(st.st_mode)) return err("not a regular file: " + path);
  if (static_cast<uint64_t>(st.st_size) > max_bytes) return err("file too large to hash: " + path);
  Sha256 h;
  std::string buf(256 * 1024, '\0');
  uint64_t total = 0;
  while (true) {
    const ssize_t n = ::read(f.fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR) continue;
      return err(errnoMsg("read " + path));
    }
    if (n == 0) break;
    total += static_cast<uint64_t>(n);
    if (total > max_bytes) return err("file too large to hash: " + path);
    h.update(buf.data(), static_cast<size_t>(n));
  }
  return h.hexDigest();
}

Result<std::string> LocalTransport::readLink(const std::string& path) {
  if (auto a = requireAbsolute(path); !a) return err(a.error());
  std::string buf(4096, '\0');
  const ssize_t n = ::readlink(path.c_str(), buf.data(), buf.size());
  if (n < 0) return err(errnoMsg("readlink " + path));
  buf.resize(static_cast<size_t>(n));
  return buf;
}

Result<std::vector<DirEntry>> LocalTransport::listDir(const std::string& path) {
  if (auto a = requireAbsolute(path); !a) return err(a.error());
  DIR* d = ::opendir(path.c_str());
  if (!d) return err(errnoMsg("opendir " + path));
  std::vector<DirEntry> out;
  while (const dirent* e = ::readdir(d)) {
    const std::string n = e->d_name;
    if (n == "." || n == "..") continue;
    DirEntry de;
    de.name = n;
    de.is_dir = e->d_type == DT_DIR;
    de.is_symlink = e->d_type == DT_LNK;
    out.push_back(std::move(de));
  }
  ::closedir(d);
  return out;
}

Result<FileInfo> LocalTransport::stat(const std::string& path) {
  if (auto a = requireAbsolute(path); !a) return err(a.error());
  struct stat st {};
  if (::lstat(path.c_str(), &st) != 0) return err(errnoMsg("lstat " + path));
  FileInfo fi;
  fi.mode = st.st_mode;
  fi.uid = st.st_uid;
  fi.gid = st.st_gid;
  fi.size = static_cast<uint64_t>(st.st_size);
  fi.atime = st.st_atim.tv_sec;
  fi.mtime = st.st_mtim.tv_sec;
  fi.ctime = st.st_ctim.tv_sec;
  fi.is_symlink = S_ISLNK(st.st_mode);
  return fi;
}

namespace {

// Runs an already validated executable without a shell: clean environment, no stdin, output cap, timeout.
Result<CommandResult> execCapture(const std::string& exe, const std::vector<std::string>& argv, const RunLimits& limits, bool low_priority) {

  // Everything the child needs is prepared before fork().
  std::vector<char*> cargv;
  for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
  cargv.push_back(nullptr);
  char env0[] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin";
  char env1[] = "LANG=C";
  char env2[] = "LC_ALL=C";
  char* const envp[] = {env0, env1, env2, nullptr};

  int out_pipe[2], err_pipe[2];
  if (::pipe2(out_pipe, O_CLOEXEC) != 0) return err(errnoMsg("pipe"));
  if (::pipe2(err_pipe, O_CLOEXEC) != 0) {
    ::close(out_pipe[0]);
    ::close(out_pipe[1]);
    return err(errnoMsg("pipe"));
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    for (int fd : {out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]}) ::close(fd);
    return err(errnoMsg("fork"));
  }
  if (pid == 0) {
    ::setpgid(0, 0);
    const int devnull = ::open("/dev/null", O_RDONLY);
    if (devnull >= 0) ::dup2(devnull, 0);
    ::dup2(out_pipe[1], 1);
    ::dup2(err_pipe[1], 2);
    ::close_range(3, ~0U, 0);
    if (low_priority) ::setpriority(PRIO_PROCESS, 0, 19);  // scans must never compete with the machine's real work
    ::execve(exe.c_str(), cargv.data(), envp);
    ::_exit(127);
  }
  ::setpgid(pid, pid);
  ::close(out_pipe[1]);
  ::close(err_pipe[1]);

  CommandResult res;
  struct pollfd pfds[2] = {{out_pipe[0], POLLIN, 0}, {err_pipe[0], POLLIN, 0}};
  std::string* sinks[2] = {&res.out, &res.err};
  const auto deadline = std::chrono::steady_clock::now() + limits.timeout;
  int open_fds = 2;
  char buf[16 * 1024];

  while (open_fds > 0) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0) {
      res.timed_out = true;
      break;
    }
    const int pr = ::poll(pfds, 2, static_cast<int>(std::min<long long>(left.count(), 1000)));
    if (pr < 0 && errno != EINTR) break;
    for (int i = 0; i < 2; ++i) {
      if (pfds[i].fd < 0 || !(pfds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
      const ssize_t n = ::read(pfds[i].fd, buf, sizeof(buf));
      if (n > 0) {
        if (sinks[i]->size() + static_cast<size_t>(n) > limits.max_output) {
          sinks[i]->append(buf, limits.max_output - sinks[i]->size());
          res.truncated = true;
          open_fds = 0;  // output cap reached: stop and kill the child
          break;
        }
        sinks[i]->append(buf, static_cast<size_t>(n));
      } else if (n == 0 || (errno != EINTR && errno != EAGAIN)) {
        ::close(pfds[i].fd);
        pfds[i].fd = -1;
        --open_fds;
      }
    }
  }

  for (auto& p : pfds) if (p.fd >= 0) ::close(p.fd);
  if (res.timed_out || res.truncated) ::kill(-pid, SIGKILL);

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  ::kill(-pid, SIGKILL);  // reap any stray members of the process group
  if (WIFEXITED(status)) res.exit_code = WEXITSTATUS(status);
  else if (WIFSIGNALED(status)) res.exit_code = 128 + WTERMSIG(status);
  return res;
}

std::string findExecutable(const char* name) {
  for (const char* dir : {"/usr/bin", "/bin", "/usr/sbin", "/sbin"}) {
    const std::string p = std::string(dir) + "/" + name;
    if (::access(p.c_str(), X_OK) == 0) return p;
  }
  return {};
}

}  // namespace

Result<CommandResult> LocalTransport::run(const std::vector<std::string>& argv, const RunLimits& limits) {
  auto exe = CommandPolicy::validate(argv);
  if (!exe) return err(exe.error());
  return execCapture(exe.value(), argv, limits, false);
}

Result<TailResult> LocalTransport::tailFile(const std::string& path, uint64_t offset, uint64_t max_bytes) {
  if (auto a = requireAbsolute(path); !a) return err(a.error());
  Fd f(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY));
  if (f.fd < 0) return err(errnoMsg("open " + path));
  struct stat st {};
  if (::fstat(f.fd, &st) != 0) return err(errnoMsg("fstat " + path));
  if (!S_ISREG(st.st_mode)) return err("not a regular file: " + path);
  TailResult r;
  r.size = static_cast<uint64_t>(st.st_size);
  r.inode = static_cast<uint64_t>(st.st_ino);
  r.mtime = st.st_mtim.tv_sec;
  max_bytes = std::min<uint64_t>(max_bytes, 64u << 20);
  if (offset >= r.size || max_bytes == 0) return r;
  r.data.resize(static_cast<size_t>(std::min<uint64_t>(max_bytes, r.size - offset)));
  size_t got = 0;
  while (got < r.data.size()) {
    const ssize_t n = ::pread(f.fd, r.data.data() + got, r.data.size() - got, static_cast<off_t>(offset + got));
    if (n < 0) {
      if (errno == EINTR) continue;
      return err(errnoMsg("read " + path));
    }
    if (n == 0) break;
    got += static_cast<size_t>(n);
  }
  r.data.resize(got);
  return r;
}

Result<JournalResult> LocalTransport::journal(const std::string& scope, const std::string& after_cursor, uint64_t max_lines) {
  if (scope != "sys" && scope != "kernel") return err("bad journal scope");
  if (!validJournalCursor(after_cursor)) return err("bad journal cursor");
  const std::string exe = findExecutable("journalctl");
  if (exe.empty()) return err("journalctl not found");
  std::vector<std::string> a = {"journalctl", "-q", "--no-pager", "-o", "short-iso", "--show-cursor", "-n", std::to_string(std::min<uint64_t>(max_lines, 20000))};
  if (scope == "kernel") a.push_back("-k");
  if (!after_cursor.empty()) a.push_back("--after-cursor=" + after_cursor);
  RunLimits lim;
  lim.timeout = std::chrono::seconds(30);
  lim.max_output = 16u << 20;
  auto r = execCapture(exe, a, lim, true);
  if (!r) return err(r.error());
  if (r.value().exit_code != 0) return err("journalctl failed: " + r.value().out.substr(0, 200) + r.value().err.substr(0, 200));
  // journalctl says so on stdout when it may not read the journal (no group membership)
  if (r.value().out.find("insufficient permissions") != std::string::npos) return err("journal not readable (insufficient permissions)");
  return parseJournalOutput(r.value().out);
}

Result<std::vector<ScanEntry>> LocalTransport::scan(const std::string& preset) {
  const ScanPreset* p = findScanPreset(preset);
  if (!p) return err("unknown scan preset: " + preset);
  const std::string exe = findExecutable("find");
  if (exe.empty()) return err("find not found");
  std::vector<std::string> a = {"find"};
  a.insert(a.end(), p->find_args.begin(), p->find_args.end());
  RunLimits lim;
  lim.timeout = std::chrono::seconds(3600);  // a full-disk walk at idle priority can take very long
  lim.max_output = 32u << 20;
  auto r = execCapture(exe, a, lim, true);
  if (!r) return err(r.error());
  if (r.value().timed_out) return err("scan '" + preset + "' timed out");
  // find exits 1 when it could not read some directories (normal for an unprivileged user): keep what it found
  return parseScanOutput(r.value().out);
}

}  // namespace agent
