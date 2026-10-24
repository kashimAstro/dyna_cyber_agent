#pragma once
#include <atomic>
#include <chrono>
#include <string>
#include <vector>

#include <sys/types.h>

#include "transport/transport.h"

namespace agent {

struct SshOptions {
  std::string host;
  int port = 22;
  std::string user;
  std::string key_file;
  std::string known_hosts;  // empty = the user's ~/.ssh/known_hosts
  std::string proxy_jump;   // optional bastion: user@host[:port]
  std::string ssh_binary = "/usr/bin/ssh";
  std::string gate_mode = "stream";  // stream: script sent on the fly, nothing installed | installed: run gate_path
  std::string gate_path;             // installed mode, e.g. /usr/local/bin/dyna_cyber_agent-gate
  bool sudo = false;                 // installed mode only: run the gate through `sudo -n`
  std::chrono::seconds connect_timeout{10};
  std::chrono::seconds op_timeout{30};
};

// Reads a remote machine through the system OpenSSH client and the read-only "gate" (see gate.h).
// One persistent ssh session; requests are batched so a full /proc scan costs a few round trips.
// Host keys are always verified (StrictHostKeyChecking=yes, no trust-on-first-use): the admin adds the
// key to known_hosts beforehand. The transport reconnects by itself after a failure, but not more often
// than every 15 seconds.
class SshTransport final : public ITransport {
 public:
  explicit SshTransport(SshOptions o);
  ~SshTransport() override;
  SshTransport(const SshTransport&) = delete;
  SshTransport& operator=(const SshTransport&) = delete;

  std::string name() const override { return "ssh:" + o_.user + "@" + o_.host; }

  Result<FileContent> readFile(const std::string& path, size_t max_bytes) override;
  Result<std::string> readLink(const std::string& path) override;
  Result<std::vector<DirEntry>> listDir(const std::string& path) override;
  Result<FileInfo> stat(const std::string& path) override;
  Result<std::string> sha256File(const std::string& path, uint64_t max_bytes) override;
  Result<TailResult> tailFile(const std::string& path, uint64_t offset, uint64_t max_bytes) override;
  Result<JournalResult> journal(const std::string& scope, const std::string& after_cursor, uint64_t max_lines) override;
  Result<std::vector<ScanEntry>> scan(const std::string& preset) override;
  std::vector<OpResult> bulk(const std::vector<ReadOp>& ops) override;
  Result<CommandResult> run(const std::vector<std::string>& argv, const RunLimits& limits = {}) override;

  // Connects now (otherwise the first request does it). Returns the gate's host name.
  Result<std::string> connect();
  // What the remote machine offers (GNU tools, uid): used by `--ssh-test`.
  Result<std::string> capabilities();

  // When the flag turns true, pending ssh operations stop at once (used for a prompt shutdown).
  static void setCancelFlag(const std::atomic<bool>* flag);

  // Exposed for tests.
  static std::vector<std::string> buildArgv(const SshOptions& o);
  static std::string remoteCommand(const SshOptions& o);

 private:
  Result<bool> ensureConnected();
  void disconnect();
  // Sends `lines` and waits for the same number of reply lines (or `expect_lines` when nothing is sent).
  Result<std::vector<std::string>> pump(const std::vector<std::string>& lines, size_t expect, std::chrono::seconds timeout);
  std::string stderrTail() const;

  SshOptions o_;
  pid_t pid_ = -1;
  int in_ = -1, out_ = -1, err_ = -1;
  std::string rbuf_, errtail_, remote_host_;
  std::chrono::steady_clock::time_point retry_after_{};
  std::string last_connect_error_;
};

}  // namespace agent
