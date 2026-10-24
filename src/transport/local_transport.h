#pragma once
#include "transport/transport.h"

namespace agent {

// Reads the machine the agent runs on. Opens files O_RDONLY only.
class LocalTransport final : public ITransport {
 public:
  std::string name() const override { return "local"; }

  Result<FileContent> readFile(const std::string& path, size_t max_bytes) override;
  Result<std::string> readLink(const std::string& path) override;
  Result<std::vector<DirEntry>> listDir(const std::string& path) override;
  Result<FileInfo> stat(const std::string& path) override;
  Result<std::string> sha256File(const std::string& path, uint64_t max_bytes) override;
  Result<TailResult> tailFile(const std::string& path, uint64_t offset, uint64_t max_bytes) override;
  Result<JournalResult> journal(const std::string& scope, const std::string& after_cursor, uint64_t max_lines) override;
  Result<std::vector<ScanEntry>> scan(const std::string& preset) override;
  Result<CommandResult> run(const std::vector<std::string>& argv, const RunLimits& limits = {}) override;
};

}  // namespace agent
