#pragma once
#include <optional>

#include "collectors/collector.h"

namespace agent {

struct PackageDiff {
  std::string flags;  // 9 characters, e.g. "??5??????" (dpkg) or "S.5....T." (rpm), or "missing"
  bool config = false;
  std::string path;
};

// Parses `dpkg -V` / `rpm -Va` output.
std::vector<PackageDiff> parsePackageVerify(const std::string& text);

// Compares installed files with what their package shipped (`dpkg -V` or `rpm -Va`). Slow and disk-heavy: it
// runs rarely, and what it finds is rarely benign for binaries (config files are expected to differ).
class IntegrityCollector final : public ICollector {
 public:
  std::string name() const override { return "integrity"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::hours(6); }
  Result<CollectOutput> collect(ITransport& t) override;
};

}  // namespace agent
