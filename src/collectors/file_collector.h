#pragma once
#include "collectors/collector.h"

namespace agent {

// Filesystem audit through the transport's fixed scans (metadata only, lowest CPU/IO priority):
//   suid        setuid/setgid files, with a note when they sit outside system directories or are GTFOBins
//   volatile    what is lying around in /tmp, /var/tmp, /dev/shm (with a look at the first bytes: ELF? script?)
//   writable    world-writable files and directories in system locations
//   localexec   executables dropped into /usr/local, /opt, /srv
class FileCollector final : public ICollector {
 public:
  std::string name() const override { return "files"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::minutes(30); }
  Result<CollectOutput> collect(ITransport& t) override;

  // The SUID walk visits the whole disk (minutes, even hours on big machines): it runs at most this often,
  // the quick scans run every time. Tests set it to 0.
  void setSuidInterval(std::chrono::seconds s) { suid_interval_ = s; }

 private:
  std::chrono::seconds suid_interval_ = std::chrono::hours(6);
  int64_t last_suid_ = 0;
  std::vector<ScanEntry> suid_cache_;  // re-emitted between walks so snapshots stay complete (findings must not flap)
};

}  // namespace agent
