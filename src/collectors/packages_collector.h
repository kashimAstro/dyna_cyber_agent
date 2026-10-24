#pragma once
#include <optional>

#include "collectors/collector.h"

namespace agent {

struct InstalledPackage {
  std::string name, version, arch;
  std::string source, source_version;  // upstream source package (Debian family: what vulnerability databases key on)
  std::string manager;                 // dpkg | rpm
  bool multiarch_same = false;         // dpkg "Multi-Arch: same": its file list is named <name>:<arch>.list
};

struct OsRelease {
  std::string id, version_id, codename, pretty_name, id_like;
};

// Pure parsers (exposed for tests).
std::vector<InstalledPackage> parseDpkgStatus(const std::string& status_file);
std::vector<InstalledPackage> parseRpmList(const std::string& rpm_qa_output);  // "name-version-release.arch" lines
OsRelease parseOsRelease(const std::string& text);
std::string kernelUpstreamVersion(const std::string& release);  // "5.15.0-91-generic" -> "5.15.0"

// Which files of a package matter for explaining things that appear after an upgrade: programs, services, helpers,
// configuration and kernel modules. Documentation, locales, libraries and language packages are left out
// (they would multiply the table by twenty without ever being cited).
bool interestingOwnedPath(const std::string& path);

// File paths of a dpkg `<package>.list`, reduced to the interesting ones (at most `max` of them).
std::vector<std::string> parseDpkgFileList(const std::string& list_file, size_t max = 600);

// Software inventory of the target: OS release, kernel and every installed package. It is what the
// vulnerability matcher works on. Read-only: the dpkg database is read as a file, rpm through `rpm -qa`.
//
// It also notices what changed between two runs (installed, upgraded, removed) and which files each package owns, and reports
// that as `pkg.change` observations. The agent stores those apart from the snapshot: they are what lets a later
// "new program appeared" finding be recognised as the effect of an upgrade (see USAGE.md, "Explained by an update").
class PackagesCollector final : public ICollector {
 public:
  void configure(const CollectorOptions& o) override { opts_ = o; }
  std::string name() const override { return "packages"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::hours(6); }
  Result<CollectOutput> collect(ITransport& t) override;

  static constexpr size_t kMaxListReadsPerRun = 600;  // a first run spreads the file lists over several collections

 private:
  // Compares with the previous run (kept in the collector state) and adds the `pkg.change` observations.
  void trackChanges(ITransport& t, const std::vector<InstalledPackage>& pkgs, CollectOutput& out);

  CollectorOptions opts_;
};

}  // namespace agent
