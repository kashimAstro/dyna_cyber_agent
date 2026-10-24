#pragma once
#include <map>
#include <optional>

#include "collectors/collector.h"

namespace agent {

struct InetSocket {
  std::string local_addr, remote_addr;
  unsigned local_port = 0, remote_port = 0;
  std::string state;
  uint64_t uid = 0;
  uint64_t inode = 0;
};

struct UnixSocket {
  std::string path;  // leading '@' = abstract namespace
  std::string type;
  bool listening = false;
  uint64_t inode = 0;
};

struct PacketSocket {
  std::string type;
  std::string proto;
  uint64_t uid = 0;
  uint64_t inode = 0;
};

// Pure parsers (exposed for tests). `v6` selects the address format.
std::optional<std::string> decodeAddr(const std::string& hex, bool v6);
std::vector<InetSocket> parseInetTable(const std::string& text, bool v6, bool tcp);
std::vector<UnixSocket> parseUnixTable(const std::string& text, size_t* unnamed = nullptr);
std::vector<PacketSocket> parsePacketTable(const std::string& text);

class NetworkCollector final : public ICollector {
 public:
  std::string name() const override { return "network"; }
  std::chrono::seconds defaultInterval() const override { return std::chrono::seconds(15); }
  Result<CollectOutput> collect(ITransport& t) override;
};

}  // namespace agent
