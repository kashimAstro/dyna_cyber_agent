#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace agent {

// Incremental SHA-256 (FIPS 180-4).
class Sha256 {
 public:
  Sha256();
  void update(const void* data, size_t len);
  std::string hexDigest();  // finalises; the object must not be reused afterwards

  static std::string hex(const std::string& data);

 private:
  void block(const uint8_t* p);
  std::array<uint32_t, 8> h_;
  std::array<uint8_t, 64> buf_{};
  size_t buf_len_ = 0;
  uint64_t total_ = 0;
};

}  // namespace agent
