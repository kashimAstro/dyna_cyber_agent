#include "core/gzip.h"

#include <zlib.h>

namespace agent {

Result<std::string> gunzip(const std::string& in, size_t max_out) {
  z_stream z{};
  if (inflateInit2(&z, 15 + 32) != Z_OK) return err("zlib: cannot start decompression");  // 15 + 32: gzip or zlib header, detected
  z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  z.avail_in = static_cast<uInt>(in.size());
  std::string out;
  char buf[1 << 16];
  int rc;
  do {
    z.next_out = reinterpret_cast<Bytef*>(buf);
    z.avail_out = sizeof(buf);
    rc = inflate(&z, Z_NO_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END) {
      inflateEnd(&z);
      return err("not a valid gzip file");
    }
    out.append(buf, sizeof(buf) - z.avail_out);
    if (out.size() > max_out) {
      inflateEnd(&z);
      return err("decompressed data too large");
    }
  } while (rc != Z_STREAM_END);
  inflateEnd(&z);
  return out;
}

}  // namespace agent
