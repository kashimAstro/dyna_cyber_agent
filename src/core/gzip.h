#pragma once
#include <string>

#include "core/result.h"

namespace agent {

// Decompresses a gzip (or zlib) buffer. Fails when the output would exceed `max_out` bytes: a downloaded file is
// untrusted and a tiny archive can expand a thousandfold.
Result<std::string> gunzip(const std::string& in, size_t max_out = 256u << 20);

}  // namespace agent
