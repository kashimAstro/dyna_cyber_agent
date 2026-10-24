#pragma once
#include <string>
#include <vector>

#include "core/base64.h"
#include "core/result.h"
#include "core/severity.h"

namespace agent {

struct MailMessage {
  std::string from;  // "a@b.c" or "Name <a@b.c>"
  std::vector<std::string> to;
  std::string subject;
  std::string text;
  std::string html;
  Severity importance = Severity::Info;
  int64_t date = 0;                      // unix seconds (UTC)
  std::string message_id_domain = "localhost";
};

// RFC 2047 encoded-word for non-ASCII subjects; ASCII passes through.
std::string encodeHeaderValue(const std::string& v);
// RFC 5322 date, e.g. "Thu, 22 Oct 2026 20:15:00 +0000".
std::string rfc5322Date(int64_t unix_seconds);

// Builds a multipart/alternative message (text first, html second; clients show the last one they support).
// Fails if any header value contains CR/LF (header injection) or an address is malformed.
Result<std::string> buildMime(const MailMessage& m);

}  // namespace agent
