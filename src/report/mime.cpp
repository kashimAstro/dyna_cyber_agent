#include "report/mime.h"

#include <ctime>
#include <random>

#include "core/config.h"

namespace agent {
namespace {

bool hasCtl(const std::string& s) {
  for (unsigned char c : s) if (c == '\r' || c == '\n' || c == 0) return true;
  return false;
}

std::string randomHex(size_t bytes) {
  static thread_local std::mt19937_64 rng{std::random_device{}()};
  static const char* d = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < bytes; ++i) {
    const auto b = static_cast<unsigned>(rng() & 0xFF);
    out += d[b >> 4];
    out += d[b & 15];
  }
  return out;
}

// Mail transport expects CRLF line ends.
std::string toCrlf(const std::string& s) {
  std::string out;
  out.reserve(s.size() + s.size() / 20);
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\r' && i + 1 < s.size() && s[i + 1] == '\n') continue;
    if (s[i] == '\n') out += "\r\n";
    else out += s[i];
  }
  return out;
}

}  // namespace

std::string encodeHeaderValue(const std::string& v) {
  bool ascii = true;
  for (unsigned char c : v) ascii = ascii && c < 0x80;
  if (ascii) return v;
  // Encoded-words are limited to 75 chars: chunk by whole UTF-8 characters (max 36 bytes -> 48 base64 chars).
  std::string out;
  std::string chunk;
  auto flush = [&]() {
    if (chunk.empty()) return;
    if (!out.empty()) out += "\r\n ";
    out += "=?UTF-8?B?" + base64Encode(chunk, 0) + "?=";
    chunk.clear();
  };
  for (size_t i = 0; i < v.size();) {
    const auto c = static_cast<unsigned char>(v[i]);
    const size_t len = c < 0x80 ? 1 : c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : 2;
    if (chunk.size() + len > 36) flush();
    chunk.append(v, i, len);
    i += len;
  }
  flush();
  return out;
}

std::string rfc5322Date(int64_t unix_seconds) {
  static const char* days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  const std::time_t t = static_cast<std::time_t>(unix_seconds);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%s, %02d %s %04d %02d:%02d:%02d +0000", days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon],
                tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
  return buf;
}

Result<std::string> buildMime(const MailMessage& m) {
  if (m.to.empty()) return err("mail has no recipient");
  if (hasCtl(m.from) || hasCtl(m.subject) || hasCtl(m.message_id_domain)) return err("control characters in mail header");
  if (!validEmailAddress(addressOf(m.from))) return err("invalid From address");
  std::string to;
  for (const auto& r : m.to) {
    if (!validEmailAddress(r)) return err("invalid recipient '" + r + "'");
    to += (to.empty() ? "" : ", ") + r;
  }
  const std::string outer = "=_agent_" + randomHex(12);
  std::string h;
  h += "From: " + m.from + "\r\n";
  h += "To: " + to + "\r\n";
  h += "Subject: " + encodeHeaderValue(m.subject) + "\r\n";
  h += "Date: " + rfc5322Date(m.date) + "\r\n";
  h += "Message-ID: <" + randomHex(10) + "." + std::to_string(m.date) + "@" + m.message_id_domain + ">\r\n";
  h += "MIME-Version: 1.0\r\n";
  h += "Auto-Submitted: auto-generated\r\n";          // mail loops / vacation responders must ignore us
  h += "X-Auto-Response-Suppress: All\r\n";
  h += "X-Mailer: dyna_cyber_agent\r\n";
  if (m.importance >= Severity::High) h += "X-Priority: 1\r\nImportance: High\r\n";
  h += "Content-Type: multipart/alternative; boundary=\"" + outer + "\"\r\n\r\n";
  h += "This is a multi-part message in MIME format.\r\n";

  auto part = [&](const std::string& type, const std::string& body) {
    return "--" + outer + "\r\nContent-Type: " + type + "; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
           base64Encode(toCrlf(body)) + "\r\n";
  };
  std::string body = part("text/plain", m.text);
  if (!m.html.empty()) body += part("text/html", m.html);
  body += "--" + outer + "--\r\n";
  return h + body;
}

}  // namespace agent
