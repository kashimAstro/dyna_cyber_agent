#include "web/http_server.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>

#include <spdlog/spdlog.h>

namespace agent {
namespace {

constexpr size_t kMaxHeader = 16 * 1024;
constexpr size_t kMaxBody = 256 * 1024;
constexpr int kMaxConnections = 32;

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

const char* reason(int status) {
  switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    case 429: return "Too Many Requests";
    case 503: return "Service Unavailable";
    default: return "Error";
  }
}

bool sendAll(int fd, const std::string& data) {
  size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

// Reads until `need` returns true or the limits/deadline are hit.
bool readSome(int fd, std::string& buf, std::chrono::steady_clock::time_point deadline) {
  const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
  if (left <= 0) return false;
  pollfd p{fd, POLLIN, 0};
  if (::poll(&p, 1, static_cast<int>(left)) <= 0) return false;
  char tmp[8192];
  const ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
  if (n <= 0) return false;
  buf.append(tmp, static_cast<size_t>(n));
  return true;
}

void reply(int fd, const HttpReply& r) {
  std::string head = "HTTP/1.1 " + std::to_string(r.status) + " " + reason(r.status) + "\r\n" + "Content-Type: " + r.content_type + "\r\n" +
                     "Content-Length: " + std::to_string(r.body.size()) + "\r\n" + "Connection: close\r\n" + "Cache-Control: no-store\r\n" +
                     "X-Content-Type-Options: nosniff\r\n" + "X-Frame-Options: DENY\r\n" + "Referrer-Policy: no-referrer\r\n" +
                     "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
                     "connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\r\n";
  sendAll(fd, head + r.body);
}

}  // namespace

std::string httpUrlDecode(const std::string& s) {
  std::string out;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '+') {
      out += ' ';
    } else if (s[i] == '%' && i + 2 < s.size() + 0 && std::isxdigit(static_cast<unsigned char>(s[i + 1])) && std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
      out += static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16));
      i += 2;
    } else {
      out += s[i];
    }
  }
  return out;
}

Result<bool> HttpServer::start(const std::string& host, int port, Handler handler) {
  handler_ = std::move(handler);
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* res = nullptr;
  const int gai = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
  if (gai != 0) return err("web: cannot resolve '" + host + "': " + gai_strerror(gai));
  std::string last = "no address";
  for (addrinfo* a = res; a; a = a->ai_next) {
    const int fd = ::socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
    if (fd < 0) { last = std::strerror(errno); continue; }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (::bind(fd, a->ai_addr, a->ai_addrlen) != 0 || ::listen(fd, 16) != 0) {
      last = std::strerror(errno);
      ::close(fd);
      continue;
    }
    listen_fd_ = fd;
    break;
  }
  ::freeaddrinfo(res);
  if (listen_fd_ < 0) return err("web: cannot listen on " + host + ":" + std::to_string(port) + ": " + last);
  port_ = port;
  if (port == 0) {
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&ss), &len) == 0) {
      port_ = ss.ss_family == AF_INET6 ? ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port) : ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
    }
  }
  stopping_ = false;
  thread_ = std::thread([this] { acceptLoop(); });
  return true;
}

void HttpServer::stop() {
  if (listen_fd_ < 0) return;
  stopping_ = true;
  ::shutdown(listen_fd_, SHUT_RDWR);
  if (thread_.joinable()) thread_.join();
  ::close(listen_fd_);
  listen_fd_ = -1;
  for (int i = 0; i < 100 && active_ > 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

void HttpServer::acceptLoop() {
  while (!stopping_) {
    pollfd p{listen_fd_, POLLIN, 0};
    if (::poll(&p, 1, 500) <= 0) continue;
    const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd < 0) continue;
    if (active_ >= kMaxConnections) {
      reply(fd, {429, "text/plain", "too many connections"});
      ::close(fd);
      continue;
    }
    ++active_;
    std::thread([this, fd] {
      serve(fd);
      ::close(fd);
      --active_;
    }).detach();
  }
}

void HttpServer::serve(int fd) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
  std::string buf;
  size_t end;
  while ((end = buf.find("\r\n\r\n")) == std::string::npos) {
    if (buf.size() > kMaxHeader || !readSome(fd, buf, deadline)) return;
  }
  HttpRequest req;
  const std::string head = buf.substr(0, end);
  std::string body = buf.substr(end + 4);

  const size_t eol = head.find("\r\n");
  const std::string line = head.substr(0, eol);
  const size_t sp1 = line.find(' '), sp2 = line.rfind(' ');
  if (sp1 == std::string::npos || sp2 <= sp1) { reply(fd, {400, "text/plain", "bad request"}); return; }
  req.method = line.substr(0, sp1);
  std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
  const size_t q = target.find('?');
  if (q != std::string::npos) {
    const std::string qs = target.substr(q + 1);
    target.resize(q);
    size_t i = 0;
    while (i <= qs.size()) {
      size_t j = qs.find('&', i);
      if (j == std::string::npos) j = qs.size();
      const std::string kv = qs.substr(i, j - i);
      if (!kv.empty()) {
        const size_t eq = kv.find('=');
        req.query[httpUrlDecode(kv.substr(0, eq))] = eq == std::string::npos ? "" : httpUrlDecode(kv.substr(eq + 1));
      }
      i = j + 1;
    }
  }
  req.path = httpUrlDecode(target);
  if (eol != std::string::npos) {
    size_t pos = eol + 2;
    while (pos < head.size()) {
      size_t nl = head.find("\r\n", pos);
      if (nl == std::string::npos) nl = head.size();
      const std::string h = head.substr(pos, nl - pos);
      const size_t c = h.find(':');
      if (c != std::string::npos) {
        std::string v = h.substr(c + 1);
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
        req.headers[lower(h.substr(0, c))] = v;
      }
      pos = nl + 2;
    }
  }
  size_t want = 0;
  if (const auto it = req.headers.find("content-length"); it != req.headers.end()) {
    try { want = std::stoul(it->second); } catch (...) { reply(fd, {400, "text/plain", "bad content-length"}); return; }
    if (want > kMaxBody) { reply(fd, {413, "text/plain", "body too large"}); return; }
  }
  while (body.size() < want) {
    if (!readSome(fd, body, deadline)) return;
  }
  body.resize(want);
  req.body = std::move(body);

  HttpReply r;
  try {
    r = handler_(req);
  } catch (const std::exception& e) {
    spdlog::error("web: handler failed: {}", e.what());
    r = {500, "application/json", "{\"error\":\"internal error\"}"};
  }
  reply(fd, r);
}

}  // namespace agent
