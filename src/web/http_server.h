#pragma once
#include <atomic>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "core/result.h"

namespace agent {

struct HttpRequest {
  std::string method, path;
  std::map<std::string, std::string> query;    // decoded
  std::map<std::string, std::string> headers;  // names lower-cased
  std::string body;
};

struct HttpReply {
  int status = 200;
  std::string content_type = "application/json; charset=utf-8";
  std::string body;
};

// Tiny HTTP/1.1 server for the local console: one request per connection, bounded sizes and time, no TLS.
class HttpServer {
 public:
  using Handler = std::function<HttpReply(const HttpRequest&)>;
  ~HttpServer() { stop(); }

  Result<bool> start(const std::string& host, int port, Handler handler);
  void stop();
  int port() const { return port_; }

 private:
  void acceptLoop();
  void serve(int fd);

  Handler handler_;
  int listen_fd_ = -1;
  int port_ = 0;
  std::atomic<bool> stopping_{false};
  std::atomic<int> active_{0};
  std::thread thread_;
};

std::string httpUrlDecode(const std::string& s);

}  // namespace agent
