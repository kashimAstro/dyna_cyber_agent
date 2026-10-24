#pragma once
#include <functional>

#include "llm/http_client.h"

namespace agent {

// HTTP stand-in for tests: routes are matched by URL substring, in order. No socket is ever opened.
class ScriptedHttp final : public IHttpClient {
 public:
  using Handler = std::function<Result<HttpResponse>(const std::string& url)>;
  std::vector<std::pair<std::string, Handler>> routes;
  std::vector<std::string> requested;
  std::vector<std::vector<std::string>> request_headers;

  void on(const std::string& url_part, Handler h) { routes.emplace_back(url_part, std::move(h)); }
  void ok(const std::string& url_part, const std::string& body) {
    on(url_part, [body](const std::string&) -> Result<HttpResponse> { return HttpResponse{200, body}; });
  }
  void status(const std::string& url_part, long code, const std::string& body = "") {
    on(url_part, [code, body](const std::string&) -> Result<HttpResponse> { return HttpResponse{code, body}; });
  }

  Result<HttpResponse> get(const std::string& url, const std::vector<std::string>& headers, std::chrono::seconds) override {
    requested.push_back(url);
    request_headers.push_back(headers);
    return dispatch(url);
  }
  Result<HttpResponse> postJson(const std::string& url, const std::string& body, const std::vector<std::string>& headers, std::chrono::seconds) override {
    requested.push_back(url + " <- " + body);
    request_headers.push_back(headers);
    return dispatch(url);
  }

  size_t count(const std::string& part) const {
    size_t n = 0;
    for (const auto& r : requested) n += r.find(part) != std::string::npos;
    return n;
  }

 private:
  Result<HttpResponse> dispatch(const std::string& url) {
    for (auto& [part, h] : routes) if (url.find(part) != std::string::npos) return h(url);
    return err("no route for " + url);
  }
};

}  // namespace agent
