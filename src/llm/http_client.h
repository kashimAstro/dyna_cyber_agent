#pragma once
#include <chrono>
#include <string>
#include <vector>

#include "core/result.h"

namespace agent {

struct HttpResponse {
  long status = 0;
  std::string body;
};

// Minimal HTTP surface the LLM client needs. Kept abstract so tests never touch the network.
class IHttpClient {
 public:
  virtual ~IHttpClient() = default;
  virtual Result<HttpResponse> get(const std::string& url, const std::vector<std::string>& headers,
                                   std::chrono::seconds timeout) = 0;
  virtual Result<HttpResponse> postJson(const std::string& url, const std::string& body,
                                        const std::vector<std::string>& headers, std::chrono::seconds timeout) = 0;
};

class CurlHttpClient final : public IHttpClient {
 public:
  CurlHttpClient();
  ~CurlHttpClient() override;
  Result<HttpResponse> get(const std::string& url, const std::vector<std::string>& headers, std::chrono::seconds timeout) override;
  Result<HttpResponse> postJson(const std::string& url, const std::string& body, const std::vector<std::string>& headers,
                                std::chrono::seconds timeout) override;

 private:
  Result<HttpResponse> perform(const std::string& url, const std::string* body, const std::vector<std::string>& headers,
                               std::chrono::seconds timeout);
};

}  // namespace agent
