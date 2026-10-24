#include "llm/http_client.h"

#include <curl/curl.h>

namespace agent {
namespace {

constexpr size_t kMaxResponse = 8u << 20;

size_t onWrite(char* ptr, size_t size, size_t nmemb, void* userdata) {
  auto* out = static_cast<std::string*>(userdata);
  const size_t n = size * nmemb;
  if (out->size() + n > kMaxResponse) return 0;  // abort the transfer: response too large
  out->append(ptr, n);
  return n;
}

}  // namespace

CurlHttpClient::CurlHttpClient() { curl_global_init(CURL_GLOBAL_DEFAULT); }
CurlHttpClient::~CurlHttpClient() { curl_global_cleanup(); }

Result<HttpResponse> CurlHttpClient::perform(const std::string& url, const std::string* body,
                                             const std::vector<std::string>& headers, std::chrono::seconds timeout) {
  CURL* c = curl_easy_init();
  if (!c) return err("curl_easy_init failed");
  HttpResponse resp;
  curl_slist* hl = nullptr;
  for (const auto& h : headers) hl = curl_slist_append(hl, h.c_str());

  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, hl);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, onWrite);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp.body);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, static_cast<long>(timeout.count()));
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);  // never follow redirects: the URL is configuration
#if LIBCURL_VERSION_NUM >= 0x075500  // 7.85.0
  curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
#else
  curl_easy_setopt(c, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
  if (body) {
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body->c_str());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body->size()));
  }

  const CURLcode rc = curl_easy_perform(c);
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp.status);
  curl_slist_free_all(hl);
  curl_easy_cleanup(c);
  if (rc != CURLE_OK) return err(std::string("http: ") + curl_easy_strerror(rc));
  return resp;
}

Result<HttpResponse> CurlHttpClient::get(const std::string& url, const std::vector<std::string>& headers, std::chrono::seconds timeout) {
  return perform(url, nullptr, headers, timeout);
}

Result<HttpResponse> CurlHttpClient::postJson(const std::string& url, const std::string& body,
                                              const std::vector<std::string>& headers, std::chrono::seconds timeout) {
  return perform(url, &body, headers, timeout);
}

}  // namespace agent
