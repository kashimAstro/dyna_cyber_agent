#include "report/mailer.h"

#include <curl/curl.h>

#include <cstring>

namespace agent {
namespace {

struct Upload {
  const std::string* data;
  size_t pos = 0;
};

size_t readCb(char* dst, size_t size, size_t nmemb, void* userp) {
  auto* u = static_cast<Upload*>(userp);
  const size_t room = size * nmemb;
  const size_t n = std::min(room, u->data->size() - u->pos);
  std::memcpy(dst, u->data->data() + u->pos, n);
  u->pos += n;
  return n;
}

}  // namespace

Result<bool> SmtpMailer::send(const MailMessage& m) {
  auto mime = buildMime(m);
  if (!mime) return err(mime.error());

  CURL* c = curl_easy_init();
  if (!c) return err("curl_easy_init failed");
  char errbuf[CURL_ERROR_SIZE] = {0};
  Upload up{&mime.value()};
  curl_slist* rcpt = nullptr;
  for (const auto& r : m.to) rcpt = curl_slist_append(rcpt, ("<" + r + ">").c_str());

  const std::string scheme = cfg_.tls == "ssl" ? "smtps://" : "smtp://";
  const std::string url = scheme + cfg_.host + ":" + std::to_string(cfg_.port);
  const std::string from = "<" + addressOf(cfg_.from) + ">";

  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_MAIL_FROM, from.c_str());
  curl_easy_setopt(c, CURLOPT_MAIL_RCPT, rcpt);
  curl_easy_setopt(c, CURLOPT_READFUNCTION, readCb);
  curl_easy_setopt(c, CURLOPT_READDATA, &up);
  curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(mime.value().size()));
  curl_easy_setopt(c, CURLOPT_TIMEOUT, static_cast<long>(cfg_.timeout.count()));
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_ERRORBUFFER, errbuf);
  if (cfg_.tls == "starttls") curl_easy_setopt(c, CURLOPT_USE_SSL, static_cast<long>(CURLUSESSL_ALL));  // fail rather than downgrade
  if (cfg_.tls != "none") {
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
  }
  if (!cfg_.user.empty()) {
    curl_easy_setopt(c, CURLOPT_USERNAME, cfg_.user.c_str());
    curl_easy_setopt(c, CURLOPT_PASSWORD, password_.c_str());
  }

  const CURLcode rc = curl_easy_perform(c);
  curl_slist_free_all(rcpt);
  curl_easy_cleanup(c);
  if (rc != CURLE_OK) return err(std::string("smtp: ") + (errbuf[0] ? errbuf : curl_easy_strerror(rc)));
  return true;
}

}  // namespace agent
