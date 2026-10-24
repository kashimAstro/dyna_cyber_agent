#pragma once
#include <string>

#include "core/config.h"
#include "report/mime.h"

namespace agent {

class IMailer {
 public:
  virtual ~IMailer() = default;
  virtual Result<bool> send(const MailMessage& m) = 0;
};

// Delivers through an SMTP server with libcurl (STARTTLS or implicit TLS, certificate verification on).
class SmtpMailer final : public IMailer {
 public:
  SmtpMailer(SmtpConfig cfg, std::string password) : cfg_(std::move(cfg)), password_(std::move(password)) {}
  Result<bool> send(const MailMessage& m) override;

 private:
  SmtpConfig cfg_;
  std::string password_;
};

}  // namespace agent
