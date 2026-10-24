#pragma once
#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "core/config.h"
#include "llm/http_client.h"

namespace agent {

struct ChatRequest {
  std::string system;
  std::string user;
  nlohmann::json schema;  // JSON Schema the reply must satisfy (enforced by llama-server via grammar)
  std::string schema_name = "result";
  int max_tokens = 2048;
  std::chrono::seconds timeout{0};  // 0 = llm.timeout
};

struct ChatResponse {
  std::string content;
  std::string finish_reason;  // "stop" | "length" | ...
  int prompt_tokens = 0;
  int completion_tokens = 0;
  std::string model;
};

// Talks to llama-server through its OpenAI-compatible API.
class LlmClient {
 public:
  LlmClient(LlmConfig cfg, IHttpClient& http, std::string api_key = "")
      : cfg_(std::move(cfg)), http_(http), api_key_(std::move(api_key)) {}

  // Builds the request body (exposed for tests and for --llm-prompt).
  nlohmann::json buildRequest(const ChatRequest& req) const;

  Result<ChatResponse> chat(const ChatRequest& req);

  // GET /health: ok when the model is loaded and ready.
  Result<bool> ping();
  // Context size reported by the server (/props), if available.
  std::optional<int> serverContextSize();

  const LlmConfig& config() const { return cfg_; }

 private:
  std::vector<std::string> headers() const;

  LlmConfig cfg_;
  IHttpClient& http_;
  std::string api_key_;
};

// Reads an API key from a file (first line, trimmed). Empty path = no key.
Result<std::string> readSecretFile(const std::string& path);

}  // namespace agent
