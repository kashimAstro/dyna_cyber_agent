#include "llm/llm_client.h"

#include <fstream>

#include "core/util.h"

namespace agent {

Result<std::string> readSecretFile(const std::string& path) {
  if (path.empty()) return std::string();
  std::ifstream f(path);
  if (!f) return err("cannot read secret file '" + path + "'");
  std::string line;
  std::getline(f, line);
  return std::string(util::trim(line));
}

std::vector<std::string> LlmClient::headers() const {
  std::vector<std::string> h = {"Content-Type: application/json", "Accept: application/json"};
  if (!api_key_.empty()) h.push_back("Authorization: Bearer " + api_key_);
  return h;
}

nlohmann::json LlmClient::buildRequest(const ChatRequest& req) const {
  nlohmann::json body = {
      {"messages", {{{"role", "system"}, {"content", req.system}}, {{"role", "user"}, {"content", req.user}}}},
      {"temperature", cfg_.temperature},
      {"max_tokens", req.max_tokens},
      {"stream", false},
      // Sampling recommended for Qwen3-Coder; llama-server accepts these as extra fields.
      {"top_p", 0.8},
      {"top_k", 20},
      {"repeat_penalty", 1.05},
      // llama-server turns the schema into a GBNF grammar, so the reply is always well-formed JSON.
      {"response_format",
       {{"type", "json_schema"}, {"json_schema", {{"name", req.schema_name}, {"strict", true}, {"schema", req.schema}}}}},
  };
  if (!cfg_.model.empty()) body["model"] = cfg_.model;
  return body;
}

Result<ChatResponse> LlmClient::chat(const ChatRequest& req) {
  const std::string body = buildRequest(req).dump();
  auto r = http_.postJson(cfg_.url + "/v1/chat/completions", body, headers(), req.timeout.count() > 0 ? req.timeout : cfg_.timeout);
  if (!r) return err(r.error());
  const HttpResponse& resp = r.value();
  if (resp.status != 200) {
    std::string detail = resp.body.substr(0, 300);
    return err("llama-server returned HTTP " + std::to_string(resp.status) + ": " + detail);
  }
  const auto j = nlohmann::json::parse(resp.body, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return err("llama-server reply is not JSON");
  if (!j.contains("choices") || !j["choices"].is_array() || j["choices"].empty()) return err("llama-server reply has no choices");
  const auto& ch = j["choices"][0];
  if (!ch.contains("message") || !ch["message"].is_object() || !ch["message"].contains("content") || !ch["message"]["content"].is_string()) {
    return err("llama-server reply has no message content");
  }
  ChatResponse out;
  out.content = ch["message"]["content"].get<std::string>();
  out.finish_reason = ch.value("finish_reason", std::string());
  if (j.contains("usage") && j["usage"].is_object()) {
    out.prompt_tokens = j["usage"].value("prompt_tokens", 0);
    out.completion_tokens = j["usage"].value("completion_tokens", 0);
  }
  out.model = j.value("model", std::string());
  return out;
}

Result<bool> LlmClient::ping() {
  auto r = http_.get(cfg_.url + "/health", headers(), std::chrono::seconds(10));
  if (!r) return err(r.error());
  if (r.value().status == 200) return true;
  return err("llama-server /health returned HTTP " + std::to_string(r.value().status) + " (model still loading?)");
}

std::optional<int> LlmClient::serverContextSize() {
  auto r = http_.get(cfg_.url + "/props", headers(), std::chrono::seconds(10));
  if (!r || r.value().status != 200) return std::nullopt;
  const auto j = nlohmann::json::parse(r.value().body, nullptr, false);
  if (!j.is_object() || !j.contains("default_generation_settings")) return std::nullopt;
  const auto& d = j["default_generation_settings"];
  if (d.is_object() && d.contains("n_ctx") && d["n_ctx"].is_number_integer()) return d["n_ctx"].get<int>();
  return std::nullopt;
}

}  // namespace agent
