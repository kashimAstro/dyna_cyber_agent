#include "llm/reasoner.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <thread>
#include <unordered_set>

#include "llm/prompt.h"

namespace agent {
namespace {

constexpr int kMaxSplitDepth = 3;
constexpr size_t kPromptMargin = 512;

std::vector<Finding> byImportance(std::vector<Finding> f) {
  std::stable_sort(f.begin(), f.end(), [](const Finding& a, const Finding& b) {
    return a.severity != b.severity ? a.severity > b.severity : a.last_seen > b.last_seen;
  });
  return f;
}

int64_t nowTs() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

}  // namespace

Result<Synthesis> Reasoner::synthesize(const SynthesisInput& in) {
  if (!available()) return err("LLM temporarily disabled after repeated failures");
  const PromptParts prompt = buildSynthesisPrompt(in, opts_.language, opts_.admin_focus);
  const size_t budget = opts_.context_tokens > static_cast<size_t>(opts_.synthesis_max_tokens) + kPromptMargin
                            ? opts_.context_tokens - static_cast<size_t>(opts_.synthesis_max_tokens) - kPromptMargin
                            : 1024;
  if (prompt.estimated_tokens > budget) return err("report too large for the model context");

  ChatRequest req;
  req.system = prompt.system;
  req.user = prompt.user;
  req.schema = synthesisSchema();
  req.schema_name = "security_report";
  req.max_tokens = opts_.synthesis_max_tokens;
  req.timeout = opts_.synthesis_timeout;

  Result<ChatResponse> resp = err("not called");
  for (int attempt = 0; attempt <= opts_.max_retries; ++attempt) {
    resp = client_.chat(req);
    if (resp) break;
    spdlog::warn("LLM synthesis failed (attempt {}/{}): {}", attempt + 1, opts_.max_retries + 1, resp.error());
    if (attempt < opts_.max_retries) std::this_thread::sleep_for(opts_.retry_delay * (attempt + 1));
  }
  if (!resp) {
    if (++consecutive_failures_ >= opts_.breaker_threshold) {
      paused_until_ = std::chrono::steady_clock::now() + opts_.breaker_pause;
      consecutive_failures_ = 0;
      spdlog::error("LLM unreachable: pausing LLM analysis for {}s", opts_.breaker_pause.count());
    }
    return err(resp.error());
  }
  consecutive_failures_ = 0;
  if (resp.value().finish_reason == "length") return err("model reply truncated");
  std::unordered_set<int64_t> ids(prompt.finding_ids.begin(), prompt.finding_ids.end());
  auto parsed = parseSynthesis(resp.value().content, ids);
  if (!parsed) return err(parsed.error());
  parsed.value().model = resp.value().model.empty() ? client_.config().model : resp.value().model;
  return parsed;
}

bool Reasoner::available() const { return std::chrono::steady_clock::now() >= paused_until_; }

Result<std::vector<Analysis>> Reasoner::analyze(const std::string& target, std::vector<Finding> findings, const nlohmann::json& host_context) {
  std::vector<Analysis> all;
  if (findings.empty()) return all;
  if (!available()) return err("LLM temporarily disabled after repeated failures");

  const size_t budget = opts_.context_tokens > static_cast<size_t>(opts_.max_tokens) + kPromptMargin
                            ? opts_.context_tokens - static_cast<size_t>(opts_.max_tokens) - kPromptMargin
                            : 1024;
  findings = byImportance(std::move(findings));

  // Pack findings into batches that respect both the count limit and the context budget.
  std::vector<std::vector<Finding>> batches(1);
  for (auto& f : findings) {
    auto& cur = batches.back();
    std::vector<Finding> trial = cur;
    trial.push_back(f);
    const bool too_many = trial.size() > opts_.max_findings_per_call;
    const bool too_big = !cur.empty() && buildPrompt(target, trial, host_context, opts_.language, opts_.admin_focus).estimated_tokens > budget;
    if (too_many || too_big) batches.emplace_back();
    batches.back().push_back(std::move(f));
  }

  std::string last_error;
  for (const auto& b : batches) {
    if (!available()) break;
    auto r = runBatch(target, b, host_context, 0);
    if (r) {
      for (auto& a : r.value()) all.push_back(std::move(a));
    } else {
      last_error = r.error();
      spdlog::warn("LLM batch of {} finding(s) for {} failed: {}", b.size(), target, last_error);
    }
  }
  if (all.empty()) return err(last_error.empty() ? "LLM unavailable" : last_error);
  return all;
}

Result<std::vector<Analysis>> Reasoner::runBatch(const std::string& target, const std::vector<Finding>& batch,
                                                 const nlohmann::json& ctx, int depth) {
  // A lone oversized finding is retried with harder trimming before giving up.
  bool strict = false;
  PromptParts prompt = buildPrompt(target, batch, ctx, opts_.language, opts_.admin_focus);
  const size_t budget = opts_.context_tokens > static_cast<size_t>(opts_.max_tokens) + kPromptMargin
                            ? opts_.context_tokens - static_cast<size_t>(opts_.max_tokens) - kPromptMargin
                            : 1024;
  if (prompt.estimated_tokens > budget) {
    strict = true;
    prompt = buildPrompt(target, batch, ctx, opts_.language, opts_.admin_focus, true);
    if (prompt.estimated_tokens > budget && batch.size() == 1) {
      return err("finding #" + std::to_string(batch[0].id) + " is too large for the model context");
    }
  }
  if (prompt.estimated_tokens > budget && batch.size() > 1) {
    const size_t half = batch.size() / 2;
    std::vector<Finding> a(batch.begin(), batch.begin() + static_cast<std::ptrdiff_t>(half)), b(batch.begin() + static_cast<std::ptrdiff_t>(half), batch.end());
    auto ra = runBatch(target, a, ctx, depth + 1);
    auto rb = runBatch(target, b, ctx, depth + 1);
    if (!ra && !rb) return err(ra.error());
    std::vector<Analysis> out;
    for (auto* r : {&ra, &rb}) if (*r) for (auto& x : r->value()) out.push_back(std::move(x));
    return out;
  }
  (void)strict;

  ChatRequest req;
  req.system = prompt.system;
  req.user = prompt.user;
  req.schema = analysisSchema(batch.size());
  req.schema_name = "security_assessment";
  req.max_tokens = opts_.max_tokens;

  Result<ChatResponse> resp = err("not called");
  for (int attempt = 0; attempt <= opts_.max_retries; ++attempt) {
    resp = client_.chat(req);
    if (resp) break;
    spdlog::warn("LLM request failed (attempt {}/{}): {}", attempt + 1, opts_.max_retries + 1, resp.error());
    if (attempt < opts_.max_retries) std::this_thread::sleep_for(opts_.retry_delay * (attempt + 1));
  }
  if (!resp) {
    if (++consecutive_failures_ >= opts_.breaker_threshold) {
      paused_until_ = std::chrono::steady_clock::now() + opts_.breaker_pause;
      consecutive_failures_ = 0;
      spdlog::error("LLM unreachable: pausing LLM analysis for {}s", opts_.breaker_pause.count());
    }
    return err(resp.error());
  }
  consecutive_failures_ = 0;

  std::unordered_set<int64_t> ids(prompt.finding_ids.begin(), prompt.finding_ids.end());
  size_t dropped = 0;
  auto parsed = parseAnalysis(resp.value().content, ids, &dropped);
  const bool truncated = resp.value().finish_reason == "length";
  if (!parsed || truncated) {
    // Reply cut by max_tokens (or unusable): smaller batches produce shorter replies.
    if (batch.size() > 1 && depth < kMaxSplitDepth) {
      spdlog::info("LLM reply {}: splitting {} findings", truncated ? "truncated" : "unusable", batch.size());
      const size_t half = batch.size() / 2;
      std::vector<Finding> a(batch.begin(), batch.begin() + static_cast<std::ptrdiff_t>(half)), b(batch.begin() + static_cast<std::ptrdiff_t>(half), batch.end());
      auto ra = runBatch(target, a, ctx, depth + 1);
      auto rb = runBatch(target, b, ctx, depth + 1);
      if (!ra && !rb) return err(ra.error());
      std::vector<Analysis> out;
      for (auto* r : {&ra, &rb}) if (*r) for (auto& x : r->value()) out.push_back(std::move(x));
      return out;
    }
    return err(parsed ? "model reply truncated" : parsed.error());
  }
  if (dropped) spdlog::warn("LLM reply: {} invalid entr{} discarded", dropped, dropped == 1 ? "y" : "ies");

  Analysis a = std::move(parsed.value());
  a.target = target;
  a.created_at = nowTs();
  a.model = resp.value().model.empty() ? client_.config().model : resp.value().model;
  a.finding_ids = prompt.finding_ids;
  a.prompt_tokens = resp.value().prompt_tokens;
  a.completion_tokens = resp.value().completion_tokens;

  // Deterministic flags: the model cannot clear them.
  std::unordered_set<int64_t> injected;
  for (const auto& f : batch) {
    if (findingForPrompt(f).value("prompt_injection_suspected", false)) injected.insert(f.id);
  }
  for (auto& as : a.assessments) {
    as.created_at = a.created_at;
    if (injected.count(as.finding_id)) {
      as.flags.push_back("prompt_injection_suspected");
      if (as.risk < Severity::Medium) as.risk = Severity::Medium;
    }
  }
  std::vector<Analysis> out;
  out.push_back(std::move(a));
  return out;
}

}  // namespace agent
