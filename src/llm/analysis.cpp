#include "llm/analysis.h"

#include <algorithm>
#include <cctype>

#include <nlohmann/json.hpp>

#include "core/util.h"
#include "llm/ask.h"
#include "llm/synthesis.h"

namespace agent {
namespace {

std::string cleanText(const nlohmann::json& j, size_t max_len) {
  if (!j.is_string()) return {};
  std::string s;
  for (unsigned char c : j.get<std::string>()) s += (c < 0x20 && c != '\n') || c == 0x7F ? ' ' : static_cast<char>(c);
  s = util::toValidUtf8(s);
  if (s.size() > max_len) {
    s.resize(max_len);
    s = util::toValidUtf8(s) + "...";  // a cut multi-byte sequence becomes '?' instead of invalid UTF-8
  }
  return std::string(util::trim(s));
}

// The model's output grammar cuts a string at its maximum length, even in the middle of a word. A summary that does
// not end like a sentence is cut back to the last complete one.
std::string endAtSentence(std::string s) {
  const auto ends = [](char c) { return c == '.' || c == '!' || c == '?'; };
  if (s.empty() || ends(s.back()) || (s.size() > 3 && s.compare(s.size() - 3, 3, "...") == 0)) return s;
  size_t cut = std::string::npos;
  for (size_t i = 0; i + 1 < s.size(); ++i) {
    if (ends(s[i]) && (s[i + 1] == ' ' || s[i + 1] == '\n')) cut = i;
  }
  if (cut == std::string::npos || cut < s.size() / 3) return s;  // no sentence worth keeping: leave the text alone
  return s.substr(0, cut + 1);
}

// Leading sentence of `summary` that only repeats the headline.
std::string dropRepeatedHeadline(const std::string& summary, const std::string& headline) {
  const auto norm = [](const std::string& t) {
    std::string o;
    for (unsigned char c : t) {
      if (std::isalnum(c)) o += static_cast<char>(std::tolower(c));
    }
    return o;
  };
  const std::string h = norm(headline);
  if (h.size() < 20) return summary;
  size_t end = std::string::npos;  // a full stop followed by a space: the dots inside "1.1.1.1" do not end a sentence
  for (size_t i = 0; i + 1 < summary.size(); ++i) {
    if ((summary[i] == '.' || summary[i] == '!' || summary[i] == '?') && std::isspace(static_cast<unsigned char>(summary[i + 1]))) {
      end = i;
      break;
    }
  }
  if (end == std::string::npos) return summary;
  const std::string first = norm(summary.substr(0, end + 1));
  if (first.find(h) == std::string::npos && h.find(first) == std::string::npos) return summary;
  std::string rest(util::trim(summary.substr(end + 1)));
  return rest.empty() ? summary : rest;
}

std::vector<std::string> cleanList(const nlohmann::json& j, size_t max_items, size_t max_len) {
  std::vector<std::string> out;
  if (!j.is_array()) return out;
  for (const auto& e : j) {
    if (out.size() >= max_items) break;
    std::string s = cleanText(e, max_len);
    if (!s.empty()) out.push_back(std::move(s));
  }
  return out;
}

std::optional<Severity> sev(const nlohmann::json& j) {
  return j.is_string() ? parseSeverity(j.get<std::string>()) : std::nullopt;
}

bool validVerdict(const std::string& v) {
  return v == "likely_malicious" || v == "suspicious" || v == "likely_benign" || v == "needs_more_data";
}

}  // namespace

Result<Analysis> parseAnalysis(const std::string& text, const std::unordered_set<int64_t>& allowed_ids, size_t* dropped) {
  size_t drop = 0;
  const auto j = nlohmann::json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return err("model reply is not a JSON object");

  Analysis a;
  a.summary = cleanText(j.value("summary", nlohmann::json()), 1200);
  const auto overall = sev(j.value("overall_risk", nlohmann::json()));
  if (a.summary.empty() || !overall) return err("model reply misses summary or overall_risk");
  a.overall_risk = *overall;

  std::unordered_set<int64_t> seen;
  if (j.contains("assessments") && j["assessments"].is_array()) {
    for (const auto& e : j["assessments"]) {
      if (!e.is_object() || !e.contains("finding_id") || !e["finding_id"].is_number_integer()) { ++drop; continue; }
      Assessment as;
      as.finding_id = e["finding_id"].get<int64_t>();
      const auto risk = sev(e.value("risk", nlohmann::json()));
      const std::string verdict = e.value("verdict", std::string());
      if (!allowed_ids.count(as.finding_id) || !seen.insert(as.finding_id).second || !risk || !validVerdict(verdict)) {
        ++drop;  // hallucinated id, duplicate, or malformed
        continue;
      }
      as.verdict = verdict;
      as.risk = *risk;
      const int64_t conf = e.value("confidence", static_cast<int64_t>(0));
      as.confidence = static_cast<int>(std::max<int64_t>(0, std::min<int64_t>(100, conf)));
      as.explanation = cleanText(e.value("explanation", nlohmann::json()), 1500);
      as.recommended_actions = cleanList(e.value("recommended_actions", nlohmann::json()), 6, 400);
      as.additional_checks = cleanList(e.value("additional_checks", nlohmann::json()), 4, 300);
      a.assessments.push_back(std::move(as));
    }
  }

  if (j.contains("correlations") && j["correlations"].is_array()) {
    for (const auto& e : j["correlations"]) {
      if (!e.is_object()) { ++drop; continue; }
      Correlation c;
      c.title = cleanText(e.value("title", nlohmann::json()), 200);
      c.narrative = cleanText(e.value("narrative", nlohmann::json()), 1500);
      const auto risk = sev(e.value("risk", nlohmann::json()));
      if (e.contains("finding_ids") && e["finding_ids"].is_array()) {
        for (const auto& id : e["finding_ids"]) {
          if (id.is_number_integer() && allowed_ids.count(id.get<int64_t>())) c.finding_ids.push_back(id.get<int64_t>());
        }
      }
      c.mitre = cleanList(e.value("mitre", nlohmann::json()), 6, 16);
      if (c.title.empty() || !risk || c.finding_ids.size() < 2) { ++drop; continue; }  // a correlation links at least two findings
      c.risk = *risk;
      a.correlations.push_back(std::move(c));
    }
  }
  if (dropped) *dropped = drop;
  return a;
}

Result<Synthesis> parseSynthesis(const std::string& text, const std::unordered_set<int64_t>& allowed_ids) {
  const auto j = nlohmann::json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return err("model reply is not a JSON object");
  Synthesis s;
  s.headline = cleanText(j.value("headline", nlohmann::json()), 300);
  s.summary = dropRepeatedHeadline(endAtSentence(cleanText(j.value("summary", nlohmann::json()), 1800)), s.headline);
  if (s.headline.empty() || s.summary.empty()) return err("model reply misses headline or summary");
  const auto validIds = [&](const nlohmann::json& arr) {
    std::vector<int64_t> ids;
    if (!arr.is_array()) return ids;
    for (const auto& id : arr) {
      if (id.is_number_integer() && allowed_ids.count(id.get<int64_t>())) ids.push_back(id.get<int64_t>());
    }
    return ids;
  };
  if (j.contains("priorities") && j["priorities"].is_array()) {
    for (const auto& e : j["priorities"]) {
      if (!e.is_object() || s.priorities.size() >= 5) continue;
      Synthesis::Priority p;
      p.text = cleanText(e.value("text", nlohmann::json()), 450);
      p.finding_ids = validIds(e.value("finding_ids", nlohmann::json()));
      if (!p.text.empty()) s.priorities.push_back(std::move(p));
    }
  }
  if (j.contains("correlations") && j["correlations"].is_array()) {
    for (const auto& e : j["correlations"]) {
      if (!e.is_object() || s.correlations.size() >= 3) continue;
      Correlation c;
      c.title = cleanText(e.value("title", nlohmann::json()), 200);
      c.narrative = cleanText(e.value("narrative", nlohmann::json()), 1000);
      const auto risk = sev(e.value("risk", nlohmann::json()));
      c.finding_ids = validIds(e.value("finding_ids", nlohmann::json()));
      c.mitre = cleanList(e.value("mitre", nlohmann::json()), 6, 16);
      if (c.title.empty() || !risk || c.finding_ids.size() < 2) continue;
      c.risk = *risk;
      s.correlations.push_back(std::move(c));
    }
  }
  return s;
}

Result<AskAnswer> parseAskAnswer(const std::string& text, const std::unordered_set<int64_t>& allowed_ids) {
  const auto j = nlohmann::json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return err("model reply is not a JSON object");
  AskAnswer a;
  a.answer = endAtSentence(cleanText(j.value("answer", nlohmann::json()), 2000));
  a.data_gaps = endAtSentence(cleanText(j.value("data_gaps", nlohmann::json()), 400));
  if (a.answer.empty()) return err("model reply has no answer");
  if (j.contains("finding_ids") && j["finding_ids"].is_array()) {
    for (const auto& id : j["finding_ids"]) {
      if (id.is_number_integer() && allowed_ids.count(id.get<int64_t>()) && a.finding_ids.size() < 12 &&
          std::find(a.finding_ids.begin(), a.finding_ids.end(), id.get<int64_t>()) == a.finding_ids.end())
        a.finding_ids.push_back(id.get<int64_t>());
    }
  }
  return a;
}

}  // namespace agent
