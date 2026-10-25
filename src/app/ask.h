#pragma once
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "store/store.h"

namespace agent {

// "Ask the agent": the administrator writes a question in Italian or English ("what changed on web01 since Tuesday?").
// The agent does NOT let the model search the machines. It works out the period and the machines from the question,
// collects what its own database knows about them (findings, incidents, package changes, collection problems) and gives
// the model only that, so every statement in the answer can be checked against data the console can show.

struct AskWindow {
  int64_t from = 0, to = 0;
  std::string label;     // "da martedi 20 ottobre 2026 00:00 a ora" / "since Tuesday 20 October 2026 00:00 until now"
  bool detected = false; // false: nothing in the question named a period, the default was used
};

// Understands: oggi/today, ieri/yesterday, "da|dal|since <weekday>", weekday alone (that whole day), "ultime N ore",
// "ultimi N giorni", "last N hours/days", ultima ora, ultima settimana, questa settimana, ultimo mese (and the English
// equivalents). Never more than 90 days. `language` only selects the wording of the label.
AskWindow parseAskWindow(const std::string& question, int64_t now, const std::string& language);

// Names of configured machines that the question mentions (whole word, case-insensitive); empty = it names none.
std::vector<std::string> askTargets(const std::string& question, const std::vector<std::string>& configured);

// "it" or "en", from the words of the question; `fallback` when it cannot tell.
std::string askLanguage(const std::string& question, const std::string& fallback);

struct AskContext {
  nlohmann::json facts;
  std::vector<int64_t> finding_ids;  // the findings that appear in `facts` (the only ones the answer may cite)
  std::vector<std::string> targets;
  AskWindow window;
  size_t findings_total = 0, findings_shown = 0;
};

// `targets` empty = every configured machine. Read-only on the database.
AskContext gatherAskContext(Store& store, const std::vector<std::string>& targets, const std::vector<std::string>& configured, const AskWindow& window);

}  // namespace agent
