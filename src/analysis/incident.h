#pragma once
#include <chrono>
#include <string>
#include <vector>

#include "analysis/finding.h"
#include "store/store.h"

namespace agent {

// Findings that point at the same address, account, program or file are usually one story told in pieces: the
// brute force, the login that worked, the key added afterwards, the connection the new program opened. The engine
// chains them (deterministically, no model involved) into an incident with a timeline and the stages of the attack.

struct IncidentOptions {
  std::chrono::seconds window{24 * 3600};  // two findings are linked only if they appeared this close to each other
  size_t min_findings = 2;
};

struct Entity {
  std::string kind;   // ip | user | path
  std::string value;
  bool operator<(const Entity& o) const { return kind != o.kind ? kind < o.kind : value < o.value; }
  bool operator==(const Entity& o) const { return kind == o.kind && value == o.value; }
};

// What a finding says about WHO or WHAT is involved. Generic things (root, system binaries, private addresses)
// are left out on purpose: they would chain unrelated findings together.
std::vector<Entity> entitiesOf(const Finding& f);

// ATT&CK tactic of a finding ("credential-access", "persistence"...), from its techniques or, failing that, its source.
std::string stageOf(const Finding& f);

class IncidentEngine {
 public:
  IncidentEngine(Store& store, IncidentOptions opts) : store_(store), opts_(opts) {}

  // Re-derives the incidents from the open findings. Existing incidents keep their id while they keep a member;
  // two incidents joined by a new finding merge into the older one; one that no longer holds together is closed.
  // Returns the number of open incidents.
  Result<size_t> update(int64_t now);

 private:
  Store& store_;
  IncidentOptions opts_;
};

// Severity of an incident: its worst finding, one level higher when the chain spans three or more stages.
Severity incidentSeverity(const std::vector<Finding>& members, size_t stage_count);

// "Credential access -> Initial access -> Persistence on web01" in the given language.
std::string incidentTitle(const nlohmann::json& stages, const nlohmann::json& targets, const std::string& lang);

}  // namespace agent
