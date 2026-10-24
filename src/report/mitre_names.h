#pragma once
#include <string>

namespace agent {

// Names of the MITRE ATT&CK techniques the built-in rules refer to ("T1110.001" -> "Brute Force: Password Guessing").
// Returns "" for an id the table does not know.
std::string mitreName(const std::string& technique_id);

// The ATT&CK tactic ("stage of the attack") a technique mostly serves: "T1110.001" -> "credential-access". "" when unknown.
std::string mitreTactic(const std::string& technique_id);

// Readable name of a tactic id in "it" or "en": "credential-access" -> "Credential access" / "Accesso alle credenziali".
std::string tacticName(const std::string& tactic_id, const std::string& lang);

}  // namespace agent
