#pragma once
#include "llm/reasoner.h"
#include "report/notifier.h"
#include "store/store.h"

namespace agent {

// Turns a Report into the model's input (security findings in full, vulnerabilities only as an aggregate,
// plus what the last mails already said) and asks for ONE report.
SynthesisInput makeSynthesisInput(const Report& r, const std::vector<std::string>& previous);

// Hook for Notifier::setSynthesizer. The Reasoner and the Store must outlive the returned function.
Notifier::Synthesizer makeSynthesizer(Reasoner& reasoner, Store& store);

}  // namespace agent
