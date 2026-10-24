#pragma once
#include "llm/reasoner.h"
#include "store/store.h"

namespace agent {

struct AssessStats {
  size_t analyses = 0;   // model calls that produced a valid analysis
  size_t assessed = 0;   // findings that received an assessment
  size_t missing = 0;    // submitted but not assessed by the model (they stay unassessed)
};

// Sends open findings without an assessment to the model, one target at a time, and stores the results.
// Fails only when nothing could be analysed although there was work to do.
Result<AssessStats> assessPending(Store& store, Reasoner& reasoner, size_t limit);

}  // namespace agent
