#pragma once
#include <string>

#include <nlohmann/json.hpp>

#include "store/store.h"

namespace agent {

// Short description of the host built from its latest snapshots: gives the model the "normal
// background" (exposed services, who can log in) to judge a finding against.
nlohmann::json buildHostContext(Store& store, const std::string& target);

}  // namespace agent
