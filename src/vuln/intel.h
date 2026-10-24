#pragma once
#include <functional>
#include <string>
#include <vector>

#include "store/store.h"
#include "vuln/vuln_db.h"

namespace agent {

// Lines for the digest's "vulnerability intelligence" section: state of the feeds, KEV entries added in the
// period, how many of them are present on the monitored systems, and the weakness classes (CWE) most
// frequent among the newly found vulnerabilities.
std::function<std::vector<std::string>(int64_t, int64_t)> makeIntelProvider(VulnDb& db, Store& store, const std::string& lang);

// CWE names from the downloaded catalog (empty when unknown: the built-in table is the fallback).
std::function<std::string(const std::string&)> makeCweNameProvider(VulnDb& db);

}  // namespace agent
