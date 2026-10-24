#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace agent {

// One "vulnerable" CPE entry of an NVD record: which product, and which versions of it.
struct CpeMatch {
  std::string vendor, product, version;  // version "*" = see the range fields
  std::string start_incl, start_excl, end_incl, end_excl;
};

struct CveRecord {
  std::string id;
  int64_t published = 0, modified = 0;
  std::optional<double> cvss;
  std::string severity, vector, status, summary;  // status: NVD vulnStatus ("Analyzed", "Rejected"...)
  std::vector<std::string> cwes;                  // "CWE-79"
  std::vector<CpeMatch> cpes;
};

struct KevEntry {
  std::string cve, vendor, product, name, description, action;
  int64_t added = 0, due = 0;
  bool ransomware = false;
  std::vector<std::string> cwes;
};

struct EpssRow {
  std::string cve;
  double score = 0, percentile = 0;  // score: probability (0..1) of exploitation activity in the next 30 days
};

struct CweRecord {
  std::string id;  // "CWE-79"
  std::string name, description, status, likelihood;
};

struct OsvVuln {
  std::string id, summary;
  std::string modified;
  int64_t published = 0;
  std::vector<std::string> aliases;
  std::string cvss_vector;
  std::string severity_text;  // vendor rating when there is no CVSS vector (e.g. Ubuntu "medium")
  bool withdrawn = false;
  std::map<std::string, std::string> fixed;  // package name -> first fixed version ("" = no fix known)
};

struct CveRow : CveRecord {
  bool kev = false;
  int64_t kev_added = 0, kev_due = 0;
  std::string kev_action;
  bool kev_ransomware = false;
};

struct CpeRow : CpeMatch {
  std::string cve_id;
};

}  // namespace agent
