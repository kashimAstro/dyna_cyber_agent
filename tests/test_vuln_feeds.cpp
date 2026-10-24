#include <catch2/catch.hpp>

#include "vuln/feed_parsers.h"
#include "vuln/vuln_db.h"

using namespace agent;

namespace {

// Trimmed from a real NVD CVE 2.0 response (CVE-2021-44228).
const char* kNvdPage = R"J({
  "resultsPerPage": 3, "startIndex": 0, "totalResults": 3, "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-10-22T20:04:33.951",
  "vulnerabilities": [
    {"cve": {
      "id": "CVE-2021-44228", "vulnStatus": "Analyzed", "published": "2021-12-10T10:15:09.143", "lastModified": "2026-08-11T19:33:44.513",
      "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}, {"lang": "es", "value": "Las caracteristicas"}],
      "metrics": {
        "cvssMetricV31": [
          {"source": "security@apache.org", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L", "baseScore": 9.9, "baseSeverity": "CRITICAL"}},
          {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0, "baseSeverity": "CRITICAL"}}
        ],
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C", "baseScore": 9.3}}]
      },
      "weaknesses": [
        {"source": "security@apache.org", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-20"}, {"lang": "en", "value": "CWE-502"}]},
        {"source": "nvd@nist.gov", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-917"}, {"lang": "en", "value": "CWE-20"}, {"lang": "en", "value": "NVD-CWE-Other"}]}
      ],
      "configurations": [
        {"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
          {"vulnerable": true, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "versionStartIncluding": "2.0.1", "versionEndExcluding": "2.3.1", "matchCriteriaId": "A"},
          {"vulnerable": true, "criteria": "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*", "matchCriteriaId": "B"},
          {"vulnerable": false, "criteria": "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*", "matchCriteriaId": "C"},
          {"vulnerable": true, "criteria": "cpe:2.3:o:vendor\\:x:thing:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "D"},
          {"vulnerable": true, "criteria": "cpe:2.3:h:vendor:box:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "E"}
        ]}]}
      ]
    }},
    {"cve": {"id": "CVE-2010-0001", "vulnStatus": "Rejected", "published": "2010-01-01T00:00:00.000", "lastModified": "2011-01-01T00:00:00.000",
             "descriptions": [{"lang": "en", "value": "** REJECT **"}]}},
    {"cve": {"id": "CVE-2012-1624", "vulnStatus": "Analyzed", "published": "2012-03-01T10:00:00.000", "lastModified": "2026-10-20T17:49:59.130",
             "descriptions": [{"lang": "en", "value": "Old one with CVSS 2 only."}],
             "metrics": {"cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": 7.5}}]}}},
    {"notcve": 1}
  ]})J";

const char* kKev = R"J({
  "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.10.20", "dateReleased": "2026-10-20T15:30:00.000Z", "count": 3,
  "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
     "dateAdded": "2021-12-10", "shortDescription": "Apache Log4j2 contains a vulnerability in JNDI features.", "requiredAction": "Apply updates per vendor instructions.",
     "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]},
    {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Acme Widget RCE", "dateAdded": "2026-10-19",
     "shortDescription": "Widget RCE.", "requiredAction": "Patch.", "dueDate": "2026-11-09", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "not-a-cve", "vendorProject": "x"}
  ]})J";

const char* kCwe = R"J({"Weaknesses": [
  {"ID": "79", "Name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Abstraction": "Base", "Structure": "Simple",
   "Status": "Stable", "Description": "The product does not neutralize user-controllable input.", "LikelihoodOfExploit": "High", "RelatedWeaknesses": []},
  {"ID": "787", "Name": "Out-of-bounds Write", "Status": "Stable", "Description": "Writes data past the end of a buffer."},
  {"ID": "abc", "Name": "garbage"},
  {"Name": "no id"}
]})J";

const char* kOsvVuln = R"J({
  "id": "UBUNTU-CVE-2023-5678", "modified": "2026-01-01T00:00:00Z", "published": "2023-11-06T00:00:00Z",
  "aliases": ["CVE-2023-5678"], "summary": "Excessive time spent in DH check",
  "severity": [{"type": "Ubuntu", "score": "medium"}],
  "affected": [
    {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.13"}]}]},
    {"package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "openssl"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1f-1ubuntu2.21"}]}]},
    {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "edk2"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
    {"package": {"ecosystem": "PyPI", "name": "openssl"}, "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.9.9"}]}]}
  ]})J";

const char* kOsvDebian = R"J({
  "id": "DSA-5532-1", "modified": "2025-05-05T00:00:00Z", "aliases": ["CVE-2023-4863", "CVE-2023-5129"],
  "details": "A heap buffer overflow was discovered in libwebp. This goes on for a while to be used as a summary.",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}],
  "affected": [{"package": {"ecosystem": "Debian:12", "name": "libwebp"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.4-0.2+deb12u1"}, {"fixed": "1.2.4-0.2+deb12u2"}]}]}],
  "withdrawn": "2025-06-01T00:00:00Z"})J";

}  // namespace

TEST_CASE("CPE names and ISO times") {
  auto c = parseCpe23("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
  REQUIRE(c);
  REQUIRE(c->part == "a");
  REQUIRE(c->vendor == "apache");
  REQUIRE(c->product == "log4j");
  REQUIRE(c->version == "2.14.1");
  auto e = parseCpe23("cpe:2.3:a:vendor\\:x:pro\\:duct:1.0:*:*:*:*:*:*:*");
  REQUIRE(e);
  REQUIRE(e->vendor == "vendor:x");
  REQUIRE(e->product == "pro:duct");
  REQUIRE_FALSE(parseCpe23("cpe:/a:apache:log4j"));  // old 2.2 syntax
  REQUIRE_FALSE(parseCpe23("garbage"));

  REQUIRE(parseIsoTime("1970-01-02T00:00:00.000") == 86400);
  REQUIRE(parseIsoTime("2021-12-10T10:15:09.143") == 1639131309);
  REQUIRE(parseIsoTime("2021-12-10T10:15:09Z") == 1639131309);
  REQUIRE(parseIsoTime("2021-12-10") == 1639094400);
  REQUIRE(parseIsoTime("nonsense") == 0);
  REQUIRE(parseIsoTime("") == 0);
  REQUIRE(formatNvdTime(1639131309) == "2021-12-10T10:15:09.000");
  REQUIRE(parseIsoTime(formatNvdTime(1700000000)) == 1700000000);
}

TEST_CASE("NVD page parsing") {
  auto p = parseNvdPage(kNvdPage);
  REQUIRE(p.ok());
  REQUIRE(p.value().total == 3);
  REQUIRE(p.value().per_page == 3);
  REQUIRE(p.value().cves.size() == 3);  // the bogus entry is skipped

  const auto& log4j = p.value().cves[0];
  REQUIRE(log4j.id == "CVE-2021-44228");
  REQUIRE(log4j.status == "Analyzed");
  REQUIRE(log4j.cvss.value() == Approx(10.0));      // NVD's own (Primary) score, not the CNA's 9.9
  REQUIRE(log4j.severity == "critical");
  REQUIRE(log4j.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  REQUIRE(log4j.summary.rfind("Apache Log4j2", 0) == 0);
  REQUIRE(log4j.published == parseIsoTime("2021-12-10T10:15:09"));
  REQUIRE(log4j.modified == parseIsoTime("2026-08-11T19:33:44"));
  REQUIRE(log4j.cwes == std::vector<std::string>{"CWE-20", "CWE-502", "CWE-917"});  // deduplicated, NVD-CWE-Other dropped
  REQUIRE(log4j.cpes.size() == 3);                                                    // not-vulnerable platform entry and hardware part skipped
  REQUIRE(log4j.cpes[0].product == "log4j");
  REQUIRE(log4j.cpes[0].version == "*");
  REQUIRE(log4j.cpes[0].start_incl == "2.0.1");
  REQUIRE(log4j.cpes[0].end_excl == "2.3.1");
  REQUIRE(log4j.cpes[1].version == "2.0");
  REQUIRE(log4j.cpes[2].vendor == "vendor:x");

  const auto& rejected = p.value().cves[1];
  REQUIRE(rejected.status == "Rejected");
  REQUIRE_FALSE(rejected.cvss);

  const auto& old = p.value().cves[2];
  REQUIRE(old.cvss.value() == Approx(7.5));          // falls back to CVSS 2 when nothing newer exists
  REQUIRE(old.severity == "high");

  REQUIRE_FALSE(parseNvdPage("not json").ok());
  REQUIRE_FALSE(parseNvdPage("{\"foo\": 1}").ok());
  REQUIRE_FALSE(parseNvdPage("{\"message\": \"Request forbidden by administrative rules\"}").ok());
}

TEST_CASE("KEV, CWE and OSV parsing") {
  auto k = parseKev(kKev);
  REQUIRE(k.ok());
  REQUIRE(k.value().size() == 2);
  REQUIRE(k.value()[0].cve == "CVE-2021-44228");
  REQUIRE(k.value()[0].vendor == "Apache");
  REQUIRE(k.value()[0].ransomware);
  REQUIRE(k.value()[0].added == parseIsoTime("2021-12-10"));
  REQUIRE(k.value()[0].due == parseIsoTime("2021-12-24"));
  REQUIRE(k.value()[0].cwes.size() == 4);
  REQUIRE_FALSE(k.value()[1].ransomware);
  REQUIRE(k.value()[1].cwes.empty());
  REQUIRE_FALSE(parseKev("{}").ok());

  auto c = parseCweResponse(kCwe);
  REQUIRE(c.ok());
  REQUIRE(c.value().size() == 2);
  REQUIRE(c.value()[0].id == "CWE-79");
  REQUIRE(c.value()[0].name.find("Cross-site Scripting") != std::string::npos);
  REQUIRE(c.value()[0].likelihood == "High");
  REQUIRE(c.value()[1].id == "CWE-787");
  REQUIRE_FALSE(parseCweResponse("{\"error\": 1}").ok());

  auto b = parseOsvBatch(R"J({"results": [{}, {"vulns": [{"id": "CVE-1", "modified": "2025"}, {"id": "DSA-1-1", "modified": "2024"}], "next_page_token": "tok"}]})J");
  REQUIRE(b.ok());
  REQUIRE(b.value().size() == 2);
  REQUIRE(b.value()[0].vulns.empty());
  REQUIRE(b.value()[1].vulns.size() == 2);
  REQUIRE(b.value()[1].next_page_token == "tok");
  REQUIRE_FALSE(parseOsvBatch("{}").ok());

  auto u = parseOsvVuln(kOsvVuln, "Ubuntu");
  REQUIRE(u.ok());
  REQUIRE(u.value().id == "UBUNTU-CVE-2023-5678");
  REQUIRE(u.value().aliases == std::vector<std::string>{"CVE-2023-5678"});
  REQUIRE(u.value().severity_text == "medium");
  REQUIRE(u.value().fixed.count("openssl") == 1);
  REQUIRE(u.value().fixed.at("openssl") == "3.0.2-0ubuntu1.13");  // the newest fix among releases (a hint, OSV did the matching)
  REQUIRE(u.value().fixed.at("edk2").empty());                     // affected, no fix known
  REQUIRE_FALSE(u.value().withdrawn);
  REQUIRE(u.value().published == parseIsoTime("2023-11-06T00:00:00Z"));

  auto d = parseOsvVuln(kOsvDebian, "Debian");
  REQUIRE(d.ok());
  REQUIRE(d.value().cvss_vector.rfind("CVSS:3.1/", 0) == 0);
  REQUIRE(d.value().fixed.at("libwebp") == "1.2.4-0.2+deb12u2");
  REQUIRE(d.value().withdrawn);
  REQUIRE(d.value().summary.rfind("A heap buffer overflow", 0) == 0);  // summary falls back to details
  REQUIRE(parseOsvVuln(kOsvVuln, "Debian").value().fixed.empty());     // other ecosystem family: nothing relevant
  REQUIRE_FALSE(parseOsvVuln("{}", "Debian").ok());
}

TEST_CASE("vulnerability database") {
  auto dbr = VulnDb::open(":memory:");
  REQUIRE(dbr.ok());
  VulnDb& db = *dbr.value();

  auto page = parseNvdPage(kNvdPage);
  REQUIRE(db.upsertCves(page.value().cves).ok());
  auto got = db.getCve("CVE-2021-44228");
  REQUIRE(got.value().has_value());
  REQUIRE(got.value()->cvss.value() == Approx(10.0));
  REQUIRE(got.value()->cwes.size() == 3);
  REQUIRE_FALSE(got.value()->kev);
  REQUIRE_FALSE(db.getCve("CVE-9999-0000").value().has_value());
  REQUIRE_FALSE(db.getCve("CVE-2010-0001").value()->cvss.has_value());

  auto cpes = db.cpeByProduct("log4j");
  REQUIRE(cpes.value().size() == 2);
  // re-importing a CVE replaces (not duplicates) its CPE rows
  REQUIRE(db.upsertCves(page.value().cves).ok());
  REQUIRE(db.cpeByProduct("log4j").value().size() == 2);

  // KEV flags the same record and creates stub rows for CVEs NVD has not described yet
  auto kev = parseKev(kKev);
  REQUIRE(db.applyKev(kev.value()).ok());
  auto l4 = db.getCve("CVE-2021-44228").value();
  REQUIRE(l4->kev);
  REQUIRE(l4->kev_ransomware);
  REQUIRE(l4->kev_due == parseIsoTime("2021-12-24"));
  REQUIRE(l4->cvss.value() == Approx(10.0));            // NVD data survives the KEV update
  REQUIRE(l4->cwes.size() == 3);                         // ...including its richer CWE list
  auto stub = db.getCve("CVE-2026-0001").value();
  REQUIRE(stub.has_value());
  REQUIRE(stub->kev);
  REQUIRE_FALSE(stub->cvss.has_value());
  REQUIRE(stub->summary.find("Acme Widget RCE") != std::string::npos);
  // a later NVD import of the stub fills the score and keeps the KEV flag
  CveRecord later;
  later.id = "CVE-2026-0001";
  later.cvss = 9.8;
  later.severity = "critical";
  later.summary = "Real description";
  REQUIRE(db.upsertCves({later}).ok());
  auto filled = db.getCve("CVE-2026-0001").value();
  REQUIRE(filled->kev);
  REQUIRE(filled->cvss.value() == Approx(9.8));
  REQUIRE(filled->summary == "Real description");

  auto added = db.kevAddedSince(parseIsoTime("2026-01-01"));
  REQUIRE(added.value() == std::vector<std::string>{"CVE-2026-0001"});
  REQUIRE(db.kevAddedSince(0).value().size() == 2);

  auto found = db.searchCves("log4j", 10);
  REQUIRE(found.value().size() == 1);
  REQUIRE(db.searchCves("CVE-2012", 10).value().size() == 1);

  // CWE bookkeeping: what is referenced but unknown is what we fetch
  auto need = db.cweIdsToFetch(2000000000, 86400, 100);
  REQUIRE(need.value() == std::vector<std::string>{"CWE-20", "CWE-502", "CWE-917"});
  REQUIRE(db.upsertCwes(parseCweResponse(kCwe).value()).ok());
  REQUIRE(db.getCwe("CWE-79").value()->name.find("Cross-site") != std::string::npos);
  CweRecord c20;
  c20.id = "CWE-20";
  c20.name = "Improper Input Validation";
  REQUIRE(db.upsertCwes({c20}).ok());
  need = db.cweIdsToFetch(static_cast<int64_t>(std::time(nullptr)) + 10, 86400, 100);
  REQUIRE(need.value() == std::vector<std::string>{"CWE-502", "CWE-917"});
  REQUIRE(db.cweIdsToFetch(static_cast<int64_t>(std::time(nullptr)) + 10 * 86400, 86400, 100).value().size() == 3);  // stale ones are refreshed
  REQUIRE(db.cweIdsToFetch(2000000000, 86400, 1).value().size() == 1);                                               // limit honoured

  // OSV cache
  REQUIRE_FALSE(db.getOsvCache("Debian:12", "openssl", "3.0.9-1").value().has_value());
  REQUIRE(db.putOsvCache("Debian:12", "openssl", "3.0.9-1", 1000, {"DSA-1-1", "CVE-2023-1"}).ok());
  auto cache = db.getOsvCache("Debian:12", "openssl", "3.0.9-1").value();
  REQUIRE(cache->queried == 1000);
  REQUIRE(cache->vuln_ids.size() == 2);
  REQUIRE(db.putOsvCache("Debian:12", "openssl", "3.0.9-1", 2000, {}).ok());  // refresh replaces
  REQUIRE(db.getOsvCache("Debian:12", "openssl", "3.0.9-1").value()->vuln_ids.empty());
  auto ov = parseOsvVuln(kOsvVuln, "Ubuntu").value();
  REQUIRE(db.putOsvVuln(ov, 5000).ok());
  auto back = db.getOsvVuln("UBUNTU-CVE-2023-5678").value();
  REQUIRE(back.has_value());
  REQUIRE(back->aliases == ov.aliases);
  REQUIRE(back->fixed == ov.fixed);
  REQUIRE(back->severity_text == "medium");

  REQUIRE(db.setMeta("k", "v").ok());
  REQUIRE(db.getMeta("k").value() == "v");
  REQUIRE_FALSE(db.getMeta("nope").value().has_value());
  auto st = db.stats().value();
  REQUIRE(st.cves == 4);
  REQUIRE(st.kev == 2);
  REQUIRE(st.cwes == 3);
  REQUIRE(st.osv_vulns == 1);
}
