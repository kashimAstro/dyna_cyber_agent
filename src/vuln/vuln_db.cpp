#include "vuln/vuln_db.h"

#include <sqlite3.h>

#include <ctime>
#include <nlohmann/json.hpp>
#include <set>

namespace agent {
namespace {

struct Stmt {
  sqlite3_stmt* s = nullptr;
  Stmt(sqlite3* db, const char* sql) { sqlite3_prepare_v2(db, sql, -1, &s, nullptr); }
  ~Stmt() { sqlite3_finalize(s); }
  Stmt(const Stmt&) = delete;
  Stmt& operator=(const Stmt&) = delete;
  void text(int i, const std::string& v) { sqlite3_bind_text(s, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT); }
};

const char* col(sqlite3_stmt* s, int i) {
  const auto* t = sqlite3_column_text(s, i);
  return t ? reinterpret_cast<const char*>(t) : "";
}

const char* kSchema = R"(
CREATE TABLE IF NOT EXISTS cve (
  id TEXT PRIMARY KEY,
  published INTEGER NOT NULL DEFAULT 0,
  modified INTEGER NOT NULL DEFAULT 0,
  cvss REAL,
  severity TEXT NOT NULL DEFAULT '',
  vector TEXT NOT NULL DEFAULT '',
  cwes TEXT NOT NULL DEFAULT '[]',
  summary TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  kev INTEGER NOT NULL DEFAULT 0,
  kev_added INTEGER NOT NULL DEFAULT 0,
  kev_due INTEGER NOT NULL DEFAULT 0,
  kev_action TEXT NOT NULL DEFAULT '',
  kev_ransomware INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve(kev, kev_added);
CREATE TABLE IF NOT EXISTS cpe_match (
  cve_id TEXT NOT NULL,
  vendor TEXT NOT NULL,
  product TEXT NOT NULL,
  version TEXT NOT NULL,
  v_start_incl TEXT NOT NULL DEFAULT '',
  v_start_excl TEXT NOT NULL DEFAULT '',
  v_end_incl TEXT NOT NULL DEFAULT '',
  v_end_excl TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_match(product);
CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_match(cve_id);
CREATE TABLE IF NOT EXISTS cwe (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  likelihood TEXT NOT NULL DEFAULT '',
  fetched INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS osv_cache (
  eco TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
  queried INTEGER NOT NULL,
  vulns TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (eco, name, version)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS osv_vuln (
  id TEXT PRIMARY KEY,
  modified TEXT NOT NULL DEFAULT '',
  published INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT '',
  aliases TEXT NOT NULL DEFAULT '[]',
  cvss_vector TEXT NOT NULL DEFAULT '',
  severity_text TEXT NOT NULL DEFAULT '',
  withdrawn INTEGER NOT NULL DEFAULT 0,
  fixed TEXT NOT NULL DEFAULT '{}',
  fetched INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL NOT NULL, percentile REAL NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
)";

CveRow rowFrom(sqlite3_stmt* s) {  // id,published,modified,cvss,severity,vector,cwes,summary,status,kev,kev_added,kev_due,kev_action,kev_ransomware
  CveRow r;
  r.id = col(s, 0);
  r.published = sqlite3_column_int64(s, 1);
  r.modified = sqlite3_column_int64(s, 2);
  if (sqlite3_column_type(s, 3) != SQLITE_NULL) r.cvss = sqlite3_column_double(s, 3);
  r.severity = col(s, 4);
  r.vector = col(s, 5);
  const auto cw = nlohmann::json::parse(col(s, 6), nullptr, false);
  if (cw.is_array()) r.cwes = cw.get<std::vector<std::string>>();
  r.summary = col(s, 7);
  r.status = col(s, 8);
  r.kev = sqlite3_column_int(s, 9) != 0;
  r.kev_added = sqlite3_column_int64(s, 10);
  r.kev_due = sqlite3_column_int64(s, 11);
  r.kev_action = col(s, 12);
  r.kev_ransomware = sqlite3_column_int(s, 13) != 0;
  return r;
}

constexpr const char* kCveCols = "id,published,modified,cvss,severity,vector,cwes,summary,status,kev,kev_added,kev_due,kev_action,kev_ransomware";

}  // namespace

Result<std::unique_ptr<VulnDb>> VulnDb::open(const std::string& path) {
  sqlite3* db = nullptr;
  if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
    std::string m = db ? sqlite3_errmsg(db) : "out of memory";
    sqlite3_close(db);
    return err("cannot open vulnerability database '" + path + "': " + m);
  }
  std::unique_ptr<VulnDb> v(new VulnDb(db));
  sqlite3_busy_timeout(db, 10000);
  for (const char* sql : {"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", kSchema}) {
    if (auto r = v->exec(sql); !r) return err(r.error());
  }
  return v;
}

VulnDb::~VulnDb() { sqlite3_close(db_); }

Result<bool> VulnDb::exec(const char* sql) {
  char* msg = nullptr;
  if (sqlite3_exec(db_, sql, nullptr, nullptr, &msg) != SQLITE_OK) {
    std::string m = msg ? msg : "unknown error";
    sqlite3_free(msg);
    return err("sqlite: " + m);
  }
  return true;
}

Result<bool> VulnDb::upsertCves(const std::vector<CveRecord>& cves) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (cves.empty()) return true;
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  Stmt up(db_,
          "INSERT INTO cve(id,published,modified,cvss,severity,vector,cwes,summary,status) VALUES(?,?,?,?,?,?,?,?,?) "
          "ON CONFLICT(id) DO UPDATE SET published=excluded.published, modified=excluded.modified, cvss=excluded.cvss, severity=excluded.severity, "
          "vector=excluded.vector, cwes=excluded.cwes, summary=excluded.summary, status=excluded.status");
  Stmt del(db_, "DELETE FROM cpe_match WHERE cve_id=?");
  Stmt ins(db_, "INSERT INTO cpe_match(cve_id,vendor,product,version,v_start_incl,v_start_excl,v_end_incl,v_end_excl) VALUES(?,?,?,?,?,?,?,?)");
  auto fail = [&](const char* what) {
    const std::string m = sqlite3_errmsg(db_);
    exec("ROLLBACK");
    return err(std::string(what) + ": " + m);
  };
  for (const auto& c : cves) {
    sqlite3_reset(up.s);
    up.text(1, c.id);
    sqlite3_bind_int64(up.s, 2, c.published);
    sqlite3_bind_int64(up.s, 3, c.modified);
    if (c.cvss) sqlite3_bind_double(up.s, 4, *c.cvss);
    else sqlite3_bind_null(up.s, 4);
    up.text(5, c.severity);
    up.text(6, c.vector);
    up.text(7, nlohmann::json(c.cwes).dump());
    up.text(8, c.summary);
    up.text(9, c.status);
    if (sqlite3_step(up.s) != SQLITE_DONE) return fail("upsert cve");
    sqlite3_reset(del.s);
    del.text(1, c.id);
    if (sqlite3_step(del.s) != SQLITE_DONE) return fail("delete cpe");
    for (const auto& m : c.cpes) {
      sqlite3_reset(ins.s);
      ins.text(1, c.id);
      ins.text(2, m.vendor);
      ins.text(3, m.product);
      ins.text(4, m.version);
      ins.text(5, m.start_incl);
      ins.text(6, m.start_excl);
      ins.text(7, m.end_incl);
      ins.text(8, m.end_excl);
      if (sqlite3_step(ins.s) != SQLITE_DONE) return fail("insert cpe");
    }
  }
  return exec("COMMIT");
}

Result<bool> VulnDb::applyKev(const std::vector<KevEntry>& entries) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (entries.empty()) return true;
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  Stmt up(db_,
          "INSERT INTO cve(id,summary,cwes,kev,kev_added,kev_due,kev_action,kev_ransomware) VALUES(?,?,?,1,?,?,?,?) "
          "ON CONFLICT(id) DO UPDATE SET kev=1, kev_added=excluded.kev_added, kev_due=excluded.kev_due, kev_action=excluded.kev_action, "
          "kev_ransomware=excluded.kev_ransomware, "
          "summary=CASE WHEN cve.summary='' THEN excluded.summary ELSE cve.summary END, "
          "cwes=CASE WHEN cve.cwes='[]' THEN excluded.cwes ELSE cve.cwes END");
  for (const auto& k : entries) {
    sqlite3_reset(up.s);
    up.text(1, k.cve);
    up.text(2, k.name.empty() ? k.description : k.name + ": " + k.description);
    up.text(3, nlohmann::json(k.cwes).dump());
    sqlite3_bind_int64(up.s, 4, k.added);
    sqlite3_bind_int64(up.s, 5, k.due);
    up.text(6, k.action);
    sqlite3_bind_int(up.s, 7, k.ransomware ? 1 : 0);
    if (sqlite3_step(up.s) != SQLITE_DONE) {
      const std::string m = sqlite3_errmsg(db_);
      exec("ROLLBACK");
      return err("apply kev: " + m);
    }
  }
  return exec("COMMIT");
}

Result<bool> VulnDb::upsertCwes(const std::vector<CweRecord>& cwes, int64_t fetched_at) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (cwes.empty()) return true;
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  Stmt up(db_,
          "INSERT INTO cwe(id,name,description,status,likelihood,fetched) VALUES(?,?,?,?,?,?) "
          "ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, status=excluded.status, likelihood=excluded.likelihood, fetched=excluded.fetched");
  const int64_t now = fetched_at ? fetched_at : static_cast<int64_t>(std::time(nullptr));
  for (const auto& c : cwes) {
    sqlite3_reset(up.s);
    up.text(1, c.id);
    up.text(2, c.name);
    up.text(3, c.description.substr(0, 1500));
    up.text(4, c.status);
    up.text(5, c.likelihood);
    sqlite3_bind_int64(up.s, 6, now);
    if (sqlite3_step(up.s) != SQLITE_DONE) {
      const std::string m = sqlite3_errmsg(db_);
      exec("ROLLBACK");
      return err("upsert cwe: " + m);
    }
  }
  return exec("COMMIT");
}

Result<std::optional<CveRow>> VulnDb::getCve(const std::string& id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kCveCols + " FROM cve WHERE id=?").c_str());
  q.text(1, id);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<CveRow>{};
  if (rc != SQLITE_ROW) return err(std::string("get cve: ") + sqlite3_errmsg(db_));
  return std::optional<CveRow>(rowFrom(q.s));
}

Result<std::vector<CveRow>> VulnDb::searchCves(const std::string& text, size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kCveCols + " FROM cve WHERE id LIKE ?1 OR summary LIKE ?1 ORDER BY kev DESC, modified DESC LIMIT ?2").c_str());
  q.text(1, "%" + text + "%");
  sqlite3_bind_int64(q.s, 2, static_cast<int64_t>(limit));
  std::vector<CveRow> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) out.push_back(rowFrom(q.s));
  return out;
}

Result<std::vector<CpeRow>> VulnDb::cpeByProduct(const std::string& product) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT cve_id,vendor,product,version,v_start_incl,v_start_excl,v_end_incl,v_end_excl FROM cpe_match WHERE product=?");
  q.text(1, product);
  std::vector<CpeRow> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) {
    CpeRow r;
    r.cve_id = col(q.s, 0);
    r.vendor = col(q.s, 1);
    r.product = col(q.s, 2);
    r.version = col(q.s, 3);
    r.start_incl = col(q.s, 4);
    r.start_excl = col(q.s, 5);
    r.end_incl = col(q.s, 6);
    r.end_excl = col(q.s, 7);
    out.push_back(std::move(r));
  }
  return out;
}

Result<std::optional<CweRecord>> VulnDb::getCwe(const std::string& id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT id,name,description,status,likelihood FROM cwe WHERE id=?");
  q.text(1, id);
  if (sqlite3_step(q.s) != SQLITE_ROW) return std::optional<CweRecord>{};
  CweRecord c;
  c.id = col(q.s, 0);
  c.name = col(q.s, 1);
  c.description = col(q.s, 2);
  c.status = col(q.s, 3);
  c.likelihood = col(q.s, 4);
  return std::optional<CweRecord>(std::move(c));
}

Result<std::vector<std::string>> VulnDb::cweIdsToFetch(int64_t now, int64_t max_age, size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  // every CWE mentioned by a stored CVE (the JSON arrays are tiny: scan them in code)
  std::set<std::string> wanted;
  {
    Stmt q(db_, "SELECT DISTINCT cwes FROM cve WHERE cwes != '[]'");
    while (sqlite3_step(q.s) == SQLITE_ROW) {
      const auto j = nlohmann::json::parse(col(q.s, 0), nullptr, false);
      if (j.is_array()) for (const auto& c : j) if (c.is_string()) wanted.insert(c.get<std::string>());
    }
  }
  std::vector<std::string> out;
  Stmt have(db_, "SELECT fetched FROM cwe WHERE id=?");
  for (const auto& id : wanted) {
    sqlite3_reset(have.s);
    have.text(1, id);
    const bool known = sqlite3_step(have.s) == SQLITE_ROW;
    if (!known || now - sqlite3_column_int64(have.s, 0) > max_age) out.push_back(id);
    if (out.size() >= limit) break;
  }
  return out;
}

Result<std::vector<std::string>> VulnDb::kevAddedSince(int64_t ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT id FROM cve WHERE kev=1 AND kev_added>=? ORDER BY kev_added DESC");
  sqlite3_bind_int64(q.s, 1, ts);
  std::vector<std::string> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) out.emplace_back(col(q.s, 0));
  return out;
}

Result<std::optional<VulnDb::OsvCache>> VulnDb::getOsvCache(const std::string& eco, const std::string& name, const std::string& version) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT queried,vulns FROM osv_cache WHERE eco=? AND name=? AND version=?");
  q.text(1, eco);
  q.text(2, name);
  q.text(3, version);
  if (sqlite3_step(q.s) != SQLITE_ROW) return std::optional<OsvCache>{};
  OsvCache c;
  c.queried = sqlite3_column_int64(q.s, 0);
  const auto j = nlohmann::json::parse(col(q.s, 1), nullptr, false);
  if (j.is_array()) c.vuln_ids = j.get<std::vector<std::string>>();
  return std::optional<OsvCache>(std::move(c));
}

Result<bool> VulnDb::putOsvCache(const std::string& eco, const std::string& name, const std::string& version, int64_t queried, const std::vector<std::string>& ids) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt u(db_, "INSERT INTO osv_cache(eco,name,version,queried,vulns) VALUES(?,?,?,?,?) ON CONFLICT(eco,name,version) DO UPDATE SET queried=excluded.queried, vulns=excluded.vulns");
  u.text(1, eco);
  u.text(2, name);
  u.text(3, version);
  sqlite3_bind_int64(u.s, 4, queried);
  u.text(5, nlohmann::json(ids).dump());
  if (sqlite3_step(u.s) != SQLITE_DONE) return err(std::string("put osv cache: ") + sqlite3_errmsg(db_));
  return true;
}

Result<std::optional<OsvVuln>> VulnDb::getOsvVuln(const std::string& id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT id,modified,published,summary,aliases,cvss_vector,severity_text,withdrawn,fixed FROM osv_vuln WHERE id=?");
  q.text(1, id);
  if (sqlite3_step(q.s) != SQLITE_ROW) return std::optional<OsvVuln>{};
  OsvVuln v;
  v.id = col(q.s, 0);
  v.modified = col(q.s, 1);
  v.published = sqlite3_column_int64(q.s, 2);
  v.summary = col(q.s, 3);
  const auto al = nlohmann::json::parse(col(q.s, 4), nullptr, false);
  if (al.is_array()) v.aliases = al.get<std::vector<std::string>>();
  v.cvss_vector = col(q.s, 5);
  v.severity_text = col(q.s, 6);
  v.withdrawn = sqlite3_column_int(q.s, 7) != 0;
  const auto fx = nlohmann::json::parse(col(q.s, 8), nullptr, false);
  if (fx.is_object()) for (const auto& [k, val] : fx.items()) if (val.is_string()) v.fixed[k] = val.get<std::string>();
  return std::optional<OsvVuln>(std::move(v));
}

Result<bool> VulnDb::putOsvVuln(const OsvVuln& v, int64_t fetched) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt u(db_,
         "INSERT INTO osv_vuln(id,modified,published,summary,aliases,cvss_vector,severity_text,withdrawn,fixed,fetched) VALUES(?,?,?,?,?,?,?,?,?,?) "
         "ON CONFLICT(id) DO UPDATE SET modified=excluded.modified, published=excluded.published, summary=excluded.summary, aliases=excluded.aliases, "
         "cvss_vector=excluded.cvss_vector, severity_text=excluded.severity_text, withdrawn=excluded.withdrawn, fixed=excluded.fixed, fetched=excluded.fetched");
  u.text(1, v.id);
  u.text(2, v.modified);
  sqlite3_bind_int64(u.s, 3, v.published);
  u.text(4, v.summary);
  u.text(5, nlohmann::json(v.aliases).dump());
  u.text(6, v.cvss_vector);
  u.text(7, v.severity_text);
  sqlite3_bind_int(u.s, 8, v.withdrawn ? 1 : 0);
  u.text(9, nlohmann::json(v.fixed).dump());
  sqlite3_bind_int64(u.s, 10, fetched);
  if (sqlite3_step(u.s) != SQLITE_DONE) return err(std::string("put osv vuln: ") + sqlite3_errmsg(db_));
  return true;
}

Result<std::optional<std::string>> VulnDb::getMeta(const std::string& key) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT value FROM meta WHERE key=?");
  q.text(1, key);
  if (sqlite3_step(q.s) != SQLITE_ROW) return std::optional<std::string>{};
  return std::optional<std::string>(col(q.s, 0));
}

Result<bool> VulnDb::setMeta(const std::string& key, const std::string& value) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt u(db_, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
  u.text(1, key);
  u.text(2, value);
  if (sqlite3_step(u.s) != SQLITE_DONE) return err(std::string("set meta: ") + sqlite3_errmsg(db_));
  return true;
}

Result<bool> VulnDb::replaceEpss(const std::vector<EpssRow>& rows) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  auto fail = [this](const std::string& m) {
    const std::string e = sqlite3_errmsg(db_);
    exec("ROLLBACK");
    return err(m + ": " + e);
  };
  if (sqlite3_exec(db_, "DELETE FROM epss", nullptr, nullptr, nullptr) != SQLITE_OK) return fail("clear epss");
  Stmt ins(db_, "INSERT OR REPLACE INTO epss(cve,score,percentile) VALUES(?,?,?)");
  for (const auto& r : rows) {
    sqlite3_reset(ins.s);
    ins.text(1, r.cve);
    sqlite3_bind_double(ins.s, 2, r.score);
    sqlite3_bind_double(ins.s, 3, r.percentile);
    if (sqlite3_step(ins.s) != SQLITE_DONE) return fail("insert epss");
  }
  return exec("COMMIT");
}

Result<std::optional<EpssRow>> VulnDb::getEpss(const std::string& cve) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT cve,score,percentile FROM epss WHERE cve=?");
  q.text(1, cve);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<EpssRow>{};
  if (rc != SQLITE_ROW) return err(std::string("epss lookup: ") + sqlite3_errmsg(db_));
  return std::optional<EpssRow>(EpssRow{col(q.s, 0), sqlite3_column_double(q.s, 1), sqlite3_column_double(q.s, 2)});
}

Result<VulnDb::Stats> VulnDb::stats() {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stats s;
  auto one = [&](const char* sql) {
    Stmt q(db_, sql);
    return sqlite3_step(q.s) == SQLITE_ROW ? sqlite3_column_int64(q.s, 0) : 0;
  };
  s.cves = one("SELECT COUNT(*) FROM cve");
  s.kev = one("SELECT COUNT(*) FROM cve WHERE kev=1");
  s.cwes = one("SELECT COUNT(*) FROM cwe WHERE name != ''");
  s.cpe_rows = one("SELECT COUNT(*) FROM cpe_match");
  s.osv_vulns = one("SELECT COUNT(*) FROM osv_vuln");
  s.epss = one("SELECT COUNT(*) FROM epss");
  return s;
}

}  // namespace agent
