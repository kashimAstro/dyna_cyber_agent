// Store methods added with the correlation features (package events, incidents, logins, connections).
// Kept apart from store.cpp so that file stays about snapshots, baselines and findings.
#include <sqlite3.h>

#include <algorithm>
#include <set>

#include "store/store.h"

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

constexpr size_t kMaxPathsPerPackage = 600;

}  // namespace

const char* storeExtSchema() {
  return R"(
CREATE TABLE IF NOT EXISTS pkg_events (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  ts INTEGER NOT NULL,
  package TEXT NOT NULL,
  kind TEXT NOT NULL,
  old_version TEXT NOT NULL DEFAULT '',
  new_version TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_pkg_events ON pkg_events(target, ts);
CREATE TABLE IF NOT EXISTS pkg_files (
  target TEXT NOT NULL,
  path TEXT NOT NULL,
  package TEXT NOT NULL,
  changed_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (target, path)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_pkg_files_pkg ON pkg_files(target, package);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  first_ts INTEGER NOT NULL,
  last_ts INTEGER NOT NULL,
  severity INTEGER NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  targets TEXT NOT NULL DEFAULT '[]',
  entities TEXT NOT NULL DEFAULT '[]',
  stages TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS incident_findings (
  finding_id INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_findings ON incident_findings(incident_id);
CREATE TABLE IF NOT EXISTS login_history (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  user TEXT NOT NULL,
  ts INTEGER NOT NULL,
  ip TEXT NOT NULL,
  cc TEXT NOT NULL DEFAULT '',
  lat REAL NOT NULL DEFAULT 0,
  lon REAL NOT NULL DEFAULT 0,
  located INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_login_history ON login_history(user, ts);
CREATE TABLE IF NOT EXISTS conn_events (
  target TEXT NOT NULL,
  dest TEXT NOT NULL,
  port INTEGER NOT NULL,
  comm TEXT NOT NULL DEFAULT '',
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conn_events ON conn_events(target, dest, port, ts);
)";
}

Result<std::optional<int64_t>> Store::firstSeenOf(const std::string& fingerprint) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT first_seen FROM findings WHERE fingerprint=?");
  q.text(1, fingerprint);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<int64_t>{};
  if (rc != SQLITE_ROW) return err(std::string("first_seen: ") + sqlite3_errmsg(db_));
  return std::optional<int64_t>(sqlite3_column_int64(q.s, 0));
}

Result<bool> Store::integrityFlagged(const std::string& target, const std::string& path) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT 1 FROM findings WHERE target=? AND collector='integrity' AND status='open' AND instr(details, ?) > 0 LIMIT 1");
  q.text(1, target);
  q.text(2, nlohmann::json(path).dump());  // the path as it appears inside the stored JSON, quotes included
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_ROW) return true;
  if (rc == SQLITE_DONE) return false;
  return err(std::string("integrity lookup: ") + sqlite3_errmsg(db_));
}

// ---- packages ---------------------------------------------------------------------------------------------------

Result<bool> Store::recordPackageData(const std::string& target, const std::vector<PackageEvent>& events, const std::vector<PackageFiles>& files) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (events.empty() && files.empty()) return true;
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  auto fail = [this](const std::string& m) {
    const std::string e = sqlite3_errmsg(db_);
    exec("ROLLBACK");
    return err(m + ": " + e);
  };
  Stmt ev(db_, "INSERT INTO pkg_events(target,ts,package,kind,old_version,new_version) VALUES(?,?,?,?,?,?)");
  for (const auto& e : events) {
    sqlite3_reset(ev.s);
    ev.text(1, target);
    sqlite3_bind_int64(ev.s, 2, e.ts);
    ev.text(3, e.package);
    ev.text(4, e.kind);
    ev.text(5, e.old_version);
    ev.text(6, e.new_version);
    if (sqlite3_step(ev.s) != SQLITE_DONE) return fail("insert package event");
  }
  Stmt del(db_, "DELETE FROM pkg_files WHERE target=? AND package=?");
  Stmt ins(db_, "INSERT OR REPLACE INTO pkg_files(target,path,package,changed_at) VALUES(?,?,?,?)");
  for (const auto& f : files) {
    sqlite3_reset(del.s);
    del.text(1, target);
    del.text(2, f.package);
    if (sqlite3_step(del.s) != SQLITE_DONE) return fail("clear package files");
    size_t n = 0;
    for (const auto& p : f.paths) {
      if (++n > kMaxPathsPerPackage) break;
      sqlite3_reset(ins.s);
      ins.text(1, target);
      ins.text(2, p);
      ins.text(3, f.package);
      sqlite3_bind_int64(ins.s, 4, f.ts);
      if (sqlite3_step(ins.s) != SQLITE_DONE) return fail("insert package file");
    }
  }
  return exec("COMMIT");
}

Result<std::optional<Store::PackageOwner>> Store::packageOwning(const std::string& target, const std::string& path) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT package, changed_at FROM pkg_files WHERE target=? AND path=?");
  q.text(1, target);
  q.text(2, path);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<PackageOwner>{};
  if (rc != SQLITE_ROW) return err(std::string("package owner: ") + sqlite3_errmsg(db_));
  return std::optional<PackageOwner>(PackageOwner{col(q.s, 0), sqlite3_column_int64(q.s, 1)});
}

Result<std::optional<Store::PackageEvent>> Store::lastPackageEvent(const std::string& target, const std::string& package) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT ts,package,kind,old_version,new_version FROM pkg_events WHERE target=? AND package=? ORDER BY ts DESC, id DESC LIMIT 1");
  q.text(1, target);
  q.text(2, package);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<PackageEvent>{};
  if (rc != SQLITE_ROW) return err(std::string("last package event: ") + sqlite3_errmsg(db_));
  return std::optional<PackageEvent>(PackageEvent{sqlite3_column_int64(q.s, 0), col(q.s, 1), col(q.s, 2), col(q.s, 3), col(q.s, 4)});
}

Result<std::vector<Store::PackageEvent>> Store::packageEvents(const std::string& target, int64_t since, size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT ts,package,kind,old_version,new_version FROM pkg_events WHERE (?1='' OR target=?1) AND ts>=?2 ORDER BY ts DESC, id DESC LIMIT ?3");
  q.text(1, target);
  sqlite3_bind_int64(q.s, 2, since);
  sqlite3_bind_int64(q.s, 3, static_cast<int64_t>(limit));
  std::vector<PackageEvent> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) out.push_back({sqlite3_column_int64(q.s, 0), col(q.s, 1), col(q.s, 2), col(q.s, 3), col(q.s, 4)});
  return out;
}

Result<size_t> Store::packageFileCount(const std::string& target) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT COUNT(*) FROM pkg_files WHERE target=?");
  q.text(1, target);
  if (sqlite3_step(q.s) != SQLITE_ROW) return err(std::string("package files: ") + sqlite3_errmsg(db_));
  return static_cast<size_t>(sqlite3_column_int64(q.s, 0));
}

Result<std::optional<int64_t>> Store::facetFirstSeen(const std::string& target, const std::string& facet) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT MIN(first_seen) FROM baseline WHERE target=? AND facet=?");
  q.text(1, target);
  q.text(2, facet);
  if (sqlite3_step(q.s) != SQLITE_ROW) return err(std::string("facet first seen: ") + sqlite3_errmsg(db_));
  if (sqlite3_column_type(q.s, 0) == SQLITE_NULL) return std::optional<int64_t>{};
  return std::optional<int64_t>(sqlite3_column_int64(q.s, 0));
}

// ---- baseline contents ------------------------------------------------------------------------------------------

Result<std::vector<Identity>> Store::baselineOf(const std::string& target, const std::vector<std::string>& facets) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  std::vector<Identity> out;
  Stmt q(db_, "SELECT key FROM baseline WHERE target=? AND facet=?");
  for (const auto& f : facets) {
    sqlite3_reset(q.s);
    q.text(1, target);
    q.text(2, f);
    while (sqlite3_step(q.s) == SQLITE_ROW) out.push_back({f, col(q.s, 0)});
  }
  return out;
}

// ---- incidents --------------------------------------------------------------------------------------------------

Result<int64_t> Store::saveIncident(const IncidentRow& row) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  auto fail = [this](const std::string& m) {
    const std::string e = sqlite3_errmsg(db_);
    exec("ROLLBACK");
    return err(m + ": " + e);
  };
  int64_t id = row.id;
  if (id == 0) {
    Stmt ins(db_, "INSERT INTO incidents(created_at,updated_at,first_ts,last_ts,severity,title,status,targets,entities,stages) VALUES(?,?,?,?,?,?,?,?,?,?)");
    sqlite3_bind_int64(ins.s, 1, row.created_at);
    sqlite3_bind_int64(ins.s, 2, row.updated_at);
    sqlite3_bind_int64(ins.s, 3, row.first_ts);
    sqlite3_bind_int64(ins.s, 4, row.last_ts);
    sqlite3_bind_int(ins.s, 5, static_cast<int>(row.severity));
    ins.text(6, row.title);
    ins.text(7, row.status);
    ins.text(8, row.targets.dump());
    ins.text(9, row.entities.dump());
    ins.text(10, row.stages.dump());
    if (sqlite3_step(ins.s) != SQLITE_DONE) return fail("insert incident");
    id = sqlite3_last_insert_rowid(db_);
  } else {
    Stmt up(db_, "UPDATE incidents SET updated_at=?,first_ts=?,last_ts=?,severity=?,title=?,status=?,targets=?,entities=?,stages=? WHERE id=?");
    sqlite3_bind_int64(up.s, 1, row.updated_at);
    sqlite3_bind_int64(up.s, 2, row.first_ts);
    sqlite3_bind_int64(up.s, 3, row.last_ts);
    sqlite3_bind_int(up.s, 4, static_cast<int>(row.severity));
    up.text(5, row.title);
    up.text(6, row.status);
    up.text(7, row.targets.dump());
    up.text(8, row.entities.dump());
    up.text(9, row.stages.dump());
    sqlite3_bind_int64(up.s, 10, id);
    if (sqlite3_step(up.s) != SQLITE_DONE) return fail("update incident");
  }
  Stmt clear(db_, "DELETE FROM incident_findings WHERE incident_id=?");
  sqlite3_bind_int64(clear.s, 1, id);
  if (sqlite3_step(clear.s) != SQLITE_DONE) return fail("clear incident members");
  Stmt link(db_, "INSERT OR REPLACE INTO incident_findings(finding_id,incident_id) VALUES(?,?)");
  for (int64_t f : row.finding_ids) {
    sqlite3_reset(link.s);
    sqlite3_bind_int64(link.s, 1, f);
    sqlite3_bind_int64(link.s, 2, id);
    if (sqlite3_step(link.s) != SQLITE_DONE) return fail("link incident member");
  }
  if (auto r = exec("COMMIT"); !r) return err(r.error());
  return id;
}

namespace {
Store::IncidentRow incidentFromRow(sqlite3_stmt* s) {
  Store::IncidentRow r;
  r.id = sqlite3_column_int64(s, 0);
  r.created_at = sqlite3_column_int64(s, 1);
  r.updated_at = sqlite3_column_int64(s, 2);
  r.first_ts = sqlite3_column_int64(s, 3);
  r.last_ts = sqlite3_column_int64(s, 4);
  r.severity = static_cast<Severity>(sqlite3_column_int(s, 5));
  r.title = col(s, 6);
  r.status = col(s, 7);
  auto arr = [&](int i) {
    auto j = nlohmann::json::parse(col(s, i), nullptr, false);
    return j.is_array() ? j : nlohmann::json::array();
  };
  r.targets = arr(8);
  r.entities = arr(9);
  r.stages = arr(10);
  return r;
}
constexpr const char* kIncidentCols = "id,created_at,updated_at,first_ts,last_ts,severity,title,status,targets,entities,stages";
}  // namespace

Result<std::optional<Store::IncidentRow>> Store::getIncident(int64_t id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kIncidentCols + " FROM incidents WHERE id=?").c_str());
  sqlite3_bind_int64(q.s, 1, id);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<IncidentRow>{};
  if (rc != SQLITE_ROW) return err(std::string("get incident: ") + sqlite3_errmsg(db_));
  IncidentRow r = incidentFromRow(q.s);
  Stmt m(db_, "SELECT finding_id FROM incident_findings WHERE incident_id=? ORDER BY finding_id");
  sqlite3_bind_int64(m.s, 1, id);
  while (sqlite3_step(m.s) == SQLITE_ROW) r.finding_ids.push_back(sqlite3_column_int64(m.s, 0));
  return std::optional<IncidentRow>(std::move(r));
}

Result<std::vector<Store::IncidentRow>> Store::listIncidents(const std::string& status, size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kIncidentCols + " FROM incidents WHERE (?1='' OR status=?1) ORDER BY last_ts DESC, id DESC LIMIT ?2").c_str());
  q.text(1, status);
  sqlite3_bind_int64(q.s, 2, static_cast<int64_t>(limit));
  std::vector<IncidentRow> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) out.push_back(incidentFromRow(q.s));
  Stmt m(db_, "SELECT finding_id FROM incident_findings WHERE incident_id=? ORDER BY finding_id");
  for (auto& r : out) {
    sqlite3_reset(m.s);
    sqlite3_bind_int64(m.s, 1, r.id);
    while (sqlite3_step(m.s) == SQLITE_ROW) r.finding_ids.push_back(sqlite3_column_int64(m.s, 0));
  }
  return out;
}

Result<std::optional<int64_t>> Store::incidentOfFinding(int64_t finding_id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT incident_id FROM incident_findings WHERE finding_id=?");
  sqlite3_bind_int64(q.s, 1, finding_id);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<int64_t>{};
  if (rc != SQLITE_ROW) return err(std::string("incident of finding: ") + sqlite3_errmsg(db_));
  return std::optional<int64_t>(sqlite3_column_int64(q.s, 0));
}

Result<bool> Store::deleteIncident(int64_t id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  for (const char* sql : {"DELETE FROM incident_findings WHERE incident_id=?", "DELETE FROM incidents WHERE id=?"}) {
    Stmt d(db_, sql);
    sqlite3_bind_int64(d.s, 1, id);
    if (sqlite3_step(d.s) != SQLITE_DONE) return err(std::string("delete incident: ") + sqlite3_errmsg(db_));
  }
  return true;
}

// ---- logins -----------------------------------------------------------------------------------------------------

Result<bool> Store::recordLogin(const LoginRecord& r) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt ins(db_, "INSERT INTO login_history(target,user,ts,ip,cc,lat,lon,located) VALUES(?,?,?,?,?,?,?,?)");
  ins.text(1, r.target);
  ins.text(2, r.user);
  sqlite3_bind_int64(ins.s, 3, r.ts);
  ins.text(4, r.ip);
  ins.text(5, r.cc);
  sqlite3_bind_double(ins.s, 6, r.lat);
  sqlite3_bind_double(ins.s, 7, r.lon);
  sqlite3_bind_int(ins.s, 8, r.located ? 1 : 0);
  if (sqlite3_step(ins.s) != SQLITE_DONE) return err(std::string("record login: ") + sqlite3_errmsg(db_));
  return true;
}

Result<std::optional<Store::LoginRecord>> Store::lastLocatedLogin(const std::string& user, int64_t before_ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT ts,target,user,ip,cc,lat,lon FROM login_history WHERE user=? AND located=1 AND ts<? ORDER BY ts DESC, id DESC LIMIT 1");
  q.text(1, user);
  sqlite3_bind_int64(q.s, 2, before_ts);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<LoginRecord>{};
  if (rc != SQLITE_ROW) return err(std::string("last login: ") + sqlite3_errmsg(db_));
  LoginRecord r;
  r.ts = sqlite3_column_int64(q.s, 0);
  r.target = col(q.s, 1);
  r.user = col(q.s, 2);
  r.ip = col(q.s, 3);
  r.cc = col(q.s, 4);
  r.lat = sqlite3_column_double(q.s, 5);
  r.lon = sqlite3_column_double(q.s, 6);
  r.located = true;
  return std::optional<LoginRecord>(std::move(r));
}

// ---- outbound connections ---------------------------------------------------------------------------------------

Result<bool> Store::recordConnections(const std::string& target, const std::vector<ConnEvent>& events) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (events.empty()) return true;
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  Stmt ins(db_, "INSERT INTO conn_events(target,dest,port,comm,ts) VALUES(?,?,?,?,?)");
  for (const auto& e : events) {
    sqlite3_reset(ins.s);
    ins.text(1, target);
    ins.text(2, e.dest);
    sqlite3_bind_int(ins.s, 3, e.port);
    ins.text(4, e.comm);
    sqlite3_bind_int64(ins.s, 5, e.ts);
    if (sqlite3_step(ins.s) != SQLITE_DONE) {
      const std::string m = sqlite3_errmsg(db_);
      exec("ROLLBACK");
      return err("record connection: " + m);
    }
  }
  return exec("COMMIT");
}

Result<std::vector<Store::ConnSeries>> Store::connectionSeries(const std::string& target, int64_t since, size_t min_events) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT dest,port,comm,ts FROM conn_events WHERE target=? AND ts>=? ORDER BY dest, port, ts");
  q.text(1, target);
  sqlite3_bind_int64(q.s, 2, since);
  std::vector<ConnSeries> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) {
    const std::string dest = col(q.s, 0);
    const int port = sqlite3_column_int(q.s, 1);
    if (out.empty() || out.back().dest != dest || out.back().port != port) {
      out.push_back({});
      out.back().dest = dest;
      out.back().port = port;
    }
    out.back().comm = col(q.s, 2);
    out.back().times.push_back(sqlite3_column_int64(q.s, 3));
  }
  out.erase(std::remove_if(out.begin(), out.end(), [&](const ConnSeries& s) { return s.times.size() < min_events; }), out.end());
  return out;
}

}  // namespace agent
