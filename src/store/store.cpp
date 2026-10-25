#include "store/store.h"

#include <sqlite3.h>

#include <ctime>
#include <set>

namespace agent {

const char* storeExtSchema();  // store_ext.cpp

namespace {

struct Stmt {
  sqlite3_stmt* s = nullptr;
  Stmt(sqlite3* db, const char* sql) { sqlite3_prepare_v2(db, sql, -1, &s, nullptr); }
  ~Stmt() { sqlite3_finalize(s); }
  Stmt(const Stmt&) = delete;
  Stmt& operator=(const Stmt&) = delete;
  void text(int i, const std::string& v) { sqlite3_bind_text(s, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT); }
};

const char* kSchema = R"(
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  collector TEXT NOT NULL,
  ts INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  warnings TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_snapshots_lookup ON snapshots(target, collector, ts);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY,
  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  key TEXT NOT NULL,
  tags TEXT NOT NULL DEFAULT '',
  data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_snapshot ON observations(snapshot_id);
CREATE TABLE IF NOT EXISTS baseline_meta (
  target TEXT PRIMARY KEY,
  started_at INTEGER NOT NULL,
  locked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS baseline (
  target TEXT NOT NULL,
  facet TEXT NOT NULL,
  key TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (target, facet, key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  rule_id TEXT NOT NULL,
  severity INTEGER NOT NULL,
  title TEXT NOT NULL,
  target TEXT NOT NULL,
  collector TEXT NOT NULL,
  obs_type TEXT NOT NULL,
  stable_key TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  occurrences INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'open',
  details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, severity);
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  model TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL,
  overall_risk INTEGER NOT NULL,
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  finding_ids TEXT NOT NULL DEFAULT '[]',
  correlations TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS assessments (
  id INTEGER PRIMARY KEY,
  analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  finding_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  verdict TEXT NOT NULL,
  risk INTEGER NOT NULL,
  confidence INTEGER NOT NULL,
  explanation TEXT NOT NULL,
  details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assessments_finding ON assessments(finding_id, created_at);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  subject TEXT NOT NULL,
  recipients TEXT NOT NULL,
  status TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  finding_ids TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_notifications_kind ON notifications(kind, status, created_at);
CREATE TABLE IF NOT EXISTS alerts (
  finding_id INTEGER PRIMARY KEY,
  notification_id INTEGER NOT NULL,
  sent_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS source_days (
  ip TEXT NOT NULL,
  target TEXT NOT NULL,
  day TEXT NOT NULL,
  first_ts INTEGER NOT NULL,
  last_ts INTEGER NOT NULL,
  ssh_fail INTEGER NOT NULL DEFAULT 0,
  ssh_ok INTEGER NOT NULL DEFAULT 0,
  scans INTEGER NOT NULL DEFAULT 0,
  web_hits INTEGER NOT NULL DEFAULT 0,
  web_4xx INTEGER NOT NULL DEFAULT 0,
  users TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (ip, target, day)
);
CREATE INDEX IF NOT EXISTS idx_source_days_ts ON source_days(last_ts);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
)";

std::string joinTags(const std::vector<std::string>& t) {
  std::string s;
  for (size_t i = 0; i < t.size(); ++i) s += (i ? "," : "") + t[i];
  return s;
}

std::vector<std::string> splitTags(const std::string& s) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < s.size()) {
    size_t j = s.find(',', i);
    if (j == std::string::npos) j = s.size();
    if (j > i) out.push_back(s.substr(i, j - i));
    i = j + 1;
  }
  return out;
}

nlohmann::json detailsOf(const Finding& f) {
  nlohmann::json d = {{"description", f.description}, {"remediation", f.remediation}, {"mitre", f.mitre}, {"cwe", f.cwe},
                      {"obs_key", f.obs_key},         {"tags", f.tags},               {"evidence", f.evidence}};
  d["drift"] = nlohmann::json::array();
  for (const auto& i : f.drift) d["drift"].push_back({{"facet", i.facet}, {"key", i.key}});
  return d;
}

const char* col(sqlite3_stmt* s, int i) {
  const auto* t = sqlite3_column_text(s, i);
  return t ? reinterpret_cast<const char*>(t) : "";
}

// Column order: id,fingerprint,rule_id,severity,title,target,collector,obs_type,stable_key,first_seen,last_seen,occurrences,status,details
constexpr const char* kFindingCols =
    "id,fingerprint,rule_id,severity,title,target,collector,obs_type,stable_key,first_seen,last_seen,occurrences,status,details";

Finding findingFromRow(sqlite3_stmt* s) {
  Finding f;
  f.id = sqlite3_column_int64(s, 0);
  f.fingerprint = col(s, 1);
  f.rule_id = col(s, 2);
  f.severity = static_cast<Severity>(sqlite3_column_int(s, 3));
  f.title = col(s, 4);
  f.target = col(s, 5);
  f.collector = col(s, 6);
  f.obs_type = col(s, 7);
  f.stable_key = col(s, 8);
  f.first_seen = sqlite3_column_int64(s, 9);
  f.last_seen = sqlite3_column_int64(s, 10);
  f.occurrences = sqlite3_column_int64(s, 11);
  f.status = col(s, 12);
  const auto d = nlohmann::json::parse(col(s, 13), nullptr, false);
  if (d.is_object()) {
    f.description = d.value("description", "");
    f.remediation = d.value("remediation", "");
    f.obs_key = d.value("obs_key", "");
    if (d.contains("mitre")) f.mitre = d["mitre"].get<std::vector<std::string>>();
    if (d.contains("cwe")) f.cwe = d["cwe"].get<std::vector<std::string>>();
    if (d.contains("tags")) f.tags = d["tags"].get<std::vector<std::string>>();
    if (d.contains("evidence")) f.evidence = d["evidence"];
    if (d.contains("drift")) for (const auto& i : d["drift"]) f.drift.push_back({i.value("facet", ""), i.value("key", "")});
  }
  return f;
}

}  // namespace

Result<std::unique_ptr<Store>> Store::open(const std::string& path) {
  sqlite3* db = nullptr;
  if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
    std::string m = db ? sqlite3_errmsg(db) : "out of memory";
    sqlite3_close(db);
    return err("cannot open database '" + path + "': " + m);
  }
  std::unique_ptr<Store> st(new Store(db));
  st->path_ = path;
  sqlite3_busy_timeout(db, 5000);
  for (const char* sql : {"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA foreign_keys=ON", kSchema, storeExtSchema()}) {
    if (auto r = st->exec(sql); !r) return err(r.error());
  }
  // Schema migrations for databases created by older versions (errors mean "already there").
  st->exec("ALTER TABLE findings ADD COLUMN resolved_at INTEGER NOT NULL DEFAULT 0");
  st->exec("ALTER TABLE notifications ADD COLUMN summary TEXT NOT NULL DEFAULT ''");
  return st;
}

Store::~Store() { sqlite3_close(db_); }

Result<bool> Store::exec(const char* sql) {
  char* msg = nullptr;
  if (sqlite3_exec(db_, sql, nullptr, nullptr, &msg) != SQLITE_OK) {
    std::string m = msg ? msg : "unknown error";
    sqlite3_free(msg);
    return err("sqlite: " + m);
  }
  return true;
}

Result<int64_t> Store::save(const Snapshot& s) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  auto fail = [this](const std::string& m) {
    exec("ROLLBACK");
    return err(m + ": " + sqlite3_errmsg(db_));
  };

  Stmt ins(db_, "INSERT INTO snapshots(target,collector,ts,duration_ms,error,warnings) VALUES(?,?,?,?,?,?)");
  ins.text(1, s.target);
  ins.text(2, s.collector);
  sqlite3_bind_int64(ins.s, 3, s.ts);
  sqlite3_bind_int64(ins.s, 4, s.duration_ms);
  ins.text(5, s.error);
  ins.text(6, nlohmann::json(s.warnings).dump());
  if (sqlite3_step(ins.s) != SQLITE_DONE) return fail("insert snapshot");
  const int64_t id = sqlite3_last_insert_rowid(db_);

  Stmt obs(db_, "INSERT INTO observations(snapshot_id,type,key,tags,data) VALUES(?,?,?,?,?)");
  for (const auto& o : s.observations) {
    sqlite3_reset(obs.s);
    sqlite3_bind_int64(obs.s, 1, id);
    obs.text(2, o.type);
    obs.text(3, o.key);
    obs.text(4, joinTags(o.tags));
    obs.text(5, o.data.dump());
    if (sqlite3_step(obs.s) != SQLITE_DONE) return fail("insert observation");
  }
  if (auto r = exec("COMMIT"); !r) return err(r.error());
  return id;
}

Result<std::optional<Snapshot>> Store::latest(const std::string& target, const std::string& collector) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT id,ts,duration_ms,warnings FROM snapshots WHERE target=? AND collector=? AND error='' ORDER BY ts DESC, id DESC LIMIT 1");
  q.text(1, target);
  q.text(2, collector);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<Snapshot>{};
  if (rc != SQLITE_ROW) return err(std::string("query snapshot: ") + sqlite3_errmsg(db_));

  Snapshot s;
  s.id = sqlite3_column_int64(q.s, 0);
  s.target = target;
  s.collector = collector;
  s.ts = sqlite3_column_int64(q.s, 1);
  s.duration_ms = sqlite3_column_int64(q.s, 2);
  const auto w = nlohmann::json::parse(reinterpret_cast<const char*>(sqlite3_column_text(q.s, 3)), nullptr, false);
  if (w.is_array()) s.warnings = w.get<std::vector<std::string>>();

  Stmt o(db_, "SELECT type,key,tags,data FROM observations WHERE snapshot_id=? ORDER BY id");
  sqlite3_bind_int64(o.s, 1, s.id);
  while (sqlite3_step(o.s) == SQLITE_ROW) {
    Observation ob;
    ob.type = reinterpret_cast<const char*>(sqlite3_column_text(o.s, 0));
    ob.key = reinterpret_cast<const char*>(sqlite3_column_text(o.s, 1));
    ob.tags = splitTags(reinterpret_cast<const char*>(sqlite3_column_text(o.s, 2)));
    ob.data = nlohmann::json::parse(reinterpret_cast<const char*>(sqlite3_column_text(o.s, 3)), nullptr, false);
    s.observations.push_back(std::move(ob));
  }
  return std::optional<Snapshot>(std::move(s));
}

Result<size_t> Store::prune(int64_t older_than_ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt d(db_, "DELETE FROM snapshots WHERE ts < ?");
  sqlite3_bind_int64(d.s, 1, older_than_ts);
  if (sqlite3_step(d.s) != SQLITE_DONE) return err(std::string("prune: ") + sqlite3_errmsg(db_));
  const size_t n = static_cast<size_t>(sqlite3_changes(db_));
  Stmt sd(db_, "DELETE FROM source_days WHERE last_ts < ?");  // the attack history is kept far longer than snapshots
  sqlite3_bind_int64(sd.s, 1, older_than_ts - 400LL * 86400);
  sqlite3_step(sd.s);
  for (const auto& [sql, extra] : std::initializer_list<std::pair<const char*, int64_t>>{
           {"DELETE FROM conn_events WHERE ts < ?", 0},                  // only recent history matters for beaconing
           {"DELETE FROM login_history WHERE ts < ?", -386LL * 86400},   // a year of logins feeds "usual country / hour"
           {"DELETE FROM pkg_events WHERE ts < ?", -76LL * 86400},
           {"DELETE FROM incidents WHERE status='resolved' AND updated_at < ?", -16LL * 86400}}) {
    Stmt del(db_, sql);
    sqlite3_bind_int64(del.s, 1, older_than_ts + extra);
    sqlite3_step(del.s);
  }
  exec("DELETE FROM incident_findings WHERE incident_id NOT IN (SELECT id FROM incidents)");
  return n;
}

Result<Store::BaselineMeta> Store::baselineMeta(const std::string& target, int64_t now) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  {
    Stmt ins(db_, "INSERT OR IGNORE INTO baseline_meta(target,started_at,locked) VALUES(?,?,0)");
    ins.text(1, target);
    sqlite3_bind_int64(ins.s, 2, now);
    if (sqlite3_step(ins.s) != SQLITE_DONE) return err(std::string("baseline_meta insert: ") + sqlite3_errmsg(db_));
  }
  Stmt q(db_, "SELECT started_at,locked FROM baseline_meta WHERE target=?");
  q.text(1, target);
  if (sqlite3_step(q.s) != SQLITE_ROW) return err(std::string("baseline_meta read: ") + sqlite3_errmsg(db_));
  return BaselineMeta{sqlite3_column_int64(q.s, 0), sqlite3_column_int(q.s, 1) != 0};
}

Result<bool> Store::lockBaseline(const std::string& target, int64_t now) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (auto m = baselineMeta(target, now); !m) return err(m.error());
  Stmt u(db_, "UPDATE baseline_meta SET locked=1 WHERE target=?");
  u.text(1, target);
  if (sqlite3_step(u.s) != SQLITE_DONE) return err(std::string("lock baseline: ") + sqlite3_errmsg(db_));
  return true;
}

Result<bool> Store::inBaseline(const std::string& target, const Identity& id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT 1 FROM baseline WHERE target=? AND facet=? AND key=?");
  q.text(1, target);
  q.text(2, id.facet);
  q.text(3, id.key);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_ROW) return true;
  if (rc == SQLITE_DONE) return false;
  return err(std::string("baseline lookup: ") + sqlite3_errmsg(db_));
}

Result<bool> Store::addToBaseline(const std::string& target, const std::vector<Identity>& ids, int64_t ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (ids.empty()) return true;
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  Stmt up(db_,
          "INSERT INTO baseline(target,facet,key,first_seen,last_seen) VALUES(?,?,?,?,?) "
          "ON CONFLICT(target,facet,key) DO UPDATE SET last_seen=excluded.last_seen");
  for (const auto& id : ids) {
    sqlite3_reset(up.s);
    up.text(1, target);
    up.text(2, id.facet);
    up.text(3, id.key);
    sqlite3_bind_int64(up.s, 4, ts);
    sqlite3_bind_int64(up.s, 5, ts);
    if (sqlite3_step(up.s) != SQLITE_DONE) {
      const std::string m = sqlite3_errmsg(db_);
      exec("ROLLBACK");
      return err("baseline upsert: " + m);
    }
  }
  return exec("COMMIT");
}

Result<size_t> Store::baselineSize(const std::string& target) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT COUNT(*) FROM baseline WHERE target=?");
  q.text(1, target);
  if (sqlite3_step(q.s) != SQLITE_ROW) return err(std::string("baseline count: ") + sqlite3_errmsg(db_));
  return static_cast<size_t>(sqlite3_column_int64(q.s, 0));
}

Result<Store::UpsertResult> Store::upsertFinding(const Finding& f) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt sel(db_, "SELECT id,status FROM findings WHERE fingerprint=?");
  sel.text(1, f.fingerprint);
  const int rc = sqlite3_step(sel.s);
  if (rc == SQLITE_ROW) {
    UpsertResult r{sqlite3_column_int64(sel.s, 0), false, col(sel.s, 1)};
    const bool reopen = r.status == "resolved";  // it came back
    if (reopen) r.status = "open";
    Stmt u(db_, reopen ? "UPDATE findings SET last_seen=?, occurrences=occurrences+1, severity=?, title=?, details=?, status='open', resolved_at=0 WHERE id=?"
                       : "UPDATE findings SET last_seen=?, occurrences=occurrences+1, severity=?, title=?, details=? WHERE id=?");
    sqlite3_bind_int64(u.s, 1, f.last_seen);
    sqlite3_bind_int(u.s, 2, static_cast<int>(f.severity));
    u.text(3, f.title);
    u.text(4, detailsOf(f).dump());
    sqlite3_bind_int64(u.s, 5, r.id);
    if (sqlite3_step(u.s) != SQLITE_DONE) return err(std::string("update finding: ") + sqlite3_errmsg(db_));
    return r;
  }
  if (rc != SQLITE_DONE) return err(std::string("select finding: ") + sqlite3_errmsg(db_));
  Stmt ins(db_,
           "INSERT INTO findings(fingerprint,rule_id,severity,title,target,collector,obs_type,stable_key,first_seen,last_seen,occurrences,status,details) "
           "VALUES(?,?,?,?,?,?,?,?,?,?,1,'open',?)");
  ins.text(1, f.fingerprint);
  ins.text(2, f.rule_id);
  sqlite3_bind_int(ins.s, 3, static_cast<int>(f.severity));
  ins.text(4, f.title);
  ins.text(5, f.target);
  ins.text(6, f.collector);
  ins.text(7, f.obs_type);
  ins.text(8, f.stable_key);
  sqlite3_bind_int64(ins.s, 9, f.first_seen);
  sqlite3_bind_int64(ins.s, 10, f.last_seen);
  ins.text(11, detailsOf(f).dump());
  if (sqlite3_step(ins.s) != SQLITE_DONE) return err(std::string("insert finding: ") + sqlite3_errmsg(db_));
  return UpsertResult{sqlite3_last_insert_rowid(db_), true, "open"};
}

Result<std::optional<Finding>> Store::getFinding(int64_t id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kFindingCols + " FROM findings WHERE id=?").c_str());
  sqlite3_bind_int64(q.s, 1, id);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<Finding>{};
  if (rc != SQLITE_ROW) return err(std::string("get finding: ") + sqlite3_errmsg(db_));
  return std::optional<Finding>(findingFromRow(q.s));
}

Result<std::vector<Finding>> Store::listFindings(const std::string& status, size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kFindingCols + " FROM findings WHERE (?1='' OR status=?1) ORDER BY severity DESC, last_seen DESC LIMIT ?2").c_str());
  q.text(1, status);
  sqlite3_bind_int64(q.s, 2, static_cast<int64_t>(limit));
  std::vector<Finding> out;
  int rc;
  while ((rc = sqlite3_step(q.s)) == SQLITE_ROW) out.push_back(findingFromRow(q.s));
  if (rc != SQLITE_DONE) return err(std::string("list findings: ") + sqlite3_errmsg(db_));
  return out;
}

Result<std::vector<Finding>> Store::findingsActive(int64_t from, int64_t to, const std::string& target, size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kFindingCols +
               " FROM findings WHERE last_seen>=?1 AND first_seen<=?2 AND (?3='' OR target=?3) AND rule_id != 'LOG-050' "
               "ORDER BY severity DESC, last_seen DESC LIMIT ?4").c_str());
  sqlite3_bind_int64(q.s, 1, from);
  sqlite3_bind_int64(q.s, 2, to);
  q.text(3, target);
  sqlite3_bind_int64(q.s, 4, static_cast<int64_t>(limit));
  std::vector<Finding> out;
  int rc;
  while ((rc = sqlite3_step(q.s)) == SQLITE_ROW) out.push_back(findingFromRow(q.s));
  if (rc != SQLITE_DONE) return err(std::string("findings in period: ") + sqlite3_errmsg(db_));
  return out;
}

Result<std::vector<Finding>> Store::listUnassessed(size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kFindingCols +
               " FROM findings WHERE status='open' AND collector != 'vulns' AND rule_id != 'LOG-050' AND id NOT IN (SELECT finding_id FROM assessments) "
               "ORDER BY severity DESC, last_seen DESC LIMIT ?1").c_str());
  sqlite3_bind_int64(q.s, 1, static_cast<int64_t>(limit));
  std::vector<Finding> out;
  int rc;
  while ((rc = sqlite3_step(q.s)) == SQLITE_ROW) out.push_back(findingFromRow(q.s));
  if (rc != SQLITE_DONE) return err(std::string("list unassessed: ") + sqlite3_errmsg(db_));
  return out;
}

namespace {
nlohmann::json correlationsJson(const std::vector<Correlation>& cs) {
  nlohmann::json arr = nlohmann::json::array();
  for (const auto& c : cs) {
    arr.push_back({{"title", c.title}, {"narrative", c.narrative}, {"risk", static_cast<int>(c.risk)}, {"finding_ids", c.finding_ids}, {"mitre", c.mitre}});
  }
  return arr;
}

Assessment assessmentFromRow(sqlite3_stmt* s) {  // cols: finding_id,created_at,verdict,risk,confidence,explanation,details
  Assessment a;
  a.finding_id = sqlite3_column_int64(s, 0);
  a.created_at = sqlite3_column_int64(s, 1);
  a.verdict = col(s, 2);
  a.risk = static_cast<Severity>(sqlite3_column_int(s, 3));
  a.confidence = sqlite3_column_int(s, 4);
  a.explanation = col(s, 5);
  const auto d = nlohmann::json::parse(col(s, 6), nullptr, false);
  if (d.is_object()) {
    a.recommended_actions = d.value("recommended_actions", std::vector<std::string>{});
    a.additional_checks = d.value("additional_checks", std::vector<std::string>{});
    a.flags = d.value("flags", std::vector<std::string>{});
  }
  return a;
}
}  // namespace

Result<int64_t> Store::saveAnalysis(const Analysis& a) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  auto fail = [this](const std::string& m) {
    const std::string e = sqlite3_errmsg(db_);
    exec("ROLLBACK");
    return err(m + ": " + e);
  };
  Stmt ins(db_, "INSERT INTO analyses(target,created_at,model,summary,overall_risk,prompt_tokens,completion_tokens,finding_ids,correlations) VALUES(?,?,?,?,?,?,?,?,?)");
  ins.text(1, a.target);
  sqlite3_bind_int64(ins.s, 2, a.created_at);
  ins.text(3, a.model);
  ins.text(4, a.summary);
  sqlite3_bind_int(ins.s, 5, static_cast<int>(a.overall_risk));
  sqlite3_bind_int(ins.s, 6, a.prompt_tokens);
  sqlite3_bind_int(ins.s, 7, a.completion_tokens);
  ins.text(8, nlohmann::json(a.finding_ids).dump());
  ins.text(9, correlationsJson(a.correlations).dump());
  if (sqlite3_step(ins.s) != SQLITE_DONE) return fail("insert analysis");
  const int64_t id = sqlite3_last_insert_rowid(db_);

  Stmt as(db_, "INSERT INTO assessments(analysis_id,finding_id,created_at,verdict,risk,confidence,explanation,details) VALUES(?,?,?,?,?,?,?,?)");
  for (const auto& x : a.assessments) {
    sqlite3_reset(as.s);
    sqlite3_bind_int64(as.s, 1, id);
    sqlite3_bind_int64(as.s, 2, x.finding_id);
    sqlite3_bind_int64(as.s, 3, a.created_at);
    as.text(4, x.verdict);
    sqlite3_bind_int(as.s, 5, static_cast<int>(x.risk));
    sqlite3_bind_int(as.s, 6, x.confidence);
    as.text(7, x.explanation);
    as.text(8, nlohmann::json({{"recommended_actions", x.recommended_actions}, {"additional_checks", x.additional_checks}, {"flags", x.flags}}).dump());
    if (sqlite3_step(as.s) != SQLITE_DONE) return fail("insert assessment");
  }
  if (auto r = exec("COMMIT"); !r) return err(r.error());
  return id;
}

Result<std::optional<Assessment>> Store::latestAssessment(int64_t finding_id) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT finding_id,created_at,verdict,risk,confidence,explanation,details FROM assessments WHERE finding_id=? ORDER BY created_at DESC, id DESC LIMIT 1");
  sqlite3_bind_int64(q.s, 1, finding_id);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<Assessment>{};
  if (rc != SQLITE_ROW) return err(std::string("latest assessment: ") + sqlite3_errmsg(db_));
  return std::optional<Assessment>(assessmentFromRow(q.s));
}

Result<std::vector<Analysis>> Store::listAnalysesSince(int64_t ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT id,target,created_at,model,summary,overall_risk,prompt_tokens,completion_tokens,finding_ids,correlations FROM analyses WHERE created_at>=? ORDER BY created_at");
  sqlite3_bind_int64(q.s, 1, ts);
  std::vector<Analysis> out;
  int rc;
  while ((rc = sqlite3_step(q.s)) == SQLITE_ROW) {
    Analysis a;
    a.id = sqlite3_column_int64(q.s, 0);
    a.target = col(q.s, 1);
    a.created_at = sqlite3_column_int64(q.s, 2);
    a.model = col(q.s, 3);
    a.summary = col(q.s, 4);
    a.overall_risk = static_cast<Severity>(sqlite3_column_int(q.s, 5));
    a.prompt_tokens = sqlite3_column_int(q.s, 6);
    a.completion_tokens = sqlite3_column_int(q.s, 7);
    const auto ids = nlohmann::json::parse(col(q.s, 8), nullptr, false);
    if (ids.is_array()) a.finding_ids = ids.get<std::vector<int64_t>>();
    const auto cs = nlohmann::json::parse(col(q.s, 9), nullptr, false);
    if (cs.is_array()) {
      for (const auto& c : cs) {
        Correlation x;
        x.title = c.value("title", "");
        x.narrative = c.value("narrative", "");
        x.risk = static_cast<Severity>(c.value("risk", 0));
        x.finding_ids = c.value("finding_ids", std::vector<int64_t>{});
        x.mitre = c.value("mitre", std::vector<std::string>{});
        a.correlations.push_back(std::move(x));
      }
    }
    out.push_back(std::move(a));
  }
  if (rc != SQLITE_DONE) return err(std::string("list analyses: ") + sqlite3_errmsg(db_));
  for (auto& a : out) {
    Stmt as(db_, "SELECT finding_id,created_at,verdict,risk,confidence,explanation,details FROM assessments WHERE analysis_id=? ORDER BY id");
    sqlite3_bind_int64(as.s, 1, a.id);
    while (sqlite3_step(as.s) == SQLITE_ROW) a.assessments.push_back(assessmentFromRow(as.s));
  }
  return out;
}

Result<std::vector<Finding>> Store::listUnalerted(size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, (std::string("SELECT ") + kFindingCols +
               " FROM findings WHERE status='open' AND id NOT IN (SELECT finding_id FROM alerts) "
               "ORDER BY severity DESC, first_seen ASC LIMIT ?1").c_str());
  sqlite3_bind_int64(q.s, 1, static_cast<int64_t>(limit));
  std::vector<Finding> out;
  int rc;
  while ((rc = sqlite3_step(q.s)) == SQLITE_ROW) out.push_back(findingFromRow(q.s));
  if (rc != SQLITE_DONE) return err(std::string("list unalerted: ") + sqlite3_errmsg(db_));
  return out;
}

Result<bool> Store::markAlerted(const std::vector<int64_t>& ids, int64_t notification_id, int64_t ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (ids.empty()) return true;
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  Stmt ins(db_, "INSERT OR IGNORE INTO alerts(finding_id,notification_id,sent_at) VALUES(?,?,?)");
  for (int64_t id : ids) {
    sqlite3_reset(ins.s);
    sqlite3_bind_int64(ins.s, 1, id);
    sqlite3_bind_int64(ins.s, 2, notification_id);
    sqlite3_bind_int64(ins.s, 3, ts);
    if (sqlite3_step(ins.s) != SQLITE_DONE) {
      const std::string m = sqlite3_errmsg(db_);
      exec("ROLLBACK");
      return err("mark alerted: " + m);
    }
  }
  return exec("COMMIT");
}

Result<int64_t> Store::recordNotification(const Notification& n) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt ins(db_, "INSERT INTO notifications(kind,created_at,subject,recipients,status,error,finding_ids,summary) VALUES(?,?,?,?,?,?,?,?)");
  ins.text(1, n.kind);
  sqlite3_bind_int64(ins.s, 2, n.created_at);
  ins.text(3, n.subject);
  ins.text(4, n.recipients);
  ins.text(5, n.status);
  ins.text(6, n.error);
  ins.text(7, nlohmann::json(n.finding_ids).dump());
  ins.text(8, n.summary);
  if (sqlite3_step(ins.s) != SQLITE_DONE) return err(std::string("record notification: ") + sqlite3_errmsg(db_));
  return sqlite3_last_insert_rowid(db_);
}

Result<std::optional<int64_t>> Store::lastNotificationTime(const std::string& kind, const std::string& status) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT MAX(created_at) FROM notifications WHERE kind=? AND status=?");
  q.text(1, kind);
  q.text(2, status);
  if (sqlite3_step(q.s) != SQLITE_ROW) return err(std::string("last notification: ") + sqlite3_errmsg(db_));
  if (sqlite3_column_type(q.s, 0) == SQLITE_NULL) return std::optional<int64_t>{};
  return std::optional<int64_t>(sqlite3_column_int64(q.s, 0));
}

Result<size_t> Store::countNotifications(const std::string& kind, const std::string& status, int64_t since) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT COUNT(*) FROM notifications WHERE kind=? AND status=? AND created_at>=?");
  q.text(1, kind);
  q.text(2, status);
  sqlite3_bind_int64(q.s, 3, since);
  if (sqlite3_step(q.s) != SQLITE_ROW) return err(std::string("count notifications: ") + sqlite3_errmsg(db_));
  return static_cast<size_t>(sqlite3_column_int64(q.s, 0));
}

Result<std::vector<Store::Notification>> Store::listNotifications(size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT id,kind,created_at,subject,recipients,status,error,finding_ids FROM notifications ORDER BY id DESC LIMIT ?");
  sqlite3_bind_int64(q.s, 1, static_cast<int64_t>(limit));
  std::vector<Notification> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) {
    Notification n;
    n.id = sqlite3_column_int64(q.s, 0);
    n.kind = col(q.s, 1);
    n.created_at = sqlite3_column_int64(q.s, 2);
    n.subject = col(q.s, 3);
    n.recipients = col(q.s, 4);
    n.status = col(q.s, 5);
    n.error = col(q.s, 6);
    const auto ids = nlohmann::json::parse(col(q.s, 7), nullptr, false);
    if (ids.is_array()) n.finding_ids = ids.get<std::vector<int64_t>>();
    out.push_back(std::move(n));
  }
  return out;
}

Result<std::optional<std::string>> Store::getMeta(const std::string& key) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT value FROM meta WHERE key=?");
  q.text(1, key);
  const int rc = sqlite3_step(q.s);
  if (rc == SQLITE_DONE) return std::optional<std::string>{};
  if (rc != SQLITE_ROW) return err(std::string("get meta: ") + sqlite3_errmsg(db_));
  return std::optional<std::string>(col(q.s, 0));
}

Result<bool> Store::setMeta(const std::string& key, const std::string& value) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt u(db_, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
  u.text(1, key);
  u.text(2, value);
  if (sqlite3_step(u.s) != SQLITE_DONE) return err(std::string("set meta: ") + sqlite3_errmsg(db_));
  return true;
}

Result<std::vector<Store::CollectorHealth>> Store::collectorHealth(int64_t since) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_,
         "SELECT target, collector, "
         "COALESCE(MAX(CASE WHEN error='' THEN ts END),0), "
         "COALESCE(MAX(CASE WHEN error!='' THEN ts END),0), "
         "SUM(CASE WHEN error='' THEN 1 ELSE 0 END), SUM(CASE WHEN error!='' THEN 1 ELSE 0 END) "
         "FROM snapshots GROUP BY target, collector ORDER BY target, collector");
  std::vector<CollectorHealth> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) {
    CollectorHealth h;
    h.target = col(q.s, 0);
    h.collector = col(q.s, 1);
    h.last_ok = sqlite3_column_int64(q.s, 2);
    h.last_error_ts = sqlite3_column_int64(q.s, 3);
    h.ok_count = sqlite3_column_int64(q.s, 4);
    h.error_count = sqlite3_column_int64(q.s, 5);
    out.push_back(std::move(h));
  }
  // The window counts and the last error text need a second, windowed pass.
  for (auto& h : out) {
    Stmt w(db_, "SELECT SUM(CASE WHEN error='' THEN 1 ELSE 0 END), SUM(CASE WHEN error!='' THEN 1 ELSE 0 END) FROM snapshots WHERE target=? AND collector=? AND ts>=?");
    w.text(1, h.target);
    w.text(2, h.collector);
    sqlite3_bind_int64(w.s, 3, since);
    if (sqlite3_step(w.s) == SQLITE_ROW) {
      h.ok_count = sqlite3_column_int64(w.s, 0);
      h.error_count = sqlite3_column_int64(w.s, 1);
    }
    if (h.last_error_ts) {
      Stmt e(db_, "SELECT error FROM snapshots WHERE target=? AND collector=? AND error!='' ORDER BY ts DESC, id DESC LIMIT 1");
      e.text(1, h.target);
      e.text(2, h.collector);
      if (sqlite3_step(e.s) == SQLITE_ROW) h.last_error = col(e.s, 0);
    }
  }
  return out;
}

Result<std::vector<std::pair<int64_t, std::string>>> Store::openFingerprints(const std::string& target, const std::string& collector) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT id,fingerprint FROM findings WHERE status='open' AND target=? AND collector=?");
  q.text(1, target);
  q.text(2, collector);
  std::vector<std::pair<int64_t, std::string>> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) out.emplace_back(sqlite3_column_int64(q.s, 0), col(q.s, 1));
  return out;
}

Result<size_t> Store::resolveFindings(const std::vector<int64_t>& ids, int64_t ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (ids.empty()) return static_cast<size_t>(0);
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  Stmt u(db_, "UPDATE findings SET status='resolved', resolved_at=? WHERE id=? AND status='open'");
  size_t n = 0;
  for (int64_t id : ids) {
    sqlite3_reset(u.s);
    sqlite3_bind_int64(u.s, 1, ts);
    sqlite3_bind_int64(u.s, 2, id);
    if (sqlite3_step(u.s) != SQLITE_DONE) {
      const std::string m = sqlite3_errmsg(db_);
      exec("ROLLBACK");
      return err("resolve findings: " + m);
    }
    n += static_cast<size_t>(sqlite3_changes(db_));
  }
  if (auto r = exec("COMMIT"); !r) return err(r.error());
  return n;
}

Result<size_t> Store::countResolvedSince(int64_t ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT COUNT(*) FROM findings WHERE status='resolved' AND resolved_at>=?");
  sqlite3_bind_int64(q.s, 1, ts);
  if (sqlite3_step(q.s) != SQLITE_ROW) return err(std::string("count resolved: ") + sqlite3_errmsg(db_));
  return static_cast<size_t>(sqlite3_column_int64(q.s, 0));
}

Result<std::vector<std::pair<int64_t, std::string>>> Store::recentSummaries(int64_t since, size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  Stmt q(db_, "SELECT created_at,summary FROM notifications WHERE status='sent' AND summary != '' AND created_at>=? ORDER BY created_at DESC LIMIT ?");
  sqlite3_bind_int64(q.s, 1, since);
  sqlite3_bind_int64(q.s, 2, static_cast<int64_t>(limit));
  std::vector<std::pair<int64_t, std::string>> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) out.emplace_back(sqlite3_column_int64(q.s, 0), col(q.s, 1));
  return out;
}

namespace {

std::string dayKey(int64_t ts) {
  const std::time_t t = static_cast<std::time_t>(ts);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char buf[16];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
  return buf;
}

std::vector<std::string> jsonStrings(const std::string& text) {
  std::vector<std::string> out;
  const auto j = nlohmann::json::parse(text, nullptr, false);
  if (j.is_array()) for (const auto& e : j) if (e.is_string()) out.push_back(e.get<std::string>());
  return out;
}

}  // namespace

Result<size_t> Store::recordSources(const std::string& target, const std::vector<SourceDelta>& deltas, int64_t ts) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (deltas.empty()) return size_t(0);
  if (auto r = exec("BEGIN IMMEDIATE"); !r) return err(r.error());
  const std::string day = dayKey(ts);
  Stmt sel(db_, "SELECT users FROM source_days WHERE ip=? AND target=? AND day=?");
  Stmt up(db_,
          "INSERT INTO source_days(ip,target,day,first_ts,last_ts,ssh_fail,ssh_ok,scans,web_hits,web_4xx,users) VALUES(?1,?2,?3,?4,?4,?5,?6,?7,?8,?9,?10) "
          "ON CONFLICT(ip,target,day) DO UPDATE SET last_ts=?4, ssh_fail=ssh_fail+?5, ssh_ok=ssh_ok+?6, scans=scans+?7, web_hits=web_hits+?8, web_4xx=web_4xx+?9, users=?10");
  for (const auto& d : deltas) {
    std::vector<std::string> users = jsonStrings(d.users_json);
    sqlite3_reset(sel.s);
    sel.text(1, d.ip);
    sel.text(2, target);
    sel.text(3, day);
    if (sqlite3_step(sel.s) == SQLITE_ROW) {  // merge the usernames tried today (kept short)
      std::set<std::string> merged(users.begin(), users.end());
      for (auto& u : jsonStrings(reinterpret_cast<const char*>(sqlite3_column_text(sel.s, 0)))) if (merged.size() < 12) merged.insert(u);
      users.assign(merged.begin(), merged.end());
    }
    if (users.size() > 12) users.resize(12);
    sqlite3_reset(up.s);
    up.text(1, d.ip);
    up.text(2, target);
    up.text(3, day);
    sqlite3_bind_int64(up.s, 4, ts);
    sqlite3_bind_int64(up.s, 5, d.ssh_fail);
    sqlite3_bind_int64(up.s, 6, d.ssh_ok);
    sqlite3_bind_int64(up.s, 7, d.scans);
    sqlite3_bind_int64(up.s, 8, d.web_hits);
    sqlite3_bind_int64(up.s, 9, d.web_4xx);
    up.text(10, nlohmann::json(users).dump());
    if (sqlite3_step(up.s) != SQLITE_DONE) {
      const std::string m = sqlite3_errmsg(db_);
      exec("ROLLBACK");
      return err("record sources: " + m);
    }
  }
  if (auto r = exec("COMMIT"); !r) return err(r.error());
  return deltas.size();
}

Result<std::vector<Store::SourceRow>> Store::listSources(int64_t since, const std::string& target, size_t limit) {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  std::string sql =
      "SELECT ip, MIN(first_ts), MAX(last_ts), SUM(ssh_fail), SUM(ssh_ok), SUM(scans), SUM(web_hits), SUM(web_4xx), "
      "GROUP_CONCAT(DISTINCT target), GROUP_CONCAT(users, char(10)) FROM source_days WHERE last_ts>=?1";
  if (!target.empty()) sql += " AND target=?2";
  sql += " GROUP BY ip ORDER BY SUM(ssh_fail)+SUM(ssh_ok)+SUM(scans)+SUM(web_hits)+SUM(web_4xx) DESC, MAX(last_ts) DESC LIMIT ?3";
  Stmt q(db_, sql.c_str());
  sqlite3_bind_int64(q.s, 1, since);
  if (!target.empty()) q.text(2, target);
  sqlite3_bind_int64(q.s, 3, static_cast<int64_t>(limit));
  std::vector<SourceRow> out;
  while (sqlite3_step(q.s) == SQLITE_ROW) {
    SourceRow r;
    r.ip = col(q.s, 0);
    r.first_ts = sqlite3_column_int64(q.s, 1);
    r.last_ts = sqlite3_column_int64(q.s, 2);
    r.ssh_fail = sqlite3_column_int64(q.s, 3);
    r.ssh_ok = sqlite3_column_int64(q.s, 4);
    r.scans = sqlite3_column_int64(q.s, 5);
    r.web_hits = sqlite3_column_int64(q.s, 6);
    r.web_4xx = sqlite3_column_int64(q.s, 7);
    r.targets = splitTags(col(q.s, 8));
    std::set<std::string> users;
    size_t i = 0;
    const std::string all = col(q.s, 9);
    while (i < all.size()) {
      size_t j = all.find('\n', i);
      if (j == std::string::npos) j = all.size();
      for (auto& u : jsonStrings(all.substr(i, j - i))) if (users.size() < 12) users.insert(u);
      i = j + 1;
    }
    r.users.assign(users.begin(), users.end());
    out.push_back(std::move(r));
  }
  return out;
}

Result<size_t> Store::backfillSources() {
  std::lock_guard<std::recursive_mutex> lock(mu_);
  if (auto m = getMeta("sources_backfilled"); m && m.value()) return size_t(0);
  size_t n = 0;
  Stmt q(db_, "SELECT target, obs_type, first_seen, last_seen, details FROM findings WHERE obs_type IN ('log.auth.bruteforce','log.auth.scan','log.web.attack','log.web.scan')");
  struct Row { std::string target; SourceDelta d; int64_t ts; };
  std::vector<Row> rows;
  while (sqlite3_step(q.s) == SQLITE_ROW) {
    const std::string type = col(q.s, 1);
    const auto details = nlohmann::json::parse(col(q.s, 4), nullptr, false);
    const nlohmann::json ev = details.is_object() && details.contains("evidence") ? details["evidence"] : nlohmann::json();
    if (!ev.is_object() || !ev.contains("src_ip") || !ev["src_ip"].is_string()) continue;
    Row r;
    r.target = col(q.s, 0);
    r.ts = sqlite3_column_int64(q.s, 3);
    r.d.ip = ev["src_ip"].get<std::string>();
    if (type == "log.auth.bruteforce") {
      r.d.ssh_fail = ev.value("failures", int64_t(0));
      if (ev.contains("success_user")) r.d.ssh_ok = 1;
      if (ev.contains("users")) r.d.users_json = ev["users"].dump();
    } else if (type == "log.auth.scan") {
      r.d.scans = ev.value("count", int64_t(1));
    } else if (type == "log.web.attack") {
      r.d.web_hits = ev.value("count", int64_t(1));
    } else {
      r.d.web_4xx = ev.value("errors_4xx", int64_t(1));
    }
    rows.push_back(std::move(r));
  }
  for (const auto& r : rows) {
    if (auto x = recordSources(r.target, {r.d}, r.ts)) n += x.value();
  }
  setMeta("sources_backfilled", "1");
  return n;
}

}  // namespace agent
