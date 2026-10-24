#include "geo/geo_db.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <zlib.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

#include <spdlog/spdlog.h>

namespace agent {
namespace {

// IPv4 -> its 32-bit value; IPv6 -> its first 64 bits with the sign bit flipped (so SQLite's signed order is the numeric order).
struct Key {
  bool v6 = false;
  int64_t n = 0;
};

std::optional<Key> parseIp(const std::string& ip) {
  in_addr a4{};
  if (::inet_pton(AF_INET, ip.c_str(), &a4) == 1) return Key{false, static_cast<int64_t>(ntohl(a4.s_addr))};
  in6_addr a6{};
  if (::inet_pton(AF_INET6, ip.c_str(), &a6) == 1) {
    static const unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (std::memcmp(a6.s6_addr, mapped, 12) == 0) {  // ::ffff:a.b.c.d is an IPv4 address in disguise
      uint32_t v;
      std::memcpy(&v, a6.s6_addr + 12, 4);
      return Key{false, static_cast<int64_t>(ntohl(v))};
    }
    uint64_t hi = 0;
    for (int i = 0; i < 8; ++i) hi = (hi << 8) | a6.s6_addr[i];
    return Key{true, static_cast<int64_t>(hi ^ (1ULL << 63))};
  }
  return std::nullopt;
}

std::vector<std::string> csvFields(const std::string& line) {
  std::vector<std::string> out;
  std::string cur;
  bool quoted = false;
  for (size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (quoted) {
      if (c == '"' && i + 1 < line.size() && line[i + 1] == '"') { cur += '"'; ++i; }
      else if (c == '"') quoted = false;
      else cur += c;
    } else if (c == '"') {
      quoted = true;
    } else if (c == ',') {
      out.push_back(std::move(cur));
      cur.clear();
    } else if (c != '\r' && c != '\n') {
      cur += c;
    }
  }
  out.push_back(std::move(cur));
  return out;
}

struct Db {
  sqlite3* h = nullptr;
  ~Db() { if (h) sqlite3_close(h); }
};

struct Stmt {
  sqlite3_stmt* s = nullptr;
  Stmt(sqlite3* db, const char* sql) { sqlite3_prepare_v2(db, sql, -1, &s, nullptr); }
  ~Stmt() { sqlite3_finalize(s); }
};

const char* kSchema = R"(
CREATE TABLE loc (id INTEGER PRIMARY KEY, cc TEXT NOT NULL, region TEXT NOT NULL, city TEXT NOT NULL, lat REAL NOT NULL, lon REAL NOT NULL);
CREATE TABLE v4 (start INTEGER PRIMARY KEY, end INTEGER NOT NULL, loc INTEGER NOT NULL);
CREATE TABLE v6 (start INTEGER PRIMARY KEY, end INTEGER NOT NULL, loc INTEGER NOT NULL);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
)";

}  // namespace

bool GeoDb::isLocalAddress(const std::string& ip) {
  const auto k = parseIp(ip);
  if (!k) return true;  // not an address at all (a hostname, garbage): never plotted
  if (!k->v6) {
    const uint32_t v = static_cast<uint32_t>(k->n);
    const auto in = [&](uint32_t net, int bits) { return (v & (~0u << (32 - bits))) == net; };
    return in(0x0A000000, 8) || in(0xAC100000, 12) || in(0xC0A80000, 16) || in(0x7F000000, 8) || in(0xA9FE0000, 16) || in(0x64400000, 10) ||
           in(0x00000000, 8) || in(0xE0000000, 4) || in(0xC0000000, 24) || v == 0xFFFFFFFFu;
  }
  const uint64_t hi = static_cast<uint64_t>(k->n) ^ (1ULL << 63);
  return hi == 0 || (hi >> 54) == 0x3FA /* fe80::/10 */ || (hi >> 57) == 0x7E /* fc00::/7 */;
}

Result<std::unique_ptr<GeoDb>> GeoDb::open(const std::string& path) {
  std::unique_ptr<GeoDb> g(new GeoDb(path));
  if (auto r = g->reopen(); !r) return err(r.error());
  return g;
}

GeoDb::~GeoDb() {
  if (db_) sqlite3_close(db_);
}

Result<bool> GeoDb::reopen() {
  if (db_) { sqlite3_close(db_); db_ = nullptr; }
  struct stat st {};
  if (::stat(path_.c_str(), &st) != 0) return true;  // no database yet: every lookup answers "unknown"
  if (sqlite3_open_v2(path_.c_str(), &db_, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
    const std::string m = db_ ? sqlite3_errmsg(db_) : "cannot open";
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
    return err("geo database " + path_ + ": " + m);
  }
  inode_ = static_cast<long long>(st.st_ino);
  mtime_ = static_cast<long long>(st.st_mtime);
  return true;
}

void GeoDb::reopenIfChanged() {
  const auto now = std::chrono::steady_clock::now();
  if (now - last_check_ < std::chrono::seconds(30)) return;
  last_check_ = now;
  struct stat st {};
  if (::stat(path_.c_str(), &st) != 0) {
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
    return;
  }
  if (!db_ || static_cast<long long>(st.st_ino) != inode_ || static_cast<long long>(st.st_mtime) != mtime_) reopen();
}

bool GeoDb::empty() {
  std::lock_guard<std::mutex> lock(mu_);
  reopenIfChanged();
  if (!db_) return true;
  Stmt q(db_, "SELECT 1 FROM v4 LIMIT 1");
  return !q.s || sqlite3_step(q.s) != SQLITE_ROW;
}

std::optional<std::string> GeoDb::meta(const std::string& key) {
  std::lock_guard<std::mutex> lock(mu_);
  reopenIfChanged();
  if (!db_) return std::nullopt;
  Stmt q(db_, "SELECT value FROM meta WHERE key=?");
  if (!q.s) return std::nullopt;
  sqlite3_bind_text(q.s, 1, key.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_step(q.s) != SQLITE_ROW) return std::nullopt;
  return std::string(reinterpret_cast<const char*>(sqlite3_column_text(q.s, 0)));
}

std::optional<GeoPoint> GeoDb::lookup(const std::string& ip) {
  const auto k = parseIp(ip);
  if (!k || isLocalAddress(ip)) return std::nullopt;
  std::lock_guard<std::mutex> lock(mu_);
  reopenIfChanged();
  if (!db_) return std::nullopt;
  Stmt q(db_, k->v6 ? "SELECT l.cc,l.region,l.city,l.lat,l.lon,v.end FROM v6 v JOIN loc l ON l.id=v.loc WHERE v.start<=?1 ORDER BY v.start DESC LIMIT 1"
                    : "SELECT l.cc,l.region,l.city,l.lat,l.lon,v.end FROM v4 v JOIN loc l ON l.id=v.loc WHERE v.start<=?1 ORDER BY v.start DESC LIMIT 1");
  if (!q.s) return std::nullopt;
  sqlite3_bind_int64(q.s, 1, k->n);
  if (sqlite3_step(q.s) != SQLITE_ROW || sqlite3_column_int64(q.s, 5) < k->n) return std::nullopt;
  GeoPoint p;
  p.cc = reinterpret_cast<const char*>(sqlite3_column_text(q.s, 0));
  p.region = reinterpret_cast<const char*>(sqlite3_column_text(q.s, 1));
  p.city = reinterpret_cast<const char*>(sqlite3_column_text(q.s, 2));
  p.lat = sqlite3_column_double(q.s, 3);
  p.lon = sqlite3_column_double(q.s, 4);
  return p;
}

Result<size_t> GeoDb::importCsv(const std::string& db_path, const std::string& csv_path, const std::string& source_label, std::chrono::seconds now_ts) {
  gzFile gz = gzopen(csv_path.c_str(), "rb");  // reads plain files too
  if (!gz) return err("cannot open " + csv_path);
  struct Closer { gzFile f; ~Closer() { gzclose(f); } } closer{gz};

  const std::string tmp = db_path + ".new";
  std::remove(tmp.c_str());
  Db db;
  if (sqlite3_open(tmp.c_str(), &db.h) != SQLITE_OK) return err("cannot create " + tmp);
  char* msg = nullptr;
  if (sqlite3_exec(db.h, "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;", nullptr, nullptr, &msg) != SQLITE_OK ||
      sqlite3_exec(db.h, kSchema, nullptr, nullptr, &msg) != SQLITE_OK || sqlite3_exec(db.h, "BEGIN", nullptr, nullptr, &msg) != SQLITE_OK) {
    const std::string m = msg ? msg : "error";
    sqlite3_free(msg);
    return err("geo schema: " + m);
  }
  Stmt iloc(db.h, "INSERT INTO loc(cc,region,city,lat,lon) VALUES(?,?,?,?,?)");
  Stmt i4(db.h, "INSERT OR IGNORE INTO v4(start,end,loc) VALUES(?,?,?)");
  Stmt i6(db.h, "INSERT OR IGNORE INTO v6(start,end,loc) VALUES(?,?,?)");
  std::map<std::string, int64_t> locs;
  size_t rows = 0, bad = 0;
  std::string line;
  char buf[4096];
  bool more = true;
  while (more) {
    line.clear();
    while (true) {  // lines can exceed the buffer
      if (!gzgets(gz, buf, sizeof(buf))) { more = false; break; }
      line += buf;
      if (!line.empty() && line.back() == '\n') break;
    }
    if (line.empty()) continue;
    const auto f = csvFields(line);
    if (f.size() < 8) { ++bad; continue; }
    const auto a = parseIp(f[0]), b = parseIp(f[1]);
    if (!a || !b || a->v6 != b->v6) { ++bad; continue; }
    double lat = 0, lon = 0;
    try { lat = std::stod(f[6]); lon = std::stod(f[7]); } catch (...) { ++bad; continue; }
    if (f[3] == "ZZ" || (lat == 0 && lon == 0)) continue;  // "unknown": nothing to plot
    const std::string lk = f[3] + "|" + f[4] + "|" + f[5] + "|" + f[6] + "|" + f[7];
    auto it = locs.find(lk);
    if (it == locs.end()) {
      sqlite3_reset(iloc.s);
      sqlite3_bind_text(iloc.s, 1, f[3].c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(iloc.s, 2, f[4].c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(iloc.s, 3, f[5].c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_double(iloc.s, 4, lat);
      sqlite3_bind_double(iloc.s, 5, lon);
      if (sqlite3_step(iloc.s) != SQLITE_DONE) return err(std::string("geo import: ") + sqlite3_errmsg(db.h));
      it = locs.emplace(lk, sqlite3_last_insert_rowid(db.h)).first;
    }
    Stmt& ins = a->v6 ? i6 : i4;
    sqlite3_reset(ins.s);
    sqlite3_bind_int64(ins.s, 1, a->n);
    sqlite3_bind_int64(ins.s, 2, b->n);
    sqlite3_bind_int64(ins.s, 3, it->second);
    if (sqlite3_step(ins.s) != SQLITE_DONE) return err(std::string("geo import: ") + sqlite3_errmsg(db.h));
    if (++rows % 1000000 == 0) spdlog::info("geo import: {} million ranges...", rows / 1000000);
  }
  if (rows < 1000) return err("the file has too few valid rows (" + std::to_string(rows) + "): is it a DB-IP city CSV?");
  Stmt im(db.h, "INSERT INTO meta(key,value) VALUES(?,?)");
  const auto put = [&](const char* k, const std::string& v) {
    sqlite3_reset(im.s);
    sqlite3_bind_text(im.s, 1, k, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(im.s, 2, v.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(im.s);
  };
  put("source", source_label);
  put("built_at", std::to_string(now_ts.count()));
  put("ranges", std::to_string(rows));
  if (sqlite3_exec(db.h, "COMMIT", nullptr, nullptr, &msg) != SQLITE_OK) {
    const std::string m = msg ? msg : "error";
    sqlite3_free(msg);
    return err("geo commit: " + m);
  }
  if (bad) spdlog::warn("geo import: {} malformed line(s) skipped", bad);
  sqlite3_close(db.h);
  db.h = nullptr;
  if (std::rename(tmp.c_str(), db_path.c_str()) != 0) return err("cannot move " + tmp + " to " + db_path + ": " + std::strerror(errno));
  return rows;
}

std::string dbipCityUrl(int year, int month) {
  char buf[128];
  std::snprintf(buf, sizeof(buf), "https://download.db-ip.com/free/dbip-city-lite-%04d-%02d.csv.gz", year, month);
  return buf;
}

namespace {
size_t writeFile(char* p, size_t sz, size_t n, void* u) { return std::fwrite(p, sz, n, static_cast<FILE*>(u)) == n ? sz * n : 0; }
}  // namespace

Result<bool> downloadFile(const std::string& url, const std::string& dest, std::chrono::seconds timeout, long* status) {
  if (url.rfind("https://", 0) != 0) return err("only https:// downloads are allowed");
  FILE* f = std::fopen(dest.c_str(), "wb");
  if (!f) return err("cannot write " + dest + ": " + std::strerror(errno));
  CURL* c = curl_easy_init();
  if (!c) { std::fclose(f); return err("curl_easy_init failed"); }
  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, writeFile);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, static_cast<long>(timeout.count()));
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_FAILONERROR, 0L);
  const CURLcode rc = curl_easy_perform(c);
  long code = 0;
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
  if (status) *status = code;
  curl_easy_cleanup(c);
  const bool flushed = std::fclose(f) == 0;
  if (rc != CURLE_OK) { std::remove(dest.c_str()); return err(std::string("download: ") + curl_easy_strerror(rc)); }
  if (code != 200) { std::remove(dest.c_str()); return err("download: HTTP " + std::to_string(code)); }
  if (!flushed) { std::remove(dest.c_str()); return err("cannot write " + dest); }
  return true;
}

}  // namespace agent
