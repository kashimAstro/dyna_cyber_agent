#pragma once
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "core/result.h"

struct sqlite3;

namespace agent {

struct GeoPoint {
  std::string cc, region, city;  // ISO country code, state/province, city
  double lat = 0, lon = 0;
};

// Offline IP -> location database (DB-IP "IP to City Lite", CC BY 4.0), kept in its own SQLite file.
// Nothing is ever sent anywhere to locate an address: the lookup is a local, indexed query.
class GeoDb {
 public:
  static Result<std::unique_ptr<GeoDb>> open(const std::string& path);  // missing file = empty database
  ~GeoDb();
  GeoDb(const GeoDb&) = delete;
  GeoDb& operator=(const GeoDb&) = delete;

  bool empty();
  std::optional<GeoPoint> lookup(const std::string& ip);
  std::optional<std::string> meta(const std::string& key);

  // Builds a new database from the CSV (plain or .gz) in `<path>.new` and swaps it in atomically.
  // A running reader picks the new file up by itself.
  static Result<size_t> importCsv(const std::string& db_path, const std::string& csv_path, const std::string& source_label,
                                  std::chrono::seconds now_ts);

  // Private, loopback, link-local, CGNAT and other addresses that no database can place on a map.
  static bool isLocalAddress(const std::string& ip);

 private:
  explicit GeoDb(std::string path) : path_(std::move(path)) {}
  Result<bool> reopen();
  void reopenIfChanged();

  std::string path_;
  sqlite3* db_ = nullptr;
  long long inode_ = 0, mtime_ = 0;
  std::chrono::steady_clock::time_point last_check_{};
  std::mutex mu_;
};

// Streams `url` into `dest` (HTTPS only, no redirects). `status` receives the HTTP status.
Result<bool> downloadFile(const std::string& url, const std::string& dest, std::chrono::seconds timeout, long* status);

// DB-IP publishes a new file every month.
std::string dbipCityUrl(int year, int month);

}  // namespace agent
