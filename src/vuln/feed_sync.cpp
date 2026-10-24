#include "vuln/feed_sync.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <ctime>
#include <set>
#include <thread>

#include <nlohmann/json.hpp>

#include "core/gzip.h"
#include "core/util.h"
#include "vuln/feed_parsers.h"

namespace agent {
namespace {

constexpr int64_t kWindow = 119 * 86400;  // the NVD accepts at most 120 days per query
constexpr int kPageSize = 1000;

int64_t systemSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t steadyMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

}  // namespace

FeedSync::FeedSync(VulnDb& db, IHttpClient& http, VulnConfig cfg, SyncHooks hooks) : db_(db), http_(http), cfg_(std::move(cfg)), hooks_(std::move(hooks)) {
  if (!hooks_.sleep) hooks_.sleep = [](std::chrono::milliseconds ms) { std::this_thread::sleep_for(ms); };
  if (!hooks_.cancelled) hooks_.cancelled = [] { return false; };
  if (!hooks_.now) hooks_.now = systemSeconds;
}

Result<std::string> FeedSync::get(const std::string& url, bool nvd) {
  std::vector<std::string> headers = {"Accept: application/json", "User-Agent: dyna_cyber_agent (security monitor; read-only)"};
  std::unique_lock<std::mutex> nvd_lock(nvd_mu_, std::defer_lock);
  if (nvd) {
    if (!hooks_.nvd_api_key.empty()) headers.push_back("apiKey: " + hooks_.nvd_api_key);
    nvd_lock.lock();
    throttleNvd();
  }
  auto r = http_.get(url, headers, cfg_.timeout);
  if (nvd) last_nvd_ms_ = steadyMs();
  if (!r) return err(r.error());
  if (r.value().status == 200) return r.value().body;
  std::string why = "HTTP " + std::to_string(r.value().status);
  if (r.value().status == 403 || r.value().status == 429) why += " (rate limited or API key rejected)";
  else if (r.value().status == 503) why += " (service busy)";
  return err(why);
}

void FeedSync::throttleNvd() {
  // NVD: 5 requests per rolling 30 s without an API key, 50 with one. Stay well inside that.
  const int64_t gap = hooks_.nvd_api_key.empty() ? 6500 : 700;
  if (last_nvd_ms_ == 0) return;
  const int64_t wait = gap - (steadyMs() - last_nvd_ms_);
  if (wait > 0) hooks_.sleep(std::chrono::milliseconds(wait));
}

SyncReport FeedSync::syncKev() {
  SyncReport rep;
  rep.feed = "kev";
  auto body = get(cfg_.kev_url, false);
  if (!body) {
    rep.message = body.error();
    return rep;
  }
  auto kev = parseKev(body.value());
  if (!kev) {
    rep.message = kev.error();
    return rep;
  }
  // which ones are new to the catalog (compared with what we already hold)
  for (const auto& e : kev.value()) {
    auto have = db_.getCve(e.cve);
    if (!have || !have.value() || !have.value()->kev) rep.new_kev.push_back(e.cve);
  }
  const auto prev = db_.getMeta("kev_last_sync");
  const bool first_sync = !(prev && prev.value());
  if (first_sync) rep.new_kev.clear();  // the initial load is not "news"
  if (auto r = db_.applyKev(kev.value()); !r) {
    rep.message = r.error();
    return rep;
  }
  db_.setMeta("kev_last_sync", std::to_string(nowSec()));
  db_.setMeta("kev_count", std::to_string(kev.value().size()));
  rep.ok = true;
  rep.items = static_cast<int64_t>(kev.value().size());
  rep.message = std::to_string(kev.value().size()) + " entries, " + std::to_string(rep.new_kev.size()) + " new";
  return rep;
}

SyncReport FeedSync::syncNvd() {
  SyncReport rep;
  rep.feed = "nvd";
  const int64_t target = nowSec();
  int64_t cursor = 0;
  if (auto c = db_.getMeta("nvd_cursor"); c && c.value()) cursor = std::stoll(*c.value());
  if (cursor == 0) cursor = target - static_cast<int64_t>(cfg_.nvd_initial_days) * 86400;

  // an interrupted window is resumed at the page where it stopped
  struct Resume { int64_t start = 0, end = 0, index = 0; } resume;
  if (auto r = db_.getMeta("nvd_resume"); r && r.value()) {
    const auto j = nlohmann::json::parse(*r.value(), nullptr, false);
    if (j.is_object()) resume = {j.value("start", static_cast<int64_t>(0)), j.value("end", static_cast<int64_t>(0)), j.value("index", static_cast<int64_t>(0))};
  }

  int64_t requests = 0;
  while (cursor < target) {
    const bool resuming = resume.start == cursor && resume.end > cursor;
    const int64_t win_end = resuming ? resume.end : std::min(cursor + kWindow, target);
    int64_t index = resuming ? resume.index : 0;
    int64_t total = -1;
    while (total < 0 || index < total) {
      if (hooks_.cancelled()) {
        rep.ok = true;
        rep.partial = true;
        rep.message = "interrupted, will resume (" + std::to_string(rep.items) + " CVEs so far)";
        return rep;
      }
      const std::string url = cfg_.nvd_url + "?lastModStartDate=" + formatNvdTime(cursor) + "Z&lastModEndDate=" + formatNvdTime(win_end) + "Z&resultsPerPage=" +
                              std::to_string(kPageSize) + "&startIndex=" + std::to_string(index);
      auto body = get(url, true);
      ++requests;
      if (!body) {
        rep.partial = true;
        rep.message = "NVD: " + body.error() + " after " + std::to_string(rep.items) + " CVEs; will resume";
        return rep;
      }
      auto page = parseNvdPage(body.value());
      if (!page) {
        rep.partial = true;
        rep.message = "NVD: " + page.error();
        return rep;
      }
      if (auto r = db_.upsertCves(page.value().cves); !r) {
        rep.message = r.error();
        return rep;
      }
      rep.items += static_cast<int64_t>(page.value().cves.size());
      total = page.value().total;
      if (page.value().cves.empty()) break;  // defensive: never loop on an empty page
      index += static_cast<int64_t>(page.value().cves.size());
      db_.setMeta("nvd_resume", nlohmann::json({{"start", cursor}, {"end", win_end}, {"index", index}}).dump());
    }
    cursor = win_end;
    db_.setMeta("nvd_cursor", std::to_string(std::max<int64_t>(0, win_end - 600)));  // a little overlap: nothing modified in the gap is missed
    db_.setMeta("nvd_resume", "");
    resume = {};
    spdlog::info("NVD: window up to {} done ({} CVEs so far)", formatNvdTime(win_end), rep.items);
  }
  db_.setMeta("nvd_last_sync", std::to_string(target));
  rep.ok = true;
  rep.message = std::to_string(rep.items) + " CVE record(s) updated in " + std::to_string(requests) + " request(s)";
  return rep;
}

Result<bool> FeedSync::fetchCve(const std::string& id) {
  if (!util::startsWith(id, "CVE-") || id.find_first_not_of("CVE-0123456789") != std::string::npos) return err("not a CVE id");
  auto body = get(cfg_.nvd_url + "?cveId=" + id, true);
  if (!body) return err(body.error());
  auto page = parseNvdPage(body.value());
  if (!page) return err(page.error());
  if (page.value().cves.empty()) return err("NVD has no record for " + id + " (yet)");
  return db_.upsertCves(page.value().cves);
}

SyncReport FeedSync::syncCwe() {
  SyncReport rep;
  rep.feed = "cwe";
  const int64_t now = nowSec();
  auto ids = db_.cweIdsToFetch(now, 30 * 86400, 400);
  if (!ids) {
    rep.message = ids.error();
    return rep;
  }
  std::vector<std::string> todo;
  for (const auto& id : ids.value()) if (util::startsWith(id, "CWE-") && util::allDigits(id.substr(4))) todo.push_back(id);
  if (todo.empty()) {
    rep.ok = true;
    rep.message = "nothing to fetch";
    return rep;
  }

  auto fetch = [&](const std::vector<std::string>& batch) -> Result<std::vector<CweRecord>> {
    std::string list;
    for (const auto& id : batch) list += (list.empty() ? "" : ",") + id.substr(4);
    auto body = get(cfg_.cwe_url + "/cwe/weakness/" + list, false);
    if (!body) return err(body.error());
    return parseCweResponse(body.value());
  };
  std::set<std::string> answered;
  for (size_t i = 0; i < todo.size(); i += 25) {
    if (hooks_.cancelled()) {
      rep.partial = true;
      break;
    }
    const std::vector<std::string> batch(todo.begin() + static_cast<std::ptrdiff_t>(i), todo.begin() + static_cast<std::ptrdiff_t>(std::min(todo.size(), i + 25)));
    auto got = fetch(batch);
    std::vector<CweRecord> records;
    if (got) {
      records = std::move(got.value());
    } else {
      // One unknown id (a category, a view) can fail the whole batch: ask one by one.
      for (const auto& id : batch) {
        hooks_.sleep(std::chrono::milliseconds(500));
        auto one = fetch({id});
        if (one) for (auto& r : one.value()) records.push_back(std::move(r));
      }
    }
    for (const auto& r : records) answered.insert(r.id);
    if (auto r = db_.upsertCwes(records, now); !r) {
      rep.message = r.error();
      return rep;
    }
    rep.items += static_cast<int64_t>(records.size());
    hooks_.sleep(std::chrono::milliseconds(1000));
  }
  // ids the API does not describe (categories...): remember that we asked, so we do not ask again every run
  std::vector<CweRecord> unknown;
  for (const auto& id : todo) {
    if (answered.count(id)) continue;
    CweRecord r;
    r.id = id;
    r.status = "unavailable";
    unknown.push_back(std::move(r));
  }
  if (!rep.partial) db_.upsertCwes(unknown, now);
  db_.setMeta("cwe_last_sync", std::to_string(now));
  rep.ok = true;
  rep.message = std::to_string(rep.items) + " weakness description(s), " + std::to_string(unknown.size()) + " without description";
  return rep;
}

SyncReport FeedSync::syncEpss() {
  SyncReport rep;
  rep.feed = "epss";
  const int64_t now = nowSec();
  if (auto last = db_.getMeta("epss_last_sync"); last && last.value() && now - std::stoll(*last.value()) < 20 * 3600) {
    rep.ok = true;
    rep.message = "up to date (refreshed once a day)";
    return rep;
  }
  // The daily file is published after noon UTC: today's may not exist yet, so look back a few days.
  std::string why = "no file found";
  for (int back = 0; back < 4; ++back) {
    const std::time_t t = static_cast<std::time_t>(now - back * 86400);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char date[16];
    std::strftime(date, sizeof(date), "%Y-%m-%d", &tm);
    std::string url = cfg_.epss_url;
    for (size_t p; (p = url.find("{date}")) != std::string::npos;) url.replace(p, 6, date);
    std::vector<std::string> headers = {"User-Agent: dyna_cyber_agent (security monitor; read-only)"};
    auto r = http_.get(url, headers, cfg_.timeout);
    if (!r) {
      why = r.error();
      break;
    }
    if (r.value().status == 403 || r.value().status == 404) {
      why = "HTTP " + std::to_string(r.value().status) + " for " + date;
      continue;  // not published yet
    }
    if (r.value().status != 200) {
      why = "HTTP " + std::to_string(r.value().status);
      break;
    }
    Result<std::string> text = cfg_.epss_url.find(".gz") != std::string::npos ? gunzip(r.value().body) : Result<std::string>(r.value().body);
    if (!text) {
      why = text.error();
      break;
    }
    auto file = parseEpssCsv(text.value());
    if (!file) {
      why = file.error();
      break;
    }
    if (auto s = db_.replaceEpss(file.value().rows); !s) {
      rep.message = s.error();
      return rep;
    }
    db_.setMeta("epss_last_sync", std::to_string(now));
    db_.setMeta("epss_date", file.value().score_date);
    rep.ok = true;
    rep.items = static_cast<int64_t>(file.value().rows.size());
    rep.message = std::to_string(rep.items) + " scores dated " + file.value().score_date;
    return rep;
  }
  rep.message = "EPSS: " + why;
  return rep;
}

std::vector<SyncReport> FeedSync::syncAll() {
  std::vector<SyncReport> out;
  if (cfg_.kev) out.push_back(syncKev());
  if (cfg_.nvd) out.push_back(syncNvd());
  if (cfg_.epss) out.push_back(syncEpss());
  if (cfg_.cwe) out.push_back(syncCwe());  // last: it needs the CWE ids the other feeds brought in
  return out;
}

}  // namespace agent
