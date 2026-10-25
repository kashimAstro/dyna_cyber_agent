#pragma once
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/config.h"
#include "geo/geo_db.h"
#include "llm/llm_client.h"
#include "llm/reasoner.h"
#include "report/report.h"
#include "store/store.h"
#include "web/http_server.h"

namespace agent {

// JSON API and page of the local console. Everything it shows comes from the agent's own database; the only
// actions are asking the model about findings and rendering report previews, and accepting a finding as normal (or taking
// that back); nothing is sent or changed on targets.
class WebApi {
 public:
  struct Deps {
    Store* store = nullptr;
    Config cfg;
    ReportContext report_ctx;
    GeoDb* geo = nullptr;            // optional: without it the map lists addresses but cannot place them
    LlmClient* llm = nullptr;        // optional: without it the analysis and AI report actions answer 503
    ReasonerOptions llm_options;
    std::string token;
    std::string version;
    std::function<int64_t()> clock;  // tests
  };

  explicit WebApi(Deps d);
  ~WebApi();

  HttpReply handle(const HttpRequest& req);

 private:
  struct Job {
    std::string id, kind, state = "running";  // running | done | error
    int64_t started = 0, finished = 0;
    nlohmann::json result;
    std::string error;
  };

  HttpReply overview();
  HttpReply findings(const HttpRequest& req);
  HttpReply findingDetail(int64_t id);
  HttpReply vulns(const HttpRequest& req);
  HttpReply notifications();
  HttpReply incidents();
  HttpReply incidentDetail(int64_t id);
  HttpReply sources(const HttpRequest& req);
  HttpReply settings();
  HttpReply addExclusion(const nlohmann::json& body);
  HttpReply importExclusions(const nlohmann::json& body);
  HttpReply deleteExclusion(const nlohmann::json& body);
  HttpReply setPause(const nlohmann::json& body);
  HttpReply resetAll(const nlohmann::json& body);
  HttpReply acceptFindings(const nlohmann::json& body);
  HttpReply reopenFindings(const nlohmann::json& body);
  HttpReply startAnalysis(const nlohmann::json& body);
  HttpReply startReport(const nlohmann::json& body);
  HttpReply startAsk(const nlohmann::json& body);
  HttpReply jobStatus(const std::string& id);

  std::string newJob(const std::string& kind);
  void finishJob(const std::string& id, nlohmann::json result, const std::string& error);
  void runAnalysis(const std::string& id, std::vector<Finding> findings, std::string question);
  void runReport(const std::string& id, std::string kind, int hours, bool synthesize);
  void runAsk(const std::string& id, std::string question, std::string target, int hours);

  int64_t now() const;
  nlohmann::json findingSummary(const Finding& f, const std::optional<Assessment>& a) const;

  Deps d_;
  std::mutex mu_;                    // jobs_ and threads_
  std::map<std::string, Job> jobs_;
  std::deque<std::string> job_order_;
  std::vector<std::thread> threads_;
  std::mutex llm_mu_;                // one model request at a time
  int running_ = 0;
  uint64_t counter_ = 0;
};

extern const char* const kConsoleHtml;  // generated from web/index.html at build time

}  // namespace agent
