#pragma once
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/result.h"
#include "transport/transport.h"

namespace agent {

// One thing seen on the target (a process, a socket, a user...). `key` is a
// stable identity so two snapshots can be diffed; `tags` mark traits that
// deserve attention and are what the rule engine (phase 2) builds on.
struct Observation {
  std::string type;
  std::string key;
  nlohmann::json data;
  std::vector<std::string> tags;
};

struct CollectOutput {
  std::vector<Observation> observations;
  std::vector<std::string> warnings;  // partial failures (permissions, vanished files...)
};

struct Snapshot {
  int64_t id = 0;
  std::string target;
  std::string collector;
  int64_t ts = 0;  // unix seconds
  int64_t duration_ms = 0;
  std::string error;  // set when the whole collection failed
  std::vector<std::string> warnings;
  std::vector<Observation> observations;
};

struct VulnContext;  // vuln/vuln_context.h
class Store;         // store/store.h

// Small persistent key/value store for collectors that must remember something across runs and restarts
// (log offsets, journal cursors). Implemented on top of the agent's database.
class IStateStore {
 public:
  virtual ~IStateStore() = default;
  virtual std::optional<std::string> get(const std::string& key) = 0;
  virtual void set(const std::string& key, const std::string& value) = 0;
};

// Per-target settings a collector may need. Passed once, before the first collect().
struct CollectorOptions {
  std::string target;
  std::vector<std::string> log_paths;  // empty = autodetect
  bool log_templates = false;          // learn the shape of log messages no parser understands (analysis.logs.templates)
  size_t log_templates_per_cycle = 25;
  int log_backfill_kb = 0;             // on first sight of a log, also read this much of its tail (0 = start at the end)
  IStateStore* state = nullptr;
  const VulnContext* vuln = nullptr;  // only the `vulns` collector uses it
  Store* store = nullptr;             // only the `peers` collector uses it (it compares what other targets have recorded)
  std::string group;                  // peer analysis: the target's group and all its members (the target included)
  std::vector<std::string> group_members;
  bool beaconing = false;             // netflow: look for steady connections to the same address
  bool traffic_spikes = false;        // netflow: compare the outbound rate with the interface's usual one
  int network_interval = 15;          // seconds between `network` snapshots (the beat can not be timed better than this)
  size_t peer_min_group = 3;
  double peer_min_share = 0.8;
};

class ICollector {
 public:
  virtual ~ICollector() = default;
  virtual void configure(const CollectorOptions&) {}
  virtual std::string name() const = 0;
  virtual std::chrono::seconds defaultInterval() const = 0;
  virtual Result<CollectOutput> collect(ITransport& transport) = 0;
};

std::unique_ptr<ICollector> makeCollector(const std::string& name);  // nullptr if unknown
std::vector<std::string> collectorNames();

// Runs a collector and wraps the outcome (including failures) in a Snapshot.
Snapshot runCollector(ICollector& collector, ITransport& transport, const std::string& target);

}  // namespace agent
