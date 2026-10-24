#include "llm/context.h"

#include <algorithm>
#include <set>

namespace agent {

nlohmann::json buildHostContext(Store& store, const std::string& target) {
  nlohmann::json ctx = nlohmann::json::object();

  if (auto s = store.latest(target, "processes"); s && s.value()) {
    size_t user_procs = 0;
    for (const auto& o : s.value()->observations) user_procs += !o.data.value("kernel_thread", false);
    ctx["running_processes"] = user_procs;
  }

  if (auto s = store.latest(target, "network"); s && s.value()) {
    std::set<std::string> seen;
    nlohmann::json listeners = nlohmann::json::array();
    for (const auto& o : s.value()->observations) {
      if (o.type != "socket.inet" || std::find(o.tags.begin(), o.tags.end(), "exposed") == o.tags.end()) continue;
      std::string comm = "?";
      if (o.data.contains("owners") && !o.data["owners"].empty()) comm = o.data["owners"][0].value("comm", std::string("?"));
      const std::string line = o.data.value("proto", std::string()) + " " + o.data.value("local_addr", std::string()) + ":" +
                               std::to_string(o.data.value("local_port", 0)) + " (" + comm + ")";
      if (seen.insert(line).second && listeners.size() < 30) listeners.push_back(line);
    }
    ctx["services_exposed_to_network"] = listeners;
  }

  if (auto s = store.latest(target, "users"); s && s.value()) {
    nlohmann::json logins = nlohmann::json::array();
    size_t keys = 0;
    for (const auto& o : s.value()->observations) {
      if (o.type == "authorized_key") ++keys;
      if (o.type != "user" || !o.data.value("login_shell", false) || logins.size() >= 20) continue;
      logins.push_back({{"name", o.data.value("name", std::string())},
                        {"uid", o.data.value("uid", 0)},
                        {"privileged_groups", o.data.value("privileged_groups", nlohmann::json::array())}});
    }
    ctx["accounts_with_login_shell"] = logins;
    ctx["ssh_authorized_keys_total"] = keys;
  }
  return ctx;
}

}  // namespace agent
