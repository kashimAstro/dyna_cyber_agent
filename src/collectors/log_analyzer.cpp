#include "collectors/log_analyzer.h"

#include <algorithm>
#include <ctime>

#include "collectors/log_templates.h"
#include "core/util.h"

namespace agent {
namespace {

std::string dayOf(int64_t ts) {
  const std::time_t t = static_cast<std::time_t>(ts);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char b[16];
  std::strftime(b, sizeof(b), "%Y-%m-%d", &tm);
  return b;
}

std::string firstWord(const std::string& cmd) {
  const size_t sp = cmd.find(' ');
  return cmd.substr(0, sp);
}

bool isShell(const std::string& cmd) {
  const std::string b = util::baseName(firstWord(cmd));
  return b == "sh" || b == "bash" || b == "dash" || b == "zsh" || b == "ksh" || b == "csh" || b == "tcsh" || b == "fish" || b == "su";
}

std::string clip(const std::string& s, size_t n) { return s.size() > n ? util::toValidUtf8(s.substr(0, n)) + "..." : util::toValidUtf8(s); }

}  // namespace

void LogAnalyzer::addCounted(Observation o) {
  auto it = events_.find(o.key);
  if (it == events_.end()) {
    Counted c;
    c.count = 1;
    c.obs = std::move(o);
    events_.emplace(c.obs.key, std::move(c));
  } else {
    ++it->second.count;
  }
}

void LogAnalyzer::prune(int64_t now) {
  for (auto it = failures_.begin(); it != failures_.end();) {
    auto& q = it->second;
    while (!q.empty() && q.front().ts < now - o_.window_seconds) q.pop_front();
    it = q.empty() ? failures_.erase(it) : std::next(it);
  }
  for (auto it = web_errors_.begin(); it != web_errors_.end();) {
    auto& q = it->second;
    while (!q.empty() && q.front() < now - o_.window_seconds) q.pop_front();
    it = q.empty() ? web_errors_.erase(it) : std::next(it);
  }
}

void LogAnalyzer::feedAuth(const std::string& file, const std::vector<std::string>& lines, int64_t now) {
  for (const auto& line : lines) {
    const auto sl = parseSyslogLine(line);
    if (!sl) continue;
    const auto ev = parseAuthLine(*sl);
    if (!ev) {
      noteLine(*sl, file);
      continue;
    }
    const bool external = !ev->src_ip.empty() && !isPrivateIp(ev->src_ip);
    switch (ev->kind) {
      case AuthEvent::Kind::LoginFail:
      case AuthEvent::Kind::InvalidUser:
      case AuthEvent::Kind::PreauthClose:
        failures_[ev->src_ip].push_back({now, ev->user, ev->kind == AuthEvent::Kind::InvalidUser});
        new_failure_ips_.insert(ev->src_ip);
        if (!ev->src_ip.empty()) {
          auto& sa = source(ev->src_ip);
          ++sa.ssh_fail;
          if (!ev->user.empty() && sa.users.size() < 10) sa.users.insert(clip(ev->user, 40));
        }
        break;
      case AuthEvent::Kind::Scan:
        ++auth_scans_[ev->src_ip];
        if (!ev->src_ip.empty()) ++source(ev->src_ip).scans;
        auth_scan_detail_[ev->src_ip] = clip(ev->detail, 120);
        break;
      case AuthEvent::Kind::LoginOk: {
        Observation o;
        o.type = "log.auth.login";
        o.key = "login|" + ev->user + "|" + ev->src_ip + "|" + ev->method;
        if (ev->user == "root") o.tags.push_back("root_login");
        if (ev->method == "publickey") o.tags.push_back("publickey_login");
        else if (ev->method == "password" || util::startsWith(ev->method, "keyboard-interactive")) o.tags.push_back("password_login");
        if (external) o.tags.push_back("external_ip");
        o.data = {{"user", ev->user}, {"src_ip", ev->src_ip}, {"method", ev->method}, {"port", ev->port}, {"key_fingerprint", ev->key}, {"file", file}, {"time", ev->time_text}};
        addCounted(std::move(o));
        if (!ev->src_ip.empty()) ++source(ev->src_ip).ssh_ok;
        const auto f = failures_.find(ev->src_ip);
        if (f != failures_.end() && f->second.size() >= 3) success_after_[ev->src_ip] = ev->user;  // the dangerous pattern
        break;
      }
      case AuthEvent::Kind::Sudo: {
        Observation o;
        o.type = "log.auth.sudo";
        o.key = "sudo|" + ev->user + "|" + firstWord(ev->command);
        if (ev->target_user == "root") o.tags.push_back("sudo_to_root");
        if (isShell(ev->command)) o.tags.push_back("sudo_shell");
        o.data = {{"user", ev->user}, {"target_user", ev->target_user}, {"command", clip(ev->command, 300)}, {"tty", ev->tty}, {"pwd", ev->pwd}, {"file", file}, {"time", ev->time_text}};
        addCounted(std::move(o));
        break;
      }
      case AuthEvent::Kind::SudoFail: {
        Observation o;
        o.type = "log.auth.sudo_failure";
        o.key = "sudofail|" + ev->user + "|" + ev->detail;
        if (ev->detail == "not in sudoers") o.tags.push_back("not_in_sudoers");
        o.data = {{"user", ev->user}, {"reason", ev->detail}, {"command", clip(ev->command, 300)}, {"tty", ev->tty}, {"file", file}, {"time", ev->time_text}};
        addCounted(std::move(o));
        break;
      }
      case AuthEvent::Kind::SuOk:
      case AuthEvent::Kind::SuFail: {
        const bool ok = ev->kind == AuthEvent::Kind::SuOk;
        Observation o;
        o.type = "log.auth.su";
        o.key = "su|" + ev->user + "|" + ev->target_user + "|" + (ok ? "ok" : "fail");
        if (!ok) o.tags.push_back("su_failed");
        if (ev->target_user == "root") o.tags.push_back("su_to_root");
        o.data = {{"from", ev->user}, {"to", ev->target_user}, {"success", ok}, {"tty", ev->tty}, {"file", file}, {"time", ev->time_text}};
        addCounted(std::move(o));
        break;
      }
      case AuthEvent::Kind::Account: {
        Observation o;
        o.type = "log.auth.account";
        o.key = "account|" + ev->action + "|" + ev->name + "|" + clip(ev->detail, 60);
        const std::string& d = ev->detail;
        if (ev->action == "useradd" || ev->action == "adduser" || util::startsWith(d, "new user")) o.tags.push_back("account_created");
        if (ev->action == "userdel" || ev->action == "deluser" || util::startsWith(d, "delete user")) o.tags.push_back("account_deleted");
        if (d.find("password changed") != std::string::npos || ev->action == "chpasswd") o.tags.push_back("password_changed");
        if (ev->action == "gpasswd" || ev->action == "usermod" || d.find("to group") != std::string::npos) o.tags.push_back("group_change");
        o.data = {{"action", ev->action}, {"name", ev->name}, {"detail", clip(d, 200)}, {"file", file}, {"time", ev->time_text}};
        addCounted(std::move(o));
        break;
      }
    }
  }
  prune(now);
}

void LogAnalyzer::noteLine(const SyslogLine& sl, const std::string& file) {
  if (!o_.templates || logNoise(sl.program, sl.message)) return;
  loadTemplateState();
  const std::string tmpl = logTemplate(sl.message);
  if (tmpl.empty()) return;
  const std::string id = logTemplateId(sl.program, tmpl);
  if (reported_templates_.count(id)) return;
  auto it = pending_templates_.find(id);
  if (it == pending_templates_.end()) {
    if (pending_templates_.size() >= 5000) return;  // a log gone wild must not eat the memory
    Tmpl t;
    t.program = clip(sl.program, 40);
    t.tmpl = clip(tmpl, 200);
    t.sample = clip(sl.message, 200);
    t.file = file;
    t.alarming = logAlarming(tmpl);
    it = pending_templates_.emplace(id, std::move(t)).first;
  }
  ++it->second.count;
}

void LogAnalyzer::feedGeneric(const std::string& file, const std::vector<std::string>& lines, int64_t) {
  if (!o_.templates) return;
  for (const auto& line : lines) {
    if (const auto sl = parseSyslogLine(line)) noteLine(*sl, file);
  }
}

void LogAnalyzer::loadTemplateState() {
  if (templates_loaded_) return;
  templates_loaded_ = true;
  if (!state_) return;
  if (const auto v = state_->get(state_key_)) for (const auto& id : util::split(*v, ' ')) if (!id.empty()) reported_templates_.insert(id);
}

void LogAnalyzer::feedKernel(const std::string& file, const std::vector<std::string>& lines, int64_t) {
  for (const auto& line : lines) {
    const auto sl = parseSyslogLine(line);
    if (!sl) continue;
    const auto ev = parseKernelLine(*sl);
    if (!ev) {
      noteLine(*sl, file);
      continue;
    }
    Observation o;
    o.type = "log.kernel";
    std::string detail;
    for (const auto& [k, v] : ev->fields) if (k != "detail") detail += (detail.empty() ? "" : "|") + v;
    o.key = "kernel|" + ev->event + "|" + clip(detail, 80);
    static const std::map<std::string, std::string> tag = {{"promisc", "promiscuous_mode"}, {"segfault", "segfault"}, {"oom_kill", "oom_kill"}, {"syn_flood", "syn_flood"},
                                                           {"conntrack_full", "conntrack_full"}, {"module_taint", "module_taint"}, {"apparmor_denied", "apparmor_denied"},
                                                           {"kernel_fault", "kernel_fault"}};
    o.tags.push_back(tag.at(ev->event));
    o.data = {{"event", ev->event}, {"file", file}, {"time", ev->time_text}};
    for (const auto& [k, v] : ev->fields) o.data[k] = clip(v, 200);
    addCounted(std::move(o));
  }
}

void LogAnalyzer::feedWeb(const std::string& file, const std::vector<std::string>& lines, int64_t now) {
  for (const auto& line : lines) {
    const auto w = parseWebLine(line);
    if (!w) continue;
    if (w->status >= 400 && w->status < 500) {
      ++source(w->ip).web_4xx;
      web_errors_[w->ip].push_back(now);
      new_web_error_ips_.insert(w->ip);
      auto& paths = web_paths_[w->ip];
      if (paths.size() < 200) paths.insert(w->uri.substr(0, w->uri.find('?')));
    }
    const auto cats = classifyWebRequest(*w);
    if (!cats.empty()) ++source(w->ip).web_hits;
    for (const auto& cat : cats) {
      auto& a = web_[w->ip + "|" + cat];
      if (a.count == 0) {
        a.ip = w->ip;
        a.category = cat;
        a.sample_uri = clip(w->uri, 300);
        a.ua = clip(w->ua, 160);
        a.file = file;
      }
      ++a.count;
      ++a.statuses[w->status];
      if (w->status >= 200 && w->status < 400) ++a.success;
    }
  }
  prune(now);
}

std::vector<Observation> LogAnalyzer::drain(int64_t now, std::vector<std::string>* warnings) {
  std::vector<Observation> out;
  const std::string day = dayOf(now);

  // failed logins -> brute force (also the "it worked after all those failures" case)
  for (const auto& ip : new_failure_ips_) {
    const auto it = failures_.find(ip);
    if (it == failures_.end()) continue;
    const auto& q = it->second;
    const bool success = success_after_.count(ip) > 0;
    if (q.size() < static_cast<size_t>(o_.bruteforce_threshold) && !success) continue;
    std::set<std::string> users;
    int64_t invalid = 0;
    for (const auto& f : q) {
      users.insert(f.user);
      invalid += f.invalid;
    }
    Observation o;
    o.type = "log.auth.bruteforce";
    o.key = "bruteforce|" + ip + "|" + day;
    if (!isPrivateIp(ip)) o.tags.push_back("external_ip");
    if (users.size() >= 5) o.tags.push_back("many_users");
    if (users.count("root")) o.tags.push_back("root_targeted");
    if (success) o.tags.push_back("success_after_failures");
    nlohmann::json ulist = nlohmann::json::array();
    for (const auto& u : users) if (ulist.size() < 10) ulist.push_back(u);
    o.data = {{"src_ip", ip}, {"failures", q.size()}, {"distinct_users", users.size()}, {"users", ulist}, {"invalid_user_attempts", invalid},
              {"window_s", o_.window_seconds}, {"day", day}};
    if (success) o.data["success_user"] = success_after_[ip];
    out.push_back(std::move(o));
  }

  for (const auto& [ip, n] : auth_scans_) {
    Observation o;
    o.type = "log.auth.scan";
    o.key = "authscan|" + ip + "|" + day;
    if (!isPrivateIp(ip)) o.tags.push_back("external_ip");
    o.data = {{"src_ip", ip}, {"count", n}, {"detail", auth_scan_detail_[ip]}, {"day", day}};
    out.push_back(std::move(o));
  }

  for (auto& [key, c] : events_) {
    c.obs.data["count"] = c.count;
    out.push_back(std::move(c.obs));
  }

  for (auto& [key, a] : web_) {
    Observation o;
    o.type = "log.web.attack";
    o.key = "webattack|" + a.ip + "|" + a.category + "|" + day;
    o.tags.push_back("web_" + a.category);
    if (!isPrivateIp(a.ip)) o.tags.push_back("external_ip");
    if (a.success > 0) o.tags.push_back("got_success_response");
    nlohmann::json st = nlohmann::json::object();
    for (const auto& [code, n] : a.statuses) st[std::to_string(code)] = n;
    o.data = {{"src_ip", a.ip}, {"category", a.category}, {"count", a.count}, {"success_responses", a.success}, {"statuses", st},
              {"sample_uri", a.sample_uri}, {"user_agent", a.ua}, {"file", a.file}, {"day", day}};
    out.push_back(std::move(o));
  }

  for (const auto& ip : new_web_error_ips_) {
    const auto it = web_errors_.find(ip);
    if (it == web_errors_.end() || it->second.size() < static_cast<size_t>(o_.web_scan_threshold)) continue;
    Observation o;
    o.type = "log.web.scan";
    o.key = "webscan|" + ip + "|" + day;
    if (!isPrivateIp(ip)) o.tags.push_back("external_ip");
    o.data = {{"src_ip", ip}, {"errors_4xx", it->second.size()}, {"distinct_paths", web_paths_[ip].size()}, {"window_s", o_.window_seconds}, {"day", day}};
    out.push_back(std::move(o));
  }

  new_failure_ips_.clear();
  new_web_error_ips_.clear();
  success_after_.clear();
  auth_scans_.clear();
  auth_scan_detail_.clear();
  events_.clear();
  web_.clear();
  web_paths_.clear();
  prune(now);

  if (out.size() > o_.max_observations) {
    if (warnings) warnings->push_back(std::to_string(out.size() - o_.max_observations) + " log event(s) dropped: more than " + std::to_string(o_.max_observations) + " in one cycle");
    out.resize(o_.max_observations);
  }

  // New message shapes come after the cap above: once reported they count as known, so none may be dropped.
  if (o_.templates && !pending_templates_.empty()) {
    // alarming shapes first, then the most frequent; whatever does not fit waits for the next drain
    std::vector<std::pair<std::string, const Tmpl*>> order;
    for (const auto& [id, t] : pending_templates_) order.emplace_back(id, &t);
    std::sort(order.begin(), order.end(), [](const auto& a, const auto& b) {
      if (a.second->alarming != b.second->alarming) return a.second->alarming;
      if (a.second->count != b.second->count) return a.second->count > b.second->count;
      return a.first < b.first;
    });
    size_t emitted = 0;
    for (const auto& [id, t] : order) {
      if (emitted >= o_.max_templates) break;
      Observation o;
      o.type = "log.template";
      o.key = "tmpl|" + id;
      if (t->alarming) o.tags.push_back("alarming_words");
      o.data = {{"program", t->program}, {"template", t->tmpl}, {"hash", id}, {"sample", t->sample}, {"count", t->count}, {"alarming", t->alarming}, {"file", t->file}};
      out.push_back(std::move(o));
      reported_templates_.insert(id);
      pending_templates_.erase(id);
      ++emitted;
      templates_dirty_ = true;
    }
    if (!pending_templates_.empty() && warnings) warnings->push_back(std::to_string(pending_templates_.size()) + " new log message shape(s) wait for the next cycle");
    if (templates_dirty_ && state_) {
      std::string all;
      size_t n = 0;
      for (const auto& id : reported_templates_) {
        if (++n > 20000) break;
        all += id + " ";
      }
      state_->set(state_key_, all);
      templates_dirty_ = false;
    }
  }

  // Per-address activity for the attack map: counters since the previous drain (deltas, so nothing is counted twice).
  std::vector<std::pair<std::string, const SourceAgg*>> busy;
  for (const auto& [ip, a] : sources_) busy.emplace_back(ip, &a);
  std::sort(busy.begin(), busy.end(), [](const auto& x, const auto& y) {
    const auto n = [](const SourceAgg* a) { return a->ssh_fail + a->ssh_ok + a->scans + a->web_hits + a->web_4xx; };
    return n(x.second) > n(y.second);
  });
  if (busy.size() > o_.max_sources) {
    if (warnings) warnings->push_back(std::to_string(busy.size() - o_.max_sources) + " source address(es) not tracked: more than " + std::to_string(o_.max_sources) + " in one cycle");
    busy.resize(o_.max_sources);
  }
  for (const auto& [ip, a] : busy) {
    Observation o;
    o.type = "log.source";
    o.key = "source|" + ip;
    nlohmann::json users = nlohmann::json::array();
    for (const auto& u : a->users) users.push_back(u);
    o.data = {{"src_ip", ip}, {"ssh_fail", a->ssh_fail}, {"ssh_ok", a->ssh_ok}, {"scans", a->scans}, {"web_hits", a->web_hits},
              {"web_4xx", a->web_4xx}, {"users", users}, {"day", day}};
    out.push_back(std::move(o));
  }
  sources_.clear();
  return out;
}

}  // namespace agent
