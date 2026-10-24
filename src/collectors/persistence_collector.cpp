#include "collectors/persistence_collector.h"

#include <algorithm>
#include <map>
#include <set>

#include "collectors/content_scan.h"
#include "collectors/user_collector.h"
#include "core/sha256.h"
#include "core/util.h"

namespace agent {
namespace {

constexpr uint64_t kMaxFile = 64 * 1024;

bool isEnvAssignment(const std::string& l) {
  const size_t eq = l.find('=');
  if (eq == std::string::npos || eq == 0) return false;
  for (size_t i = 0; i < eq; ++i) {
    const unsigned char c = static_cast<unsigned char>(l[i]);
    if (!(std::isalnum(c) || c == '_')) return false;
  }
  return true;
}

void addTags(Observation& o, const std::string& content) {
  for (const auto& t : suspiciousContentTags(content)) o.tags.push_back(t);
}

}  // namespace

std::vector<CronEntry> parseCrontab(const std::string& text, bool system_format) {
  std::vector<CronEntry> out;
  for (const auto& raw : util::split(text, '\n')) {
    const std::string l(util::trim(raw));
    if (l.empty() || l[0] == '#' || isEnvAssignment(l)) continue;
    const auto f = util::splitWs(l);
    CronEntry e;
    size_t i;
    if (f[0][0] == '@') {
      e.schedule = f[0];
      i = 1;
    } else {
      if (f.size() < 6) continue;
      e.schedule = f[0] + " " + f[1] + " " + f[2] + " " + f[3] + " " + f[4];
      i = 5;
    }
    if (system_format) {
      if (i >= f.size()) continue;
      e.user = f[i++];
    }
    if (i >= f.size()) continue;
    // the command is the rest of the line, verbatim
    size_t pos = 0;
    for (size_t k = 0; k < i; ++k) {
      pos = l.find(f[k], pos) + f[k].size();
    }
    e.command = std::string(util::trim(l.substr(pos)));
    out.push_back(std::move(e));
  }
  return out;
}

UnitInfo parseUnitFile(const std::string& text) {
  UnitInfo u;
  std::string section;
  for (const auto& raw : util::split(text, '\n')) {
    const std::string l(util::trim(raw));
    if (l.empty() || l[0] == '#' || l[0] == ';') continue;
    if (l[0] == '[' && l.back() == ']') {
      section = l.substr(1, l.size() - 2);
      continue;
    }
    const size_t eq = l.find('=');
    if (eq == std::string::npos) continue;
    const std::string k = std::string(util::trim(l.substr(0, eq))), v = std::string(util::trim(l.substr(eq + 1)));
    if (section == "Unit" && k == "Description") u.description = v;
    else if (section == "Service" && (k == "ExecStart" || k == "ExecStartPre" || k == "ExecStartPost" || k == "ExecStop" || k == "ExecReload")) u.exec.push_back(k + "=" + v);
    else if (section == "Service" && k == "User") u.user = v;
    else if (section == "Install" && (k == "WantedBy" || k == "RequiredBy")) for (const auto& w : util::splitWs(v)) u.wanted_by.push_back(w);
    else if (section == "Timer" && (k == "OnCalendar" || k == "OnBootSec" || k == "OnUnitActiveSec" || k == "OnStartupSec")) u.schedule += (u.schedule.empty() ? "" : "; ") + k + "=" + v;
    else if (section == "Socket" && (k == "ListenStream" || k == "ListenDatagram")) u.listen += (u.listen.empty() ? "" : ", ") + v;
  }
  return u;
}

Result<CollectOutput> PersistenceCollector::collect(ITransport& t) {
  CollectOutput out;

  // ---- Batch 1: single files and the directories whose entries we will read next.
  const std::vector<std::string> single_files = {"/etc/crontab", "/etc/anacrontab", "/etc/rc.local", "/etc/ld.so.preload", "/etc/environment",
                                                 "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc", "/etc/zsh/zshenv"};
  const std::vector<std::string> cron_script_dirs = {"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"};
  const std::vector<std::string> other_dirs = {"/etc/cron.d", "/etc/profile.d", "/etc/init.d", "/etc/systemd/system", "/var/spool/cron/crontabs", "/var/spool/cron"};
  std::vector<ReadOp> ops;
  for (const auto& f : single_files) ops.push_back(ReadOp::file(f, kMaxFile));
  for (const auto& d : cron_script_dirs) ops.push_back(ReadOp::list(d));
  for (const auto& d : other_dirs) ops.push_back(ReadOp::list(d));
  ops.push_back(ReadOp::file("/etc/passwd", 4 << 20));
  const auto r1 = t.bulk(ops);
  size_t k = 0;
  std::map<std::string, const OpResult*> single, dirs;
  for (const auto& f : single_files) single[f] = &r1[k++];
  for (const auto& d : cron_script_dirs) dirs[d] = &r1[k++];
  for (const auto& d : other_dirs) dirs[d] = &r1[k++];
  const OpResult& passwd = r1[k];

  // ---- Batch 2: contents of everything we found.
  struct Item {
    std::string path, kind;  // kind: cron.d | cron.script | crontab.user | profile.d | init.d | unit | user.startup
    std::string owner;       // user crontab / startup files
    bool symlink = false;
  };
  std::vector<Item> items;
  auto addDir = [&](const std::string& dir, const std::string& kind, bool files_only = true) {
    const OpResult* r = dirs[dir];
    if (!r->ok) return;
    for (const auto& e : r->entries) {
      if (e.is_dir && files_only) continue;
      if (util::startsWith(e.name, ".") && kind != "unit") continue;  // dot-files are skipped by run-parts/cron.d, except where a hidden unit would matter
      items.push_back({dir + "/" + e.name, kind, "", e.is_symlink});
    }
  };
  for (const auto& d : cron_script_dirs) addDir(d, "cron.script");
  addDir("/etc/cron.d", "cron.d");
  addDir("/etc/profile.d", "profile.d");
  addDir("/etc/init.d", "init.d");

  // systemd: unit files directly in /etc/systemd/system, and what is enabled through the *.wants directories
  std::vector<std::string> wants_dirs;
  if (dirs["/etc/systemd/system"]->ok) {
    for (const auto& e : dirs["/etc/systemd/system"]->entries) {
      if (e.is_dir) {
        if (util::endsWith(e.name, ".wants") || util::endsWith(e.name, ".requires")) wants_dirs.push_back("/etc/systemd/system/" + e.name);
        continue;
      }
      if (util::endsWith(e.name, ".service") || util::endsWith(e.name, ".timer") || util::endsWith(e.name, ".socket") || util::endsWith(e.name, ".path") ||
          util::endsWith(e.name, ".mount") || util::endsWith(e.name, ".target"))
        items.push_back({"/etc/systemd/system/" + e.name, "unit", "", e.is_symlink});
    }
  }
  std::vector<ReadOp> wops;
  for (const auto& d : wants_dirs) wops.push_back(ReadOp::list(d));

  // per-user crontabs
  for (const char* base : {"/var/spool/cron/crontabs", "/var/spool/cron"}) {
    if (!dirs[base]->ok) continue;
    for (const auto& e : dirs[base]->entries) if (!e.is_dir && !util::startsWith(e.name, ".")) items.push_back({std::string(base) + "/" + e.name, "crontab.user", e.name, false});
  }
  // login users' startup files
  if (passwd.ok) {
    std::set<std::string> homes;
    for (const auto& u : parsePasswd(passwd.file.data)) {
      if (!isLoginShell(u.shell) || u.home.empty() || u.home[0] != '/' || u.home == "/" || !homes.insert(u.home).second) continue;
      for (const char* f : {"/.bashrc", "/.bash_profile", "/.bash_login", "/.profile", "/.zshrc", "/.zprofile", "/.bash_logout", "/.ssh/rc", "/.ssh/environment", "/.config/autostart"}) {
        if (std::string(f) == "/.config/autostart") continue;  // a directory: listed below
        items.push_back({u.home + f, "user.startup", u.name, false});
      }
    }
  }
  std::vector<ReadOp> cops;
  for (const auto& it : items) {
    cops.push_back(ReadOp::file(it.path, kMaxFile));
    if (it.symlink) cops.push_back(ReadOp::link(it.path));
  }
  // one batch for contents, links and the *.wants listings
  std::vector<ReadOp> all = cops;
  all.insert(all.end(), wops.begin(), wops.end());
  const auto r2 = t.bulk(all);

  int unreadable = 0;
  size_t ci = 0;
  for (const auto& it : items) {
    const OpResult& rc = r2[ci++];
    std::string link;
    if (it.symlink) {
      const OpResult& rl = r2[ci++];
      if (rl.ok) link = rl.text;
    }
    if (!rc.ok) {
      if (it.kind != "user.startup" && it.kind != "crontab.user") ++unreadable;  // user files are mostly just absent
      else if (rc.error.find("ermission") != std::string::npos) ++unreadable;
      continue;
    }
    const std::string& content = rc.file.data;
    const std::string sha = Sha256::hex(content);

    if (it.kind == "cron.d" || it.kind == "crontab.user") {
      for (const auto& e : parseCrontab(content, it.kind == "cron.d")) {
        Observation o;
        o.type = "cron.entry";
        o.key = it.path + "|" + e.schedule + "|" + e.user + "|" + e.command;
        if (e.schedule == "@reboot") o.tags.push_back("reboot");
        if (inVolatileDir(e.command.substr(e.command.find_first_not_of(' ') == std::string::npos ? 0 : e.command.find_first_not_of(' '))) || e.command.find(" /tmp/") != std::string::npos ||
            e.command.find("/dev/shm/") != std::string::npos || e.command.find("/var/tmp/") != std::string::npos)
          o.tags.push_back("command_in_volatile_dir");
        addTags(o, e.command);
        o.data = {{"file", it.path}, {"schedule", e.schedule}, {"user", it.kind == "crontab.user" ? it.owner : e.user}, {"command", util::toValidUtf8(e.command.substr(0, 400))}, {"owner_crontab", it.kind == "crontab.user"}};
        out.observations.push_back(std::move(o));
      }
      continue;
    }
    if (it.kind == "unit") {
      const UnitInfo u = parseUnitFile(content);
      Observation o;
      o.type = "systemd.unit";
      const std::string name = util::baseName(it.path);
      o.key = it.path;
      std::string execs;
      for (const auto& e : u.exec) execs += e + "\n";
      for (const auto& line : u.exec) {
        const std::string v = line.substr(line.find('=') + 1);
        std::string cmd = v;
        while (!cmd.empty() && (cmd[0] == '-' || cmd[0] == '@' || cmd[0] == '+' || cmd[0] == '!' || cmd[0] == ':')) cmd.erase(0, 1);
        if (inVolatileDir(cmd)) o.tags.push_back("exec_in_volatile_dir");
      }
      addTags(o, execs);
      if (util::startsWith(name, ".")) o.tags.push_back("hidden_unit");
      if (!it.symlink) o.tags.push_back("admin_unit");  // a real file in /etc/systemd/system, not an alias to a packaged unit
      nlohmann::json ex = nlohmann::json::array();
      for (const auto& e : u.exec) ex.push_back(util::toValidUtf8(e.substr(0, 300)));
      o.data = {{"path", it.path}, {"name", name}, {"description", util::toValidUtf8(u.description)}, {"exec", ex}, {"user", u.user}, {"wanted_by", u.wanted_by},
                {"schedule", u.schedule}, {"listen", u.listen}, {"sha256", sha}, {"size", content.size()}, {"is_symlink", it.symlink}, {"link_target", link}};
      out.observations.push_back(std::move(o));
      continue;
    }
    // cron scripts, profile snippets, init scripts, per-user startup files: hash + content check
    Observation o;
    o.type = it.kind == "cron.script" ? "cron.script" : "startup.file";
    o.key = it.path;
    addTags(o, content);
    if (it.kind == "user.startup" && it.owner != "root" && util::endsWith(it.path, "/.ssh/rc")) o.tags.push_back("ssh_rc");
    if (it.kind == "user.startup" && util::endsWith(it.path, "/.ssh/environment")) o.tags.push_back("ssh_environment");
    o.data = {{"path", it.path}, {"kind", it.kind}, {"owner", it.owner}, {"sha256", sha}, {"size", content.size()}, {"truncated", rc.file.truncated}};
    out.observations.push_back(std::move(o));
  }

  // enabled units (what the *.wants directories link to)
  for (size_t w = 0; w < wants_dirs.size(); ++w) {
    const OpResult& rw = r2[ci + w];
    if (!rw.ok) continue;
    for (const auto& e : rw.entries) {
      Observation o;
      o.type = "systemd.enabled";
      o.key = wants_dirs[w] + "/" + e.name;
      o.data = {{"wants_dir", wants_dirs[w]}, {"unit", e.name}, {"is_symlink", e.is_symlink}};
      out.observations.push_back(std::move(o));
    }
  }

  // single files
  for (const auto& f : single_files) {
    const OpResult& r = *single[f];
    if (!r.ok) continue;
    const std::string& content = r.file.data;
    if (f == "/etc/ld.so.preload") {
      for (const auto& line : util::split(content, '\n')) {
        const std::string lib(util::trim(line));
        if (lib.empty() || lib[0] == '#') continue;
        Observation o;
        o.type = "preload.entry";
        o.key = "preload|" + lib;
        o.tags = {"ld_so_preload"};
        if (inVolatileDir(lib)) o.tags.push_back("library_in_volatile_dir");
        o.data = {{"file", f}, {"library", util::toValidUtf8(lib)}};
        out.observations.push_back(std::move(o));
      }
      continue;
    }
    if (f == "/etc/crontab" || f == "/etc/anacrontab") {
      if (f == "/etc/crontab") {
        for (const auto& e : parseCrontab(content, true)) {
          Observation o;
          o.type = "cron.entry";
          o.key = f + "|" + e.schedule + "|" + e.user + "|" + e.command;
          if (e.schedule == "@reboot") o.tags.push_back("reboot");
          if (e.command.find("/tmp/") != std::string::npos || e.command.find("/dev/shm/") != std::string::npos) o.tags.push_back("command_in_volatile_dir");
          addTags(o, e.command);
          o.data = {{"file", f}, {"schedule", e.schedule}, {"user", e.user}, {"command", util::toValidUtf8(e.command.substr(0, 400))}, {"owner_crontab", false}};
          out.observations.push_back(std::move(o));
        }
      }
      continue;
    }
    Observation o;
    o.type = "startup.file";
    o.key = f;
    addTags(o, content);
    if (f == "/etc/environment" && content.find("LD_PRELOAD") != std::string::npos && std::find(o.tags.begin(), o.tags.end(), "ld_preload") == o.tags.end()) o.tags.push_back("ld_preload");
    o.data = {{"path", f}, {"kind", "system"}, {"owner", ""}, {"sha256", Sha256::hex(content)}, {"size", content.size()}, {"truncated", r.file.truncated}};
    out.observations.push_back(std::move(o));
  }

  if (unreadable) out.warnings.push_back(std::to_string(unreadable) + " persistence file(s) not readable (insufficient privileges?)");
  return out;
}

}  // namespace agent
