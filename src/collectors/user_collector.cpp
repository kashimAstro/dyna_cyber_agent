#include "collectors/user_collector.h"

#include <map>
#include <set>

#include "core/util.h"

namespace agent {
namespace {

bool isKeyType(const std::string& s) {
  return util::startsWith(s, "ssh-") || util::startsWith(s, "ecdsa-") || util::startsWith(s, "sk-ssh-") ||
         util::startsWith(s, "sk-ecdsa-");
}

}  // namespace

std::vector<PasswdEntry> parsePasswd(const std::string& text) {
  std::vector<PasswdEntry> out;
  for (const auto& line : util::split(text, '\n')) {
    if (line.empty() || line[0] == '#') continue;
    const auto f = util::split(line, ':');
    if (f.size() < 7) continue;
    const auto uid = util::parseUint(f[2]), gid = util::parseUint(f[3]);
    if (!uid || !gid) continue;
    out.push_back({f[0], f[5], f[6], *uid, *gid});
  }
  return out;
}

bool isLoginShell(const std::string& shell) {
  if (shell.empty()) return true;  // empty shell field means /bin/sh
  const std::string b = util::baseName(shell);
  return !(b == "nologin" || b == "false" || b == "sync" || b == "halt" || b == "shutdown");
}

std::string passwordState(const std::string& f) {
  if (f.empty()) return "empty";
  if (f[0] == '!' || f[0] == '*') return "locked";
  return "set";
}

std::vector<AuthorizedKey> parseAuthorizedKeys(const std::string& text) {
  std::vector<AuthorizedKey> out;
  for (const auto& raw : util::split(text, '\n')) {
    const std::string_view line = util::trim(raw);
    if (line.empty() || line[0] == '#') continue;
    // Options may contain quoted spaces, so locate the key type token outside quotes.
    bool quoted = false;
    size_t i = 0, type_start = std::string::npos;
    for (; i < line.size(); ++i) {
      if (line[i] == '"') quoted = !quoted;
      if (!quoted && (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t')) {
        const size_t e = line.find_first_of(" \t", i);
        if (isKeyType(std::string(line.substr(i, e == std::string_view::npos ? std::string_view::npos : e - i)))) {
          type_start = i;
          break;
        }
      }
    }
    if (type_start == std::string::npos) continue;
    AuthorizedKey k;
    k.options = std::string(util::trim(line.substr(0, type_start)));
    const auto rest = util::splitWs(line.substr(type_start));
    if (rest.size() < 2) continue;
    k.type = rest[0];
    k.blob = rest[1];
    for (size_t j = 2; j < rest.size(); ++j) k.comment += (j > 2 ? " " : "") + rest[j];
    k.options = util::toValidUtf8(k.options);
    k.comment = util::toValidUtf8(k.comment);
    out.push_back(std::move(k));
  }
  return out;
}

Result<CollectOutput> UserCollector::collect(ITransport& t) {
  // Batch 1: the account databases, the main sudoers file and the sudoers.d listing.
  const auto base = t.bulk({ReadOp::file("/etc/passwd", 4 << 20), ReadOp::file("/etc/shadow", 4 << 20), ReadOp::file("/etc/group", 4 << 20),
                            ReadOp::file("/etc/sudoers", 1 << 20), ReadOp::list("/etc/sudoers.d")});
  const OpResult &pw = base[0], &sh = base[1], &gr = base[2], &sudoers_main = base[3], &sudoers_d = base[4];
  if (!pw.ok) return err(pw.error);
  CollectOutput out;

  std::map<std::string, std::vector<std::string>> state;  // user -> shadow fields
  if (sh.ok) {
    for (const auto& line : util::split(sh.file.data, '\n')) {
      const auto f = util::split(line, ':');
      if (f.size() >= 3) state[f[0]] = f;
    }
  } else {
    out.warnings.push_back("/etc/shadow not readable: password state unknown");
  }

  std::map<std::string, std::vector<std::string>> group_members;  // user -> privileged groups
  if (gr.ok) {
    for (const auto& line : util::split(gr.file.data, '\n')) {
      const auto f = util::split(line, ':');
      if (f.size() < 4) continue;
      Observation o;
      o.type = "group";
      o.key = f[0];
      o.data = {{"name", f[0]}, {"gid", util::parseUint(f[2]).value_or(0)}, {"members", f[3].empty() ? std::vector<std::string>{} : util::split(f[3], ',')}};
      if (f[0] == "sudo" || f[0] == "wheel" || f[0] == "admin" || f[0] == "docker" || f[0] == "root") {
        for (const auto& m : o.data["members"]) group_members[m.get<std::string>()].push_back(f[0]);
      }
      out.observations.push_back(std::move(o));
    }
  }

  // Batch 2: authorized_keys of every account that can log in (stat tells "absent" from "unreadable").
  struct KeyFile { const PasswdEntry* user; std::string path; };
  const auto accounts = parsePasswd(pw.file.data);
  std::vector<KeyFile> key_files;
  std::vector<ReadOp> key_ops;
  for (const auto& u : accounts) {
    if (!isLoginShell(u.shell) || u.home.empty() || u.home[0] != '/') continue;
    for (const char* name : {"authorized_keys", "authorized_keys2"}) {
      key_files.push_back({&u, u.home + "/.ssh/" + name});
      key_ops.push_back(ReadOp::stat(key_files.back().path));
      key_ops.push_back(ReadOp::file(key_files.back().path, 1 << 20));
    }
  }
  const auto key_res = t.bulk(key_ops);
  std::map<std::string, std::vector<Observation>> keys_of;  // user -> key observations
  int keys_unreadable = 0;
  for (size_t i = 0; i < key_files.size(); ++i) {
    if (!key_res[i * 2].ok) continue;  // no such file
    if (!key_res[i * 2 + 1].ok) {
      ++keys_unreadable;
      continue;
    }
    const PasswdEntry& u = *key_files[i].user;
    for (const auto& k : parseAuthorizedKeys(key_res[i * 2 + 1].file.data)) {
      Observation ko;
      ko.type = "authorized_key";
      ko.key = u.name + "|" + k.type + "|" + k.blob;
      if (!k.options.empty()) ko.tags.push_back("has_options");
      if (k.options.find("command=") != std::string::npos) ko.tags.push_back("forced_command");
      if (u.uid == 0) ko.tags.push_back("root_key");
      ko.data = {{"user", u.name}, {"file", key_files[i].path}, {"type", k.type}, {"blob", k.blob}, {"comment", k.comment}, {"options", k.options}};
      keys_of[u.name].push_back(std::move(ko));
    }
  }

  for (const auto& u : accounts) {
    const bool login = isLoginShell(u.shell);
    Observation o;
    o.type = "user";
    o.key = u.name;
    if (u.uid == 0) o.tags.push_back("uid0");
    if (u.uid == 0 && u.name != "root") o.tags.push_back("uid0_not_root");
    if (login) o.tags.push_back("login_shell");
    std::string pstate = "unknown";
    int64_t last_change = -1;
    if (auto it = state.find(u.name); it != state.end()) {
      pstate = passwordState(it->second[1]);
      last_change = static_cast<int64_t>(util::parseUint(it->second[2]).value_or(0));
      if (pstate == "empty") o.tags.push_back("empty_password");
    }
    const auto gm = group_members.find(u.name);
    o.data = {{"name", u.name},   {"uid", u.uid},         {"gid", u.gid},
              {"home", u.home},   {"shell", u.shell},     {"login_shell", login},
              {"password", pstate}, {"password_changed_day", last_change},
              {"privileged_groups", gm == group_members.end() ? std::vector<std::string>{} : gm->second}};
    out.observations.push_back(std::move(o));
    if (auto it = keys_of.find(u.name); it != keys_of.end()) {
      for (auto& ko : it->second) out.observations.push_back(std::move(ko));
    }
  }
  if (keys_unreadable) out.warnings.push_back(std::to_string(keys_unreadable) + " authorized_keys file(s) not readable");

  // Batch 3: sudoers.d files. Effective lines are kept so NOPASSWD and friends can be spotted later.
  std::vector<std::string> sudo_files = {"/etc/sudoers"};
  std::vector<ReadOp> sudo_ops;
  if (sudoers_d.ok) {
    for (const auto& e : sudoers_d.entries) {
      if (util::startsWith(e.name, ".") || e.name.find('~') != std::string::npos) continue;
      sudo_files.push_back("/etc/sudoers.d/" + e.name);
      sudo_ops.push_back(ReadOp::file(sudo_files.back(), 1 << 20));
    }
  }
  const auto sudo_res = t.bulk(sudo_ops);
  for (size_t i = 0; i < sudo_files.size(); ++i) {
    const OpResult& c = i == 0 ? sudoers_main : sudo_res[i - 1];
    if (!c.ok) {
      out.warnings.push_back(sudo_files[i] + " not readable");
      continue;
    }
    for (const auto& raw : util::split(c.file.data, '\n')) {
      const std::string_view line = util::trim(raw);
      if (line.empty() || line[0] == '#') continue;  // comments (and #include directives, which are not rules)
      Observation o;
      o.type = "sudoers_line";
      o.key = sudo_files[i] + "|" + std::string(line);
      if (line.find("NOPASSWD") != std::string_view::npos) o.tags.push_back("nopasswd");
      o.data = {{"file", sudo_files[i]}, {"line", util::toValidUtf8(std::string(line))}};
      out.observations.push_back(std::move(o));
    }
  }
  return out;
}

}  // namespace agent
