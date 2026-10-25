<p align="right"><b>English</b> · <a href="USAGE.it.md">Italiano</a></p>

# dyna_cyber_agent — user guide

A C++ security agent that watches one or more Linux machines **read-only**, detects anomalies, checks whether
the installed software is affected by **known vulnerabilities (CVE) and weakness classes (CWE)** by downloading
public feeds periodically, has a local LLM (llama-server) assess what it finds, and reports to the administrator
by mail (HTML + plain text). A local **web console** with an attack map lets you browse everything. Beyond single
rules it correlates findings into **incidents**, recognises what an update explains, ranks CVEs by real exploitability
and reach, compares machines of the same role, cross-checks kernel views against rootkits, learns the shape of log
messages, watches outbound traffic and logins, and matches public threat lists (§16).

```
 collectors ──► snapshots ──► baseline + rules ──► findings ──► LLM (analyst) ──► mail HTML/TXT
 (processes, network, users,   (SQLite)     (what is new /      (deduplicated)  (assesses, correlates,  (alert + digest)
  logs, persistence, system,                what is malicious)                   recommends)
  files, package integrity,
  installed software) ◄── CVE / CISA KEV / CWE / OSV feeds (downloaded on the agent machine)
      ▲
  transport: local  or  SSH (read-only gate)
```

**Read-only guarantee.** On the machine being analysed the agent never writes: it reads `/proc`, `/etc`, logs,
and only runs commands from a whitelist hard-coded in the program (not configurable). The only state it writes is
its own database (`state_dir`), on the machine where the agent runs.

---

## 1. Requirements and build

| What | Details |
|---|---|
| System | Linux. On a target you need the GNU tools (coreutils/findutils): `base64`, `find -printf`, `stat -c`, `sha256sum`, `head`, `grep` |
| Compiler | g++ with C++20, CMake ≥ 3.20, Ninja (recommended) |
| Libraries | spdlog, SQLite3, libcurl, zlib (from the system); yaml-cpp, nlohmann_json and Catch2 are fetched by CMake if missing |
| For SSH | the OpenSSH client (`/usr/bin/ssh`) on the agent machine |
| For the LLM | `llama-server` (llama.cpp) with a GGUF model, e.g. Qwen3-Coder Q8 |

```bash
make                  # configures with CMake and builds (see `make help`)
make test             # about 210 test cases, about 25 s, none uses the network
./build/dyna_cyber_agent --help       # list of commands
```

The same without `make`: `cmake -S . -B build -G Ninja && cmake --build build && ctest --test-dir build --output-on-failure`.

On a machine without Internet access install `libyaml-cpp-dev`, `nlohmann-json3-dev` and `catch2` before building.

Installable package (binary, rules, systemd unit, examples), from the `build` directory:

```bash
cpack                                   # produces dyna-cyber-agent_<version>_amd64.deb and a .tar.gz  (or: make package)
sudo apt install ./dyna-cyber-agent_0.9.0_amd64.deb
```

The `.deb` creates the `dyna_cyber_agent` user and the directories, copies the rules and an example configuration
to `/etc/dyna_cyber_agent/` (never overwriting existing files) and **starts nothing**: see §10.

If the file sits in your home directory, `apt` prints a warning that the download "is performed unsandboxed as root
because the user `_apt` cannot access the file": it is harmless (apt only reads a local file), and it goes away if you
install from a directory everybody can read (`cp dyna-cyber-agent_*.deb /tmp/ && sudo apt install /tmp/dyna-cyber-agent_*.deb`).
If apt ends with an error *after* the line "Setting up dyna-cyber-agent", check what was installed before repeating:
`dpkg -s dyna-cyber-agent | grep Status` must say `install ok installed`, and `ls /etc/dyna_cyber_agent` must show
`agent.yaml`, `rules` and `keys`. If it does, the package is fine (the error then comes from a hook of another package
that apt runs at the end); if it says `half-configured`, run `sudo dpkg --configure -a` and read its output.

---

## 2. Quick start (monitor this machine)

```bash
# 1) minimal configuration
mkdir -p ~/agent && cp config/agent.example.yaml ~/agent/agent.yaml
$EDITOR ~/agent/agent.yaml            # keep only the "localhost" target; set state_dir and rules_dir

# 2) check that everything is valid (config + rules), without contacting anyone
./build/dyna_cyber_agent --config ~/agent/agent.yaml --check

# 3) first snapshot: during the first days the agent LEARNS what is normal and reports no drift
./build/dyna_cyber_agent --config ~/agent/agent.yaml --once

# 4) run continuously (Ctrl+C to stop)
./build/dyna_cyber_agent --config ~/agent/agent.yaml
```

Minimal configuration to try it out (no LLM, no mail):

```yaml
state_dir: /home/user/agent/state
rules_dir: /home/user/dyna_cyber_agent/rules/default
llm: { enabled: false }
targets:
  - { name: localhost, transport: local }
```

---

## 3. Commands

`dyna_cyber_agent --config <file> [mode]`

| Mode | What it does |
|---|---|
| *(none)* | runs continuously until SIGINT/SIGTERM: one thread per target, old-data cleanup, LLM, mail, and the web console if enabled |
| `--check` | validates config and rules, checks the configured SMTP/LLM (without contacting them), local self-test |
| `--once` | runs every collector once, stores, analyses, prints snapshots and new findings; uses the LLM/mail right away if configured |
| `--events [--all]` | lists open findings (`--all` includes accepted ones) |
| `--event <id>` | detail of one finding: evidence, what is missing from the baseline, the LLM assessment |
| `--accept <id> [--note <text>] [--days <n>]` | "this is normal": marks it accepted and adds its drift to the baseline; the note records why, `--days` makes the decision expire (the finding reopens and reports again). The console does the same (§16.13) |
| `--reopen <id>` | takes an accepted finding back: what the decision had added to the baseline is removed and the finding is open again (§16.13) |
| `--baseline-status` | per target: LEARNING or ENFORCING, start/end of learning and the number of learned items |
| `--baseline-lock` | ends the learning phase of all targets now |
| `--analyze` | has the LLM assess the open findings that have no assessment yet |
| `--llm-prompt` | **prints** the exact prompt that would go to the LLM (no network) |
| `--llm-ping` | checks that llama-server is ready and compares the context size |
| `--report-preview alert\|digest\|test [--out dir]` | writes the mail's `.html`/`.txt` files; **sends nothing** |
| `--send-test-mail` | sends a test mail to the configured recipients |
| `--notifications` | lists the mails that were sent or failed |
| `--ssh-test <target\|all>` | tests the SSH connection, remote tools and privileges; collects nothing |
| `--print-gate` | prints the gate script to install on the target (hardened mode); needs no `--config` |
| `--version` | prints the version |
| `--vuln-sync [kev\|nvd\|cwe\|epss\|all]` | downloads the CVE / CISA KEV / CWE / EPSS feeds now (resumable; Ctrl+C is safe) |
| `--vuln-status` | state of the vulnerability database and of the matching for each target |
| `--vuln-search <text\|CVE-id>` | looks a CVE up in the local database (score, CWE, actively exploited or not) |
| `--vuln-check [target]` | matches a target's software inventory against the database now (queries OSV: see §13.6) |
| `--incidents` | chains the open findings into incidents now and lists them with their timeline (§16.2) |
| `--intel-update` | downloads the public threat-intelligence IP lists now (§16.9) |
| `--intel-status` | shows the threat lists on disk (entries, date) |
| `--geo-update` | downloads the offline IP-location database used by the attack map (§15.1) |
| `--geo-import <file>` | builds that database from a CSV / `.csv.gz` you downloaded yourself |
| `--geo-status` | shows the location database in use |
| `--web` | serves only the web console (no collection): browse the data already collected (§15) |

Exit codes: `0` ok, `1` error (config, network, failed collector), `2` wrong command-line usage.

---

## 4. Typical workflow

### 4.1 Learning the baseline

For the first `baseline.learning` days (default 7) the agent **learns** processes, binaries (with hashes), listening
ports, outbound destinations, users, SSH keys and sudo rules. In this phase only the "absolute" rules fire (e.g. a
shell launched by nginx, a deleted binary in `/tmp`), not the "novelty" ones.

**What exactly happens during learning**

* Everything it sees goes into the baseline **without raising findings**: a new process, a new port, a new user,
  a new cron job, a new SSH key. If something malicious is running on the machine during those days it is learned
  as normal: this is why learning should happen on a machine in a known-good state.
* These stay **always active**: the absolute rules (shell from a web server, deleted binary, ...), the log rules
  (brute force, successful login after many failures), file integrity and the **vulnerabilities (CVE)**, which do
  not depend on the baseline.
* The window starts at the target's **first snapshot**. `--baseline-status` shows when it started, when it ends and
  how many days are left; the log reports the same at startup. `--baseline-lock` closes it early.
* The AI's **correlations** (attack chains) are built from findings: while learning there are few "novelty" findings
  to link, so correlations are rare. After learning they become more frequent. This is not a model defect: it lacks
  the raw material.

```bash
dyna_cyber_agent --config agent.yaml --baseline-status
# localhost: LEARNING, 241 identities
#   learning started 2026-10-22 08:00:00 UTC, window 7 day(s)
#   ends 2026-10-29 08:00:00 UTC (5 day(s) left): ...
```

When the machine has shown its normal behaviour (a full work cycle: nightly backups, cron, deployments), close the
learning phase:

```bash
dyna_cyber_agent --config agent.yaml --baseline-lock
# localhost: ENFORCING (locked), 241 identities
```

> The 7-day count starts at the target's first snapshot: if the daemon stays off, the window expires anyway with
> little data. It is better to leave it running continuously, or use `--baseline-lock` when you are ready.

### 4.2 Reviewing and closing findings

```bash
dyna_cyber_agent --config agent.yaml --events
# #2 [medium] PROC-007 Executable never seen on this host | web01 | proc|/opt/tool/run|1000 | seen 3x ... | open

dyna_cyber_agent --config agent.yaml --event 2        # detail, evidence and AI assessment
dyna_cyber_agent --config agent.yaml --accept 2       # it is legitimate: it enters the baseline and is not reported again
```

A finding that is not accepted stays open and appears in the digests; repetitions do not generate new mails
(deduplication).

**Life cycle.** Findings about *state* data (processes, ports, files, configuration, packages, vulnerabilities)
**resolve by themselves** when the condition disappears: update a package and its vulnerabilities become
*resolved*; if the problem comes back, the finding reopens **without sending the mail again**. The digest counts how
many were resolved in the period. **Log** findings are history and stay open until you accept them.
`--events --all` also shows accepted and resolved ones.

### 4.3 After a software update

Updating a package changes the binaries' hash (`PROC-008`) and can make "new" processes appear. After a planned
update, review the findings and accept them (`--accept`), or restart the learning by deleting that target's
database (see §10).

---

## 5. Configuration (`agent.yaml`)

A complete, commented example is in `config/agent.example.yaml`. Configuration errors stop the start with a precise
message (key name and reason). A key set to `null`, `~` or left empty counts as "not set".

### 5.1 General

| Key | Default | Meaning |
|---|---|---|
| `language` | `it` | `it` or `en`. **The one language setting**: mail labels (HTML and TXT), the text written by the AI, and the web console. Rule titles and MITRE/CWE names are always English. Replaces the old `alerting.language` and `llm.language`, which are now rejected |
| `log_level` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `critical`, `off` |
| `log_file` | *(empty)* | if set, also writes to a file (besides stderr) |
| `state_dir` | `/var/lib/dyna_cyber_agent` | SQLite databases (`agent.db`: snapshots, baseline, findings, analyses, mails, attack sources; `vuln.db`; `geo.db`) and the web token |
| `retention_days` | `14` | older snapshots are deleted (findings, baseline and attack-source history are kept) |
| `rules_dir` | `/etc/dyna_cyber_agent/rules` | directory with the rules' `.yaml` files (subdirectories too). It must be a directory, not a pattern |
| `baseline.learning` | `7d` | duration of learning (`30s`, `5m`, `2h`, `7d`) |

Only one agent may use a given `state_dir`: a lock file (`agent.lock`) makes a second instance refuse to start.
Keep the directory private (`chmod 750`): it holds the baseline and evidence.

### 5.2 Targets

```yaml
targets:
  - name: localhost            # unique name, shown in reports
    transport: local           # local | ssh
    collectors: all            # or [processes, network, users]
    interval: { processes: 30s, network: 15s, users: 5m }   # optional; these are the defaults
```

`collectors: all` enables all thirteen collectors (see §5.5). Targets are collected **in parallel**: a slow or
unreachable host does not slow the others down.

`group: web` (optional) puts the target in a peer group: machines with the same group are compared with each other
(§16.4; at least 3 members).

Log-specific keys (the `logs` collector):

| Key | Default | Meaning |
|---|---|---|
| `log_paths` | *(autodetected)* | list of log files; prefix `auth:`, `web:`, `kernel:` or `syslog:` to force the type; `*` and `?` are allowed only in the file name, e.g. `web:/srv/logs/*.access.log` |
| `log_backfill_kb` | `0` | the first time a log is read, also reads the last N KB (0 = starts from the end, without re-reading history) |

SSH keys (`transport: ssh`):

| Key | Default | Meaning |
|---|---|---|
| `host`, `user`, `key` | *(required)* | destination and the agent's private key |
| `port` | `22` | |
| `known_hosts` | `~/.ssh/known_hosts` | file with the host keys; verification is **always** on |
| `proxy_jump` | — | bastion: `user@host[:port]` |
| `gate` | `stream` | `stream` = nothing to install; `installed` = runs the script already present on the target |
| `gate_path` | — | (`installed` only) absolute path, e.g. `/usr/local/bin/dyna_cyber_agent-gate` |
| `sudo` | `false` | (`installed` only) runs the gate with `sudo -n` to read every user's processes |
| `connect_timeout` | `10` | seconds for connection + authentication |
| `op_timeout` | `30` | seconds for each batch of reads |
| `ssh_binary` | `/usr/bin/ssh` | absolute path of the ssh client |

The private key must be **readable by the user the agent runs as**. A key created with `sudo` in a root-only
directory is not: SSH then silently falls back to a password and the test fails with `Permission denied (publickey,password)`.

### 5.3 LLM

```yaml
llm:
  enabled: true
  url: http://127.0.0.1:8080
  timeout: 300              # seconds per request (a large Q8 model can be slow)
  temperature: 0.2
  max_tokens: 4096
  context_tokens: 32768     # not above llama-server's -c (check it with --llm-ping)
  max_findings_per_call: 8
  batch_window: 30s         # groups nearby findings into a single call
  model: ""                 # optional
  api_key_file: ""          # only if llama-server uses --api-key
  focus_file: ""            # administrator instructions, see §8
```

### 5.4 Mail

```yaml
alerting:
  min_severity: high        # info | low | medium | high | critical: threshold for immediate alerts
  alert_delay: 2m           # wait for the AI assessment and to group related findings
  cooldown: 5m              # minimum pause between two alerts (critical ones skip it)
  max_per_hour: 6           # hard cap on alerts per hour
  subject_prefix: "[dyna_cyber_agent]"
  recipients: [admin@example.com]
  smtp:
    host: smtp.example.com
    port: 587
    tls: starttls           # starttls | ssl | none  (none with a password is refused, except for localhost)
    user: agent
    password_file: /etc/dyna_cyber_agent/smtp.pass     # chmod 600
    from: "dyna_cyber_agent <agent@example.com>"
    timeout: 30
  digest:
    enabled: true
    every: 24h              # or  at: "08:00"  (local time)
    min_severity: low
    send_when_empty: false  # true = also send "nothing new" (heartbeat). A stopped collector always forces the mail
```

Without `recipients` the agent works normally but sends no mail. The same address listed twice (or with different
capitalisation) receives one copy.

**Internal SMTP relay without authentication** (typical on a LAN): do **not** set `user:` or `password_file:`, and
use `tls: none`. The agent refuses to send credentials over an unencrypted connection (except to `localhost`), so if
a `user:` is left in (even the one from the example configuration) the configuration is rejected and the error
names the responsible field.

```yaml
  smtp: { host: 192.168.1.25, port: 25, tls: none, from: "dyna_cyber_agent <agent@yourdomain.lan>" }
```

---

### 5.5 The collectors

*For vulnerabilities (CVE/CWE) there is a dedicated `vuln:` section: see §13.4.*

| Collector | Interval | What it observes | Privileges / cost |
|---|---|---|---|
| `processes` | 30 s | processes, executables with SHA-256 hash, parent, rwx memory, deleted binaries or binaries in `/tmp` | root or `CAP_SYS_PTRACE` to see all processes |
| `network` | 15 s | TCP/UDP/raw/unix/packet sockets and the owning process | same as above for the owners |
| `users` | 5 min | accounts, groups, password state (never the hash), SSH keys, sudo rules | root for `shadow` and `sudoers` |
| `logs` | 30 s | `auth.log`/`secure` (sshd, sudo, su, useradd...), nginx/apache access logs, `kern.log`, journald | group `adm` (or root) to read the logs |
| `persistence` | 5 min | cron (system and users), systemd units, shell startup files (`.bashrc`, `profile.d`...), `rc.local`, `init.d`, `ld.so.preload` | root for other users' crontabs |
| `system` | 10 min | kernel modules and taint, security sysctls, mounts, DNS and `/etc/hosts`, `sshd_config`, promiscuous interfaces, nodes in `/dev` | almost everything is readable without privileges |
| `files` | 30 min (SUID every 6 h) | SUID/SGID files, executable/hidden/setuid files in `/tmp` `/var/tmp` `/dev/shm` (ordinary files are only counted), world-writable files in system directories, executables in `/usr/local` `/opt` `/srv` | the SUID search walks the **whole disk** at the lowest priority (nice 19, ionice idle): on large disks it can take 10+ minutes, so it runs at most every 6 hours; the first `--once` is slow |
| `integrity` | 6 h | compares installed files with the packages (`dpkg -V` / `rpm -Va`) | heavy on the disk; root to read all files |
| `packages` | 6 h | distribution, kernel and **all installed packages** (with the source package), from `/var/lib/dpkg/status` or `rpm -qa`; also installs/upgrades/removals and the files each package owns (§16.1) | light (3,600 packages in ~30 ms; file lists are read 600 packages per run) |
| `vulns` | 1 h | matches the inventory against the CVE database (see §13); **reads nothing from the target**, it works on the agent machine | requires `packages`; uses the network towards OSV if enabled |
| `peers` | 30 min | compares the target with the other members of its `group:` (§16.4); **reads nothing from the target** | needs `group:` with 3+ members and recent data of the others |
| `crossview` | 10 min | the same thing through two kernel interfaces (processes, modules, ports) and the eBPF programs (§16.5) | everything it reads is world-readable; `kallsyms` is read once an hour |
| `netflow` | 2 min | steady outbound connections and the outbound traffic rate (§16.7); works on what `network` recorded plus `/proc/net/dev` | light |

Logs are read **incrementally**: only the lines that are new since last time. The offsets are in the database, so a
restart neither loses nor repeats lines. Rotation (even with inode reuse) is recognised and the tail of the rotated
file is still read. If the classic files are missing the agent uses `journalctl`. Log events are aggregated: 10
failed logins from the same address are **one** finding that counts the repetitions, and a successful login after 3
or more failures from the same address is reported as critical. Event time is the collection time: the time zone
and the missing year of syslog lines do not matter.

To limit the collectors (or avoid the heavy ones on a target): `collectors: [processes, network, users, logs]`.

## 6. Monitoring remote machines over SSH

### 6.1 How it works (and why it is safe)

The agent starts the system `ssh` client with strict options (`BatchMode`, `StrictHostKeyChecking=yes`, no
agent/forwarding/password). On the other side runs the **gate**: a small `sh` script that accepts only read-only
requests (`read`, `readlink`, `ls`, `stat`, `sha256`, ...) and can only run a fixed list of commands. Requests
travel in batches: a full `/proc` scan takes a few round trips instead of thousands. The gate (protocol
**version 2**) can also read logs from where you left off, read the journal and run only the predefined filesystem
scans (`find` at the lowest priority). If you update the agent and the installed gate is from an earlier version,
`--ssh-test` and the log say so: just run `--print-gate` again on the target.

Two modes:

| | `gate: stream` (default) | `gate: installed` (recommended in production) |
|---|---|---|
| Installation on the target | none | root-owned script + a sudoers line + `command=` in authorized_keys |
| If the key is stolen | the attacker has a shell as `audit-ro` | they can only send the gate's read-only requests |
| Visibility of other users' processes | only if the ssh user is privileged | complete, with `sudo: true` |

**You do not install the agent on the targets.** The only thing that goes on a target is the gate: a single text
script (no compiled binary, no database, no LLM). All analysis, the database, the LLM and the mail stay on the
agent machine. You can read the script before installing it: `dyna_cyber_agent --print-gate | less`.

### 6.2 Step by step (hardened mode)

**On the agent machine** — dedicated key and host keys:

```bash
sudo mkdir -p /etc/dyna_cyber_agent/keys && sudo chmod 700 /etc/dyna_cyber_agent/keys
sudo ssh-keygen -t ed25519 -N '' -C dyna_cyber_agent@monitor01 -f /etc/dyna_cyber_agent/keys/web01

# the target's host key: fetch it and VERIFY the fingerprint through an independent channel (e.g. the console)
ssh-keyscan -p 22 -t ed25519 web01.example.com | sudo tee -a /etc/dyna_cyber_agent/known_hosts
ssh-keygen -lf /etc/dyna_cyber_agent/known_hosts            # compare with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the target
```

The agent never accepts new host keys on its own (no trust-on-first-use).

> The files in `/etc/dyna_cyber_agent/keys/` must be readable by the user the agent runs as. If you create them
> with `sudo` and then run the agent as a normal user, either `chown` them to that user or keep the key in that
> user's home (e.g. `~/agent/keys/web01`, mode 600) and point `key:` there.

**On the target** — user, gate and sudo (as an administrator, in an interactive session):

```bash
sudo useradd -m -s /bin/sh audit-ro            # the shell must be POSIX-compatible (sh/bash/dash)
```

The gate must be owned by root and **not writable by `audit-ro`** (it runs as root through sudo!). Install it from the
agent machine in two steps (a plain `... | ssh host 'sudo tee ...'` fails when sudo needs a password, because the
pipe occupies stdin and there is no terminal):

```bash
# on the agent machine
dyna_cyber_agent --print-gate > /tmp/dyna_cyber_agent-gate           # optional: read it
scp /tmp/dyna_cyber_agent-gate admin@web01:/tmp/dyna_cyber_agent-gate
ssh -t admin@web01 'sudo install -o root -g root -m 755 /tmp/dyna_cyber_agent-gate /usr/local/bin/dyna_cyber_agent-gate && rm /tmp/dyna_cyber_agent-gate'
```

Then, on the target:

```bash
# sudo: audit-ro may run ONLY the gate
echo 'audit-ro ALL=(root) NOPASSWD: /usr/local/bin/dyna_cyber_agent-gate' | sudo tee /etc/sudoers.d/dyna_cyber_agent
sudo chmod 440 /etc/sudoers.d/dyna_cyber_agent && sudo visudo -c

# audit-ro's authorized_keys: the key can run only the gate
sudo -u audit-ro mkdir -p -m 700 /home/audit-ro/.ssh
echo 'command="sudo -n /usr/local/bin/dyna_cyber_agent-gate",restrict ssh-ed25519 AAAA...public-key... dyna_cyber_agent@monitor01' \
  | sudo -u audit-ro tee /home/audit-ro/.ssh/authorized_keys
```

Paste the content of `web01.pub` in place of `AAAA...public-key...`: one line, preceded by the `command=` option.
The home directory must not be writable by others; `.ssh` is `700` and `authorized_keys` `600`, owned by `audit-ro`.

**In the agent's config:**

```yaml
  - name: web01
    transport: ssh
    host: web01.example.com
    user: audit-ro
    key: /etc/dyna_cyber_agent/keys/web01
    known_hosts: /etc/dyna_cyber_agent/known_hosts
    gate: installed
    gate_path: /usr/local/bin/dyna_cyber_agent-gate
    sudo: true
```

**Test** (collects nothing; the output below is an example, the values change):

```bash
dyna_cyber_agent --config agent.yaml --ssh-test web01
# web01: connected to 'web01' in 85 ms (gate: installed + sudo)
#   remote tools: base64=ok find=ok stat=ok sha256sum=ok head=ok grep=ok ... find_printf=ok stat_c=ok uid=0
#   scan test: 212/214 process stat files read in 310 ms
#   run test: ok (Linux 6.8.0 ...)
```

Finally **restart the agent**: the configuration is read only at start (a `SIGHUP` reloads the rules, not the targets).
The new target starts its own learning window (§4.1).

### 6.3 Quick mode without installing anything

For a first test the SSH configuration without `gate`/`sudo` is enough (`stream` mode). It works immediately, but a
normal `audit-ro` user **cannot read `/proc/<pid>/exe`, `fd` and `maps` of other users' processes**: other users'
processes and the owners of sockets will be invisible (the agent reports it in the warnings and `--ssh-test` prints a
note). To see them you need privileges: an installed gate with `sudo` (above), or the `root` user (not recommended).

### 6.4 Common problems

| Symptom | Cause / fix |
|---|---|
| `Host key verification failed` | the host key is not in `known_hosts`: add it (§6.2) |
| `Permission denied (publickey)` | the public key is not in `authorized_keys`, wrong permissions on `~/.ssh` or the home directory, or `key:` does not point to the private key |
| `Load key "...": Permission denied` followed by `Permission denied (publickey,password)` | the agent's user cannot read the private key file (see the note in §6.2) |
| `unexpected greeting ... is the gate installed and up to date?` | the remote command is not the gate: wrong `gate_path`, `sudo` asking for a password, or a different gate version (reinstall with `--print-gate`) |
| `MISSING` in `--ssh-test` | the target lacks the GNU tools (e.g. BusyBox/Alpine is not supported) |
| `unreachable ...; retrying later` | after an error the agent waits 15 s before retrying; the target is reported in the digest as "STALE" |
| `command not available over ssh` | that command is not in the gate's list (see `Gate::commands()` in `src/transport/gate.cpp`) |

---

## 7. Rules

Rules are YAML files in `rules_dir` (one example per type in `rules/default/`: **151 rules** in `processes`,
`network`, `users`, `logs`, `persistence`, `system`, `files`, `vulns`, `peers`, `crossview` and `intel`, all with
MITRE ATT&CK tags, a description and a remediation). A wrong rule (operator, regex, non-existent type or facet) **stops the start** with the file and
the rule name: a typo cannot make a rule silently never fire.

```yaml
- id: LOCAL-001                      # unique across all directories
  title: Interpreter listening on the network
  severity: high                     # info | low | medium | high | critical
  mitre: [T1571]
  description: A script interpreter listens on a non-local address.
  remediation: Identify the process and check where the script comes from.
  match:
    type: socket.inet                # observation type (table below)
    tags_all: [listening, exposed]   # all tags; or tags_any: [...]
    drift: net.listen                # (opt.) requires the item NOT to be in the baseline: "any" or a facet
    drift_absent: [process.exe]      # (opt.) facets that must NOT be in drift
    where:                           # (opt.) all conditions (AND)
      - {field: owners.comm, op: regex, value: '^(python|perl|ruby|php|node)'}
      - any:                         # any / all / not can be nested
          - {field: local_port, op: gt, value: 1024}
          - {not: {field: proto, op: equals, value: tcp}}
```

Operators: `equals`, `in` (list), `startswith`, `endswith`, `contains` (also with a list = any of them), `regex`
(ECMAScript, search), `exists` (true/false), `gt`, `gte`, `lt`, `lte`. A field that is an array (e.g. `owners.comm`)
matches if **at least one** element satisfies the condition; `owners.0.comm` is the first one. A rule with no
conditions at all is rejected (it would fire on everything). An optional `cwe: [CWE-732]` list tags the weakness
class the rule is about.

Fields by observation type:

| `type` | Main fields | Tags |
|---|---|---|
| `process` | `pid` `ppid` `comm` `uid` `gid` `exe` `exe_sha256` `parent_exe` `cwd` `cmdline[]` `rwx_mappings` `start_time` `kernel_thread` | `exe_deleted` `exe_memfd` `exe_in_volatile_dir` `comm_mismatch` `rwx_memory` |
| `socket.inet` | `proto` `local_addr` `local_port` `remote_addr` `remote_port` `state` `uid` `owners[].{pid,comm,exe}` `remote_cc` `ti.{list,category}` | `listening` `exposed` `raw_socket` `ti_malicious` `ti_c2` |
| `socket.unix` | `path` `type` `listening` `owners[]` | `listening` `abstract` `in_volatile_dir` |
| `socket.packet` | `type` `proto` `uid` `owners[]` | `packet_socket` |
| `user` | `name` `uid` `gid` `home` `shell` `login_shell` `password` (`locked`/`empty`/`set`/`unknown`) `privileged_groups[]` | `uid0` `uid0_not_root` `login_shell` `empty_password` |
| `authorized_key` | `user` `file` `type` `blob` `comment` `options` | `has_options` `forced_command` `root_key` |
| `sudoers_line` | `file` `line` | `nopasswd` |
| `group` | `name` `gid` `members[]` | — |
| `log.auth.login` | `user` `src_ip` `method` `port` `key_fingerprint` `count` `cc` `city` `lat` `lon` `hour_bucket` `travel.{from_ip,from_cc,distance_km,minutes,speed_kmh}` `ti` | `root_login` `password_login` `publickey_login` `external_ip` `impossible_travel` `ti_malicious` |
| `log.auth.bruteforce` | `src_ip` `failures` `distinct_users` `users[]` `invalid_user_attempts` `success_user` `day` | `external_ip` `many_users` `root_targeted` `success_after_failures` |
| `log.auth.sudo` / `sudo_failure` / `su` / `account` / `scan` | `user` `target_user` `command` `reason` `action` `name` `src_ip` `count` | `sudo_to_root` `sudo_shell` `not_in_sudoers` `su_failed` `account_created` `account_deleted` `password_changed` `group_change` |
| `log.web.attack` | `src_ip` `category` `count` `success_responses` `statuses` `sample_uri` `user_agent` | `web_sqli` `web_path_traversal` `web_rce` `web_lfi_rfi` `web_log4shell` `web_shellshock` `web_webshell` `web_scanner_ua` `web_sensitive_probe` `got_success_response` `external_ip` |
| `log.web.scan` | `src_ip` `errors_4xx` `distinct_paths` | `external_ip` |
| `log.kernel` | `event` (`promisc` `segfault` `oom_kill` `syn_flood` `module_taint`...) `count` | `promiscuous_mode` `segfault` `module_taint` `kernel_fault` `syn_flood` `oom_kill` |
| `log.source` | per-address activity for the attack map (§15.1); no rule matches it | — |
| `cron.entry` | `file` `schedule` `user` `command` `owner_crontab` | `reboot` `command_in_volatile_dir` `pipe_to_shell` `base64_exec` `reverse_shell` |
| `cron.script` / `startup.file` | `path` `sha256` `size` `kind` `owner` | `ld_preload` `alias_hijack` `anti_forensics` `reverse_shell` `pipe_to_shell` `base64_exec` `volatile_dir_reference` `ssh_rc` |
| `systemd.unit` | `path` `name` `exec[]` `user` `wanted_by[]` `schedule` `listen` `sha256` | `admin_unit` `exec_in_volatile_dir` `hidden_unit` + the tags of suspicious contents |
| `systemd.enabled` / `preload.entry` | `unit` `wants_dir` / `library` | `ld_so_preload` |
| `kernel.module` / `kernel.taint` | `name` `size` `used_by[]` `taint` / `value` `flags` | `module_unsigned` `module_out_of_tree` `unsigned_module` |
| `sysctl.value` | `key` `value` `expected` | `weak_setting` |
| `mount.entry` / `net.dns` / `net.hosts_entry` | `mountpoint` `fstype` `options[]` / `nameserver` / `ip` `names[]` | `exec_allowed_in_tmp` `fuse_mount` |
| `sshd.option` | `name` `value` `value_lc` | `weak_setting` `permit_root_login` `permit_empty_passwords` `permit_user_environment` `password_authentication` `authorized_keys_command` `gateway_ports` `permit_tunnel` |
| `net.iface` | `name` `flags` `promisc` | `promiscuous` |
| `dev.node` | `path` `type` `mode` `uid` | `regular_file_in_dev` `hidden_file` `executable` `world_writable_device` |
| `file.entry` | `preset` (`suid` `volatile` `writable` `localexec`) `type` `mode` `user` `size` `mtime` `path` `magic` | `suid` `sgid` `suid_root` `outside_system_dirs` `suid_gtfobin` `executable` `hidden` `binary_executable_format` `script_file` `setuid_or_setgid` `world_writable_file` `world_writable_dir` `in_binary_dir` |
| `pkg.verify` | `path` `flags` `config` `manager` | `system_binary_modified` `content_changed` `config_file` `missing` `permissions_changed` |
| `vuln.match` | `cve` `package` `installed_version` `fixed_version` `cvss` `kev` `cwes[]` `published` `confidence` (see §13), `epss` `epss_percentile` `exposure` `ports[]` `priority` `exposed_likely_exploited` (§16.3) | `kev` `recent` `established` `fix_available` `no_fix_known` `upstream_version_match` `unscored` `kernel` `epss_high` `listening` `listening_local` `running` `reboot_pending` |
| `os.reboot_required` | `required` `packages[]` | `reboot_pending` |
| `peer.deviation` | `group` `kind` (`unique`/`missing`) `facet` `item` `peers` `peers_with_it` | `peer_unique` `peer_missing` `sensitive` |
| `crossview.hidden_pid` / `hidden_module` / `hidden_port` | `pid` `comm` / `name` / `port` and `seen_in` `missing_from` | `hidden_process` `hidden_module` `hidden_port` |
| `bpf.program` / `bpf.pinned` | `tag` `name` / `name` `is_dir` | — |
| `log.template` | `program` `template` `hash` `sample` `count` `alarming` | `alarming_words` |
| `net.beacon` | `dest` `port` `comm` `events` `period_s` `jitter` `uncommon_external` | `beacon` `external_dest` |
| `net.traffic_spike` | `interface` `rate_kbps` `usual_kbps` | `traffic_spike` |

Baseline facets (for `drift` / `drift_absent`): `process.exe` `process.binary` `process.lineage` `process.user`
`net.listen` `net.raw` `net.outbound` `net.unix` `net.packet` `user.account` `user.privgroup` `ssh.key` `sudo.rule`
`auth.login` `auth.sudo` `cron.entry` `cron.script` `systemd.unit` `systemd.enabled` `startup.file` `kernel.module`
`kernel.taint` `sysctl.value` `mount.entry` `net.dns` `net.hosts` `sshd.option` `dev.node` `file.suid`
`file.localexec` `bpf.program` `bpf.pinned` `log.template` `net.beacon` `net.country` `auth.country` `auth.hour`. Ports above 32767 and the numbers in unix socket names are normalised, so random ports do not
create noise.

To try a new rule: save it in `rules_dir` and run `dyna_cyber_agent --config agent.yaml --check`.

---

## 8. Assessment with the LLM (Qwen3-Coder Q8 on llama-server)

The LLM does **not detect**: it assesses the findings the rules have already produced (verdict, risk, explanation,
recommended actions, correlations between findings). It has no tools and cannot act on any machine. The
**vulnerabilities (CVE)** are not assessed one by one by the model (the score and the source are already in the
data): the model only receives them in aggregate form, for the single report of each mail (§9.2).

Starting the server (example):

```bash
llama-server -m Qwen3-Coder-30B-A3B-Instruct-Q8_0.gguf -c 32768 --jinja -ngl 99 --host 127.0.0.1 --port 8080
```

```bash
dyna_cyber_agent --config agent.yaml --llm-ping        # is the server ready? is the context large enough?
dyna_cyber_agent --config agent.yaml --llm-prompt      # see what would be sent (no network)
dyna_cyber_agent --config agent.yaml --analyze         # assess the open findings that have no assessment
dyna_cyber_agent --config agent.yaml --event 7         # also shows the AI assessment
```

Security: the data from the machine is treated as **untrusted** (it can contain text that tries to manipulate the
LLM). The prompt says so, the reply is validated (invented ids discarded, enums checked, text cleaned) and, if the
evidence contains instructions aimed at the AI, the agent adds the `prompt_injection_suspected` flag and raises the
risk to *medium* — the model cannot remove it. The AI's judgement sits next to the rule's severity: it can raise
it, **never lower it** in the mails.

If llama-server does not answer, the findings stay stored without an assessment and the agent retries every 10
minutes (after 3 failed calls it suspends the LLM for 5 minutes).

**Instructions to the analyst** (`llm.focus_file`): a free text file, for example

```
This is a production machine with nginx + php-fpm. Pay particular attention to shells launched by the
web server, new listening ports and changes to SSH keys. Deployment happens every Tuesday
with the user "deploy": its processes in /srv/app are normal.
```

It guides the emphasis of the assessment but cannot override the security rules of the prompt.

---

## 9. Mail and reports

```bash
dyna_cyber_agent --config agent.yaml --report-preview alert --out /tmp/prev   # /tmp/prev/alert.html + alert.txt
dyna_cyber_agent --config agent.yaml --report-preview digest
dyna_cyber_agent --config agent.yaml --send-test-mail                          # verify SMTP
dyna_cyber_agent --config agent.yaml --notifications                           # history of sent mails
```

(The previews never call the LLM, so their AI section is the "unavailable" note. The web console can generate the
same previews with the AI summary: §15.)

### 9.1 Why am I getting a mail

Two kinds of mail, with different rules:

* **Alert** (immediate) — only for a **new security problem** with severity ≥ `min_severity`, or a vulnerability
  that is **actively exploited (KEV)** or **just published**. "Old" vulnerabilities (published before
  `vuln.new_within_days`) **never trigger an alert**: they travel only in the digest. For vulnerabilities the
  severity is the rule's; the AI does not raise it. It goes out after `alert_delay`, at most one every `cooldown`
  (*critical* ones skip it) and `max_per_hour` per hour. **Everything** in the queue ends up in that mail and is
  marked as reported: no drip-feeding in later mails. An **incident** that reaches `min_severity` brings all its
  members along, even those that are below it on their own; a finding that an update explains (§16.1) waits for the digest
  unless it is critical. If SMTP is down the sending is retried with backoff (5, 10, 20,
  40, 60 minutes) reusing the same AI analysis: nothing is lost and a restart does not duplicate.
* **Digest** (periodic, `digest.every` / `digest.at`) — goes out **only if something is new or resolved in the
  period**, or a collector is stopped ("STALE" after 3 intervals). With `send_when_empty: true` it always goes out.
  New problems are described in detail; those already reported appear in a compact "Still open" list.

If you receive the **same mail twice**, check `recipients` (the same address written twice or with different
capitalisation is now ignored with a warning in the log) and that a second instance is not running: the agent takes
a lock `<state_dir>/agent.lock` and refuses to start if another instance uses the same `state_dir`.

### 9.2 What a mail looks like

1. **Header** — highest risk, period, counts by severity.
2. **AI analysis** — *one single* report per mail: headline, summary, priorities (actions in order), any
   correlations. The model also receives the summaries of the last mails sent with the instruction **not to repeat
   them**: it only says what is new or changed. Vulnerabilities appear in at most two sentences. If the model is
   unreachable the mail still goes out, with a note in place of the summary.
   The summary is at most four short sentences and never repeats the headline; if the model's text arrives cut it is
   shortened to the last complete sentence. Numbers are attributed to the right subject (attempts against an unknown
   account are not attempts against a real one), the priorities are at most four and never duplicates, and when an
   attacker got in (successful login after failures, or from an impossible location) the **first priority is
   containment**: end the account's sessions, rotate password and keys, block the address. It is an instruction to the
   model, not a check: a small model may ignore it.
3. **Incidents** — when findings chain together (§16.2): title with the stages, period, shared addresses and accounts and
   a **timeline**; the three most severe members keep a full card, the others live only in the timeline.
4. **Security findings** — the detailed cards (evidence, the AI's assessment of that finding, recommended actions). A
   finding that a package update explains carries a green "probably explained by an update" note (§16.1).
5. **Still open** (digest) — a compact reminder of what had already been reported.
6. **Vulnerabilities and references** (at the bottom) — the overall picture (how many, by CVSS severity, KEV, with a
   fix), a compact list per machine and package (CVE, CVSS, KEV/NEW, CWE, fixed version) and the aggregated
   references: **MITRE ATT&CK** (with the technique name), **CWE** (with the name) and the feed news (new KEV
   entries, etc.). Vulnerabilities are ordered by **priority** (§16.3): exploited, then likely to be exploited and
   reachable from the network, with EPSS and reach shown next to each CVE.
7. **Collector health** and a closing note.

Limits per mail: `max_items` security findings (default 30) and 60 vulnerabilities (the exploited and most severe
first); the rest is counted ("other N") and can be seen with `--events`.

Every mail is `multipart/alternative`: modern HTML (light/dark theme) and plain text with all the evidence. Content
that comes from the machine is always neutralised: HTML escaped, no clickable links (`http://` becomes `hxxp://`),
no control or text-direction-override characters.

---

## 10. Running in production

### 10.1 Installation

With the package (recommended): `sudo apt install ./dyna-cyber-agent_<version>_amd64.deb` (see §1). It creates:

```
/usr/bin/dyna_cyber_agent                  the binary
/etc/dyna_cyber_agent/agent.yaml           configuration (edit it)          root:dyna_cyber_agent 0640
/etc/dyna_cyber_agent/rules/               copy of the rules (editable; never overwritten)
/etc/dyna_cyber_agent/keys/                the agent's SSH keys             dyna_cyber_agent 0700, files 0600
/var/lib/dyna_cyber_agent/                 databases (agent.db, vuln.db, geo.db)   dyna_cyber_agent 0750
/var/log/dyna_cyber_agent/                 logs (if you set log_file)       + rotation in /etc/logrotate.d
/lib/systemd/system/dyna_cyber_agent.service    hardened systemd unit
/usr/share/dyna_cyber_agent/               USAGE.md, examples, original rules, sample sudoers/authorized_keys
```

Then: edit `agent.yaml` (targets, mail, LLM), check with
`dyna_cyber_agent --config /etc/dyna_cyber_agent/agent.yaml --check` and start:

```bash
sudo systemctl enable --now dyna_cyber_agent
journalctl -u dyna_cyber_agent -f              # "FINDING #..." lines for new detections
```

Manual installation: copy the binary, the rules and `deploy/dyna_cyber_agent.service`, create the user
(`useradd --system --home /var/lib/dyna_cyber_agent --shell /usr/sbin/nologin dyna_cyber_agent`) and the
directories above. `make install` installs under `PREFIX` (default `/usr/local`).

### 10.2 The systemd unit and why it is built this way

The supplied unit (`deploy/dyna_cyber_agent.service`) takes away from the agent everything it does not need
(`NoNewPrivileges`, `ProtectSystem=strict`, system-call filter, restricted address families,
`MemoryDenyWriteExecute`...) and writes only to `/var/lib/dyna_cyber_agent` and `/var/log/dyna_cyber_agent`. Three
choices worth knowing:

* **No `PrivateTmp` and no `PrivateDevices`**: the agent must see the **real** `/tmp` and `/dev` of the machine it
  monitors. With `PrivateTmp=yes` it would see an empty `/tmp` of its own and never find anything.
* **`ProtectHome=read-only`**: it reads the home directories (users' startup files) but does not modify them.
* **Capabilities `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`**: needed to read `exe`, `fd` and `maps` of *all*
  processes and the restricted files (`shadow`, `sudoers`) of the **local** target. If you monitor only SSH targets
  with gate + sudo, remove the two lines `AmbientCapabilities` and `CapabilityBoundingSet`: the agent then runs
  without privileges.

### 10.3 Management

* **Reload the rules without restarting**: edit the files and `sudo systemctl reload dyna_cyber_agent` (sends
  SIGHUP). If a rule is wrong the agent **keeps the current rules** and writes it to the log
  (`rules NOT reloaded, keeping the current ones: ...`): a typo does not blind it.
* **Permissions**: the agent works with `umask 027` and warns if `state_dir` is readable or writable by everyone.
  Created files (databases, previews) are `0640`. The web token is `0600`.
* **Backup**: copy `state_dir/agent.db` (baseline, findings, history, attack sources). `vuln.db` and `geo.db` can be
  rebuilt from the feeds.
* **Starting over for a target**: stop the agent, delete the database (or just the target) and restart: learning
  starts again.
* **Updating the agent with an installed gate**: the gate has a protocol number; if it changes, `--ssh-test` says so
  and you just run `--print-gate` again on the target.
* **Logs**: with `log_file` the rotation is in `/etc/logrotate.d/dyna_cyber_agent` (`copytruncate`, no restart);
  without `log_file` logs go to journald.

---

## 11. Usage examples

**One server, locally, no mail.** The minimal config of §2 and `dyna_cyber_agent --config agent.yaml`.

**Three servers over SSH with a daily digest at 08:00.**

```yaml
state_dir: /var/lib/dyna_cyber_agent
rules_dir: /etc/dyna_cyber_agent/rules
llm: { enabled: false }
alerting:
  recipients: [sec@example.com]
  smtp: { host: smtp.example.com, user: agent, password_file: /etc/dyna_cyber_agent/smtp.pass, from: "dyna_cyber_agent <agent@example.com>" }
  digest: { at: "08:00" }
targets:
  - { name: web01, transport: ssh, host: web01.example.com, user: audit-ro, key: /etc/dyna_cyber_agent/keys/web01, known_hosts: /etc/dyna_cyber_agent/known_hosts, gate: installed, gate_path: /usr/local/bin/dyna_cyber_agent-gate, sudo: true }
  - { name: web02, transport: ssh, host: web02.example.com, user: audit-ro, key: /etc/dyna_cyber_agent/keys/web02, known_hosts: /etc/dyna_cyber_agent/known_hosts, gate: installed, gate_path: /usr/local/bin/dyna_cyber_agent-gate, sudo: true }
  - { name: db01,  transport: ssh, host: db01.example.com,  user: audit-ro, key: /etc/dyna_cyber_agent/keys/db01,  known_hosts: /etc/dyna_cyber_agent/known_hosts, gate: installed, gate_path: /usr/local/bin/dyna_cyber_agent-gate, sudo: true, proxy_jump: "ops@bastion.example.com:2222" }
```

**Investigating an alert.** The mail "HIGH: 1 finding - web01" arrives →

```bash
dyna_cyber_agent --config agent.yaml --events
dyna_cyber_agent --config agent.yaml --event 12          # full evidence + AI assessment + recommended actions
# if it is legitimate:
dyna_cyber_agent --config agent.yaml --accept 12
```

**Checking the mail layout without sending anything.**

```bash
dyna_cyber_agent --config agent.yaml --report-preview alert --out /tmp/prev && xdg-open /tmp/prev/alert.html
```

---

## 12. What the agent does not (yet) do

* It does not read application logs other than auth, web (nginx/apache) and kernel: databases, mail servers, etc.
  are not analysed (they can be added with `log_paths`, but would be treated as generic syslog).
* Web-log analysis is signature based (SQLi, traversal, RCE, Log4Shell, webshell, scanners): it is not a WAF and
  does not see encrypted attacks or attacks in POST bodies.
* `sshd_config`: it reads the global options (before `Match`); it does not compute the effective configuration with
  all the `Match` conditions.
* Rootkits: it compares independent kernel views (§16.5), which catches the common ways of hiding a process, a
  module or a port, but a rootkit that falsifies *every* interface consistently is not seen. It also reports new
  kernel modules, eBPF programs, `ld.so.preload`, promiscuous interfaces and binaries that differ from the package.
* **Vulnerabilities**: it only sees software installed by the package manager (dpkg/rpm). Hand-built binaries,
  containers, pip/npm/gem packages are not in the inventory. For distributions not covered by OSV the match is by
  upstream version and can be wrong in both directions (§13.7). EPSS and reach (§16.3) rank them, but reach is known
  only for programs owned by a package (not libraries).
* Short-lived processes can generate a few low-value findings right after the baseline is locked: accept them with
  `--accept`.
* `dpkg -V` / `rpm -Va` are slow and an unprivileged user cannot read all files: the `integrity` collector really
  works only with root (or gate + sudo).
* The target must have GNU tools; BusyBox/Alpine is not supported.
* Without privileges on the target, other users' processes and many logs stay invisible (see §6.3).
* The AI analysis is advisory: always verify the evidence before acting.

---

## 13. Known vulnerabilities (CVE) and weaknesses (CWE)

### 13.1 What it does

The agent answers a simple question: **"is the software installed on my systems affected by known vulnerabilities,
including the ones published yesterday?"**

```
 target ──(packages collector)──► inventory (packages + source, distribution, kernel)
                                              │
   public feeds downloaded on the agent       ▼
   machine, never on the targets:      ┌──────────────────┐        ┌─────────────────────────┐
   • CISA KEV   (exploited in the wild)│ matching (vulns) │──────► │ findings + VULN-* rules │──► mail / digest
   • NVD        (CVE, CVSS, CWE, CPE)  │  OSV + NVD/CPE   │        │ (they close by themselves│
   • MITRE CWE  (weakness names)       └──────────────────┘        │  when you update)       │
   • OSV.dev    (distro advisories)                                └─────────────────────────┘
```

* **Every 6 hours** (`vuln.refresh_every`) a background thread refreshes the feeds. The NVD download is
  *incremental* (only the CVEs modified since last time) and **resumable**: if it is interrupted or the NVD throttles
  requests, it restarts from the same page.
* **Every hour** (`vuln.match_every`) the `vulns` collector matches each target's latest inventory against the
  database.
* A **new** CVE that affects an installed package becomes a finding the first time it appears (and a mail if it
  exceeds `alerting.min_severity`); when you update the package the finding **resolves by itself**.
* The **digest** has a "Vulnerability intelligence" section: feed state, new CISA KEV entries of the period, how many
  actively exploited ones are present on your systems, new vulnerabilities found and the most frequent weakness
  classes (CWE).

### 13.2 How reliable the matching is

The classic problem: distributions fix vulnerabilities *without changing the upstream version*
(`openssl 3.0.2-0ubuntu1.12` contains fixes released in openssl 3.0.10). Comparing only version numbers with the
NVD produces false positives on almost every Ubuntu/Debian. This is why there are two paths, with a declared
confidence (`confidence` in the evidence):

| | **OSV** (confidence `high`) | **NVD/CPE** (confidence `low`, tag `upstream_version_match`) |
|---|---|---|
| Data | the distribution's security advisories (Debian, Ubuntu, Rocky, AlmaLinux) | *upstream* version ranges of the NVD records |
| Distribution backports | **taken into account** (fixed version, e.g. `3.0.2-0ubuntu1.14`) | ignored: possible false positives |
| When it is used | automatically if the distribution is covered | if OSV does not cover the distribution or does not answer (`cpe_match: auto`), or always (`always`) |

The rules (`rules/default/vulns.yaml`) fire **one rule per match**:

| Rule | Condition | Severity |
|---|---|---|
| VULN-001 | CVE in the **CISA KEV** catalog (actively exploited), high confidence | **critical** |
| VULN-002 | recently published CVE (`new_within_days`), CVSS ≥ 9, high confidence | high |
| VULN-003 | recent, 7 ≤ CVSS < 9 | medium |
| VULN-004 | not recent, CVSS ≥ 9, not fixed | medium |
| VULN-005 | not recent, 7 ≤ CVSS < 9 | low |
| VULN-006 | recent but unscored (not yet analysed by the NVD) | low |
| VULN-010 | KEV but low confidence (upstream version only): *"possibly affected, verify"* | medium |
| VULN-011 | low confidence, CVSS ≥ 7 | low |

Matches with a score below `min_cvss` (default 7) are **counted but not listed** (to avoid producing thousands of
findings): you see them in the totals of `--vuln-check` and `--vuln-status`. KEV CVEs are always listed. The score
comes from the NVD; if it is missing, from the CVSS vector of the OSV advisory (computed by the agent), and only as a
last resort from the distribution's priority (estimated: the evidence reports `score_source`).

The vulnerability severity is **always the rule's**: the AI does not assess CVEs one by one and cannot promote an old
CVE into an alert.

### 13.3 What about CWE?

A **CWE is a weakness class** ("Out-of-bounds Write", "SQL Injection"), not something a system is "affected by" in
itself: it is, through the CVEs that instantiate it, or through bad configuration. The agent uses them like this:

* **CVE → CWE**: every vulnerability finding carries the CVE's CWEs with the name (e.g. `CWE-787 Out-of-bounds Write`).
* **Configuration → CWE**: 36 configuration and attack rules are annotated with their CWE (`cwe:` in the rule file):
  for example overly broad permissions → CWE-732, empty password → CWE-258, SQL injection → CWE-89.
* **Trends**: the digest lists the most frequent weakness classes among the new vulnerabilities found on your systems.
* **Names**: there is a built-in table of ~90 common CWEs (reports are readable offline too); the downloaded MITRE
  catalog takes precedence and covers all the weaknesses cited by CVEs.

To add a CWE to a rule of your own: `cwe: [CWE-732]` next to `mitre:` (format checked at startup).

### 13.4 Configuration (`vuln:`)

```yaml
vuln:
  enabled: true
  refresh_every: 6h          # feed refresh (minimum 30m: public services must be treated with respect)
  match_every: 1h            # how often targets are re-matched
  kev: true                  # CISA Known Exploited Vulnerabilities
  nvd: true                  # CVE records (scores, CWE, CPE ranges)
  cwe: true                  # names and descriptions of the weaknesses
  osv: true                  # distribution advisories (accurate): sends package name+version to osv.dev (§13.6)
  cpe_match: auto            # auto | always | never
  nvd_initial_days: 120      # first load: CVEs modified in the last N days
  nvd_api_key_file: ""       # optional: NVD API key (10 times more requests per second), file chmod 600
  min_cvss: 7.0              # below this score matches are only counted (a CVE with EPSS >= 10% is listed anyway)
  new_within_days: 14        # "recent" = published (or added to KEV) in the last N days
  epss: true                 # EPSS probability of exploitation (daily file, ~3 MB; §16.3)
  exposure: true             # rank by reach: does the vulnerable package listen on the network / run? (§16.3)
  # db_path: /var/lib/dyna_cyber_agent/vuln.db
  # kev_url / nvd_url / cwe_url / osv_url / epss_url ({date} = YYYY-MM-DD): to use an internal mirror (http:// allowed for local mirrors)
  # timeout: 120
```

**Timing of the first NVD load.** The NVD modifies about **900 CVEs a day**; with `nvd_initial_days: 120` that is
~100,000 records in ~100 requests of 1000. Without an API key the agent respects the public limit (one request every
6.5 s): **~11 minutes**; with a key ~1-2 minutes. The key is free: request it at
https://nvd.nist.gov/developers/request-an-api-key (you get a confirmation e-mail with the key). Save it in a file
readable only by you (`chmod 600`) and point `nvd_api_key_file` at it. You can run the load by hand with
`dyna_cyber_agent --config ... --vuln-sync nvd` (Ctrl+C is safe) before starting the service; a timeout such as
"Timeout was reached after 1000 CVEs; will resume" loses nothing: what was downloaded is saved and the next run
continues from there. The disk space of `vuln.db` depends on `nvd_initial_days`: check it during acceptance (§14).

Without the NVD load the OSV matching still works (OSV brings its own score); the NVD adds official scores, CWEs and
the CPE fallback. The collector warns if the database is empty.

### 13.5 Commands

```bash
dyna_cyber_agent --config agent.yaml --vuln-sync all          # kev + nvd + cwe now (or just: kev | nvd | cwe)
dyna_cyber_agent --config agent.yaml --vuln-status            # what is in the database, latest updates, state per target
dyna_cyber_agent --config agent.yaml --vuln-search CVE-2021-44228
dyna_cyber_agent --config agent.yaml --vuln-search "log4j"    # text search
dyna_cyber_agent --config agent.yaml --vuln-check web01       # match web01's inventory now (prints the matches)
```

Sample output (values from a test with fake data):

```
$ dyna_cyber_agent --config agent.yaml --vuln-check
localhost: matching 3646 packages (ubuntu 22.04) ...
  2 matches (1 actively exploited); critical 1, high 1, medium 0, low 0, unscored 0; listed 2 (cvss >= 7 or exploited)
  * CVE-2099-0002  curl 7.81.0-1ubuntu1.29 -> fixed in 7.81.0-1ubuntu1.99  cvss=7.5 [kev,ransomware,recent,fix_available]
  * CVE-2099-0001  openssl 3.0.2-0ubuntu1.30 -> fixed in 3.0.2-0ubuntu1.99  cvss=9.8 [recent,fix_available]

$ dyna_cyber_agent --config agent.yaml --vuln-search CVE-2099-0002
CVE-2099-0002  cvss=7.5 (high)  ACTIVELY EXPLOITED (CISA KEV, due 2026-11-05)  published 2026-10-02
  Mock description of CVE-2099-0002
  CWE-122 Heap-based Buffer Overflow
  required action: Apply updates.
```

The `vulns` collector is included in `collectors: all`; for a target that lists the collectors by hand you need
`packages` **and** `vulns`.

### 13.6 Network and privacy

The agent contacts these services **from the machine where it runs** (never from the targets):

| Service | URL | What it sends |
|---|---|---|
| CISA KEV | `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | nothing (download) |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | only date ranges or a CVE id; the API key, if any, in the `apiKey` header |
| MITRE CWE | `cwe-api.mitre.org/api/v1/cwe/weakness/<id>` | only CWE numbers |
| FIRST.org EPSS | `epss.empiricalsecurity.com/epss_scores-<date>.csv.gz` | nothing (one download a day) |
| **OSV** | `api.osv.dev/v1/querybatch` and `/v1/vulns/<id>` | **name and version of the installed source packages** and the ecosystem (e.g. `Ubuntu:22.04:LTS`). No hostname, address or other data of the system |

If the package list must not leave your network: `vuln.osv: false` (matching falls back to NVD/CPE data, less
accurate, and only uses download-only feeds) or point `osv_url` at an internal mirror. To turn everything off:
`vuln.enabled: false`.

### 13.7 Limits and things to know

* **Distributions covered by OSV**: Debian, Ubuntu (ecosystem `Ubuntu:YY.MM[:LTS]`), Rocky Linux, AlmaLinux. For
  Rocky/Alma the package name in the OSV advisories was not verified in this version: check it during acceptance.
  RHEL, CentOS, Fedora, SUSE, Arch, Alpine are not covered: the CPE matching is used (low confidence).
* It sees the **software of the package managers**. It does not see hand-built binaries, images/containers,
  pip/npm/gem libraries, firmware.
* "ESM"/Ubuntu Pro fixes are not considered (ecosystem `Ubuntu:Pro:...`).
* The NVD analyses CVEs with a delay: a just-published CVE may not have a score yet (rule VULN-006).
* No match is **not a guarantee**: it means "no vulnerability *known to the feeds* for these packages".
* EPSS is a statistical estimate, not a certainty: a low score is not "safe". Reach (§16.3) is known only for
  programs of packages whose file lists have been collected (a first inventory needs a few runs).

---

## 14. Acceptance testing: what to try and what to report back

This section is the procedure for trying the agent in the field and getting useful results back to fix what is
wrong. Ground rules:

* **Use a test machine** for the simulations (§14.4): some create files, users or log lines (all *reversible*, with
  the cleanup command). The agent itself never writes to the target.
* After each step note the **outcome** (OK / KO / doubt) and, if KO or doubtful, the exact text of the error or of
  the finding.
* Timings matter (slow collectors, first NVD load): report the ones that seem too long.

### 14.1 The script that collects everything

`scripts/collaudo.sh` runs checks and collection in order and produces an archive to send back:

```bash
# conservative: nothing leaves the machine beyond what a normal --once does
# (note: with the default configuration `--once` also queries OSV with package names and versions;
#  to avoid it set `vuln: { osv: false }` in the config before running the script)
scripts/collaudo.sh --config /etc/dyna_cyber_agent/agent.yaml --out ~/collaudo-1

# complete (contacts the services: read what each option does with --help)
scripts/collaudo.sh --config /etc/dyna_cyber_agent/agent.yaml --out ~/collaudo-2 \
    --with-llm --with-vuln-sync --with-vuln-check --redact
```

Options: `--with-llm` (ping + analysis), `--with-vuln-sync` (downloads the feeds), `--with-vuln-check` (queries OSV
with the **package names and versions**), `--with-mail-test` (sends **one** mail), `--redact` (masks IPv4 addresses
and e-mails), `--skip-once` (configuration and connection checks only). It produces a directory and a `.tar.gz`
with a `SUMMARY.txt` (one outcome per step) and the output of every command. **Re-read the archive before sending
it**: it contains host names, process command lines and addresses (`--redact` does not cover everything).

### 14.2 Suggested path

| # | Step | Where | What to do | Expected outcome |
|---|---|---|---|---|
| A | Build and tests | build | `make && make test` | no warnings; "100% tests passed" (about 210 cases, ~25 s) |
| B | Local monitor | test machine | minimal config of §2, then `--check`, `--once` | 3 collectors in a few ms; a few "absolute" findings (see B below) |
| C | SSH | 1 target | §6: first `stream`, then `installed` + `sudo`; `--ssh-test <target>` | connection, tools `ok`, `uid=0` with sudo; `/proc` scan < 1 s on a LAN |
| D | Logs | test machine | log simulations (§14.4) | LOG-* findings within ~30 s of the event |
| E | Persistence/system/files | test machine | §14.4 simulations after `--baseline-lock` | one finding per simulation; `resolved` after cleanup |
| F | LLM | llama server | `--llm-ping`, `--llm-prompt`, `--analyze` | assessments in the configured language, valid JSON, no invented ids |
| G | Mail | real SMTP | `--report-preview`, `--send-test-mail` | mail readable in HTML and text |
| H | Vulnerabilities | Ubuntu/Debian machine | §14.5 | feeds downloaded, plausible matches |
| I | Service | VM | install the `.deb`, start with systemd (§10), `systemd-analyze security dyna_cyber_agent` | no "Permission denied" in the journal; regular collectors |
| J | Robustness | VM | leave it running 24 h; try switching off SMTP, llama-server, an SSH target; `kill -9` and restart | no crash; clear logs; no duplicate mail |
| K | Console and map | any | §15: open the web console; `--geo-update`; run a few simulated logins | all tabs load; the map places public addresses |
| L | Advanced analysis | test machine(s) | §16.11: one simulation per analysis, after `--baseline-lock`; `--incidents`, `--intel-update` | each finding appears as described; `crossview` stays silent on a clean machine |
| M | Decisions and questions | test machine + llama-server | §16.12 (simulated attack), §16.13 (accept / reopen), §16.14 (ask the agent), §16.15 (filters, pauses, reset) | the map and the incident appear; an accepted finding stays silent and a deadline reopens it; the answer cites real findings and shows its period |

**B - what to look at.** With `collectors: [processes, network, users, logs, persistence, system, packages]`
(without `files` and `integrity`, which are slow, at the first pass). The first `--once` is in *learning*: only
absolute rules fire (e.g. `SYS-004` weak settings, `PERS-018`). Then `--baseline-lock`, a second `--once`, and note
**every** finding that looks like a false positive with `rule id` and `subject` (the column after the machine name in
`--events`). Add `files` and `integrity` later and **time** the first `--once` (the SUID search can take 10+ minutes).

### 14.3 What to send back

1. The `collaudo.sh` archive (say with which options you ran it).
2. For each step of the table: outcome and notes (template below).
3. The list of **false positives** (rule + object) and **false negatives** (a simulation that did not produce the
   expected finding: give the step, the command and how long you waited).
4. Timings: first `--once` with all collectors, first `--vuln-sync nvd`, duration of `--ssh-test`.
5. Numbers: size of `agent.db` and `vuln.db` (`ls -la`), agent memory after 24 h (`ps -o rss,etime -p <pid>`).
6. Anything that surprised you, even if it is not an error.

Template (copy and fill in):

```
Agent machine : <distribution, version, cpu/ram>
Targets       : <n, distribution, local/ssh (stream|installed+sudo)>
Version       : <dyna_cyber_agent --version>

A build/tests       : OK | KO  - notes:
B local monitor     : OK | KO  - false positives: ...
C ssh               : OK | KO  - scan test times: ... - notes:
D logs              : OK | KO  - simulations that worked: ... missed: ...
E persist./system   : OK | KO  - ...
F llm               : OK | KO  - time per call: ... quality of assessments: ...
G mail              : OK | KO  - client used: ... HTML rendering: ...
H vulnerabilities   : OK | KO  - nvd sync duration: ... vuln.db: ... matches: ...
I service           : OK | KO  - systemd-analyze security: ...
J robustness        : OK | KO  - rss after 24h: ... db: ... incidents: ...
K console / map     : OK | KO  - ...
Other: ...
```

### 14.4 Safe simulations (test machine only)

Run them **after** learning and locking the baseline (`--baseline-lock`), then `dyna_cyber_agent --config ... --once`
and `--events`. Each row says what must appear and how to clean up. The log simulations write into the *test
machine's* log with `logger` (your action, not the agent's); they work where `auth.log`/`secure` or journald receive
`authpriv`.

| Simulation | Command | Expected finding | Cleanup |
|---|---|---|---|
| Successful brute force (log) | `for i in $(seq 1 10); do logger -p authpriv.notice -t sshd "Failed password for root from 203.0.113.50 port 4000$i ssh2"; done; logger -p authpriv.notice -t sshd "Accepted password for root from 203.0.113.50 port 50000 ssh2"` | LOG-001, **LOG-002 (critical)**, LOG-004, LOG-005 | nothing (the lines stay in the log): `--accept <id>` |
| New user (log + state) | `logger -p authpriv.notice -t useradd "new user: name=testx, UID=1999, GID=1999, home=/home/testx, shell=/bin/bash"` and `sudo useradd -M -s /bin/bash agenttest` | LOG-012, USR-003 | `sudo userdel agenttest` |
| Web attack (if nginx is present) | `curl -s "http://localhost/index.php?id=1%27%20UNION%20SELECT%201,2,3--" -A sqlmap/1.5 -o /dev/null` | LOG-020 (or 021), LOG-029 | nothing |
| Hidden executable in /tmp | `touch /tmp/.agenttest && chmod +x /tmp/.agenttest` | FILE-005 | `rm /tmp/.agenttest` |
| SUID file in /tmp | `sudo cp /bin/true /tmp/agenttest-suid && sudo chmod u+s /tmp/agenttest-suid` | FILE-007 (critical) | `sudo rm /tmp/agenttest-suid` |
| Suspicious cron | `echo '@reboot root /tmp/.agenttest/run' \| sudo tee /etc/cron.d/agenttest` | PERS-002, PERS-003, PERS-004 | `sudo rm /etc/cron.d/agenttest` |
| Password-stealing alias | `echo "alias sudo='/tmp/fakesudo'" >> ~/.bashrc` | PERS-014, PERS-015, PERS-018 | remove the line |
| Weakened ASLR | `sudo sysctl -w kernel.randomize_va_space=1` | SYS-004, SYS-005 | `sudo sysctl -w kernel.randomize_va_space=2` |
| New SSH key | add any key to `~/.ssh/authorized_keys` | USR-004 | remove the line |
| New listening port | `python3 -m http.server 8099 --bind 0.0.0.0 &` | NET-001 (then `kill %1`) | `kill %1` |

After cleanup run another `--once`: the findings about *state* data must become **resolved** (`--events --all`); the
log ones stay. If a simulation does not produce the expected finding, send me the command, the wait and the output
of `--once` for that collector.

What each log rule needs, to avoid surprises: `LOG-001` (brute force) fires with **8 or more** failed attempts from
one address within 10 minutes and only for **non-private** addresses; `LOG-002` (success after failures) needs at
least **3** failures before the successful login, from the same address, and also fires for private addresses.
`LOG-001` is *medium*, so with `min_severity: high` it appears in the digest, not as an immediate mail; `LOG-002` is
*critical* and produces the alert. The addresses 203.0.113.0/24 used above are documentation addresses: they show
in the attack map's "no position" list.

How long should the baseline learn before the simulations? For a test machine a couple of hours is enough: let the
collectors run a few cycles, check that `--baseline-status` shows a stable number of identities, then
`--baseline-lock`. The novelty rules (new port, user, cron, key) work only after that; the log, file and
system-setting rules work even while learning. For production keep the full window (§4.1). Do **not** run the
simulations before locking, or the test port/user would be learned as normal.

### 14.5 Vulnerability acceptance

On a **Debian or Ubuntu** machine (so that OSV is exercised):

```bash
# 1) quick feeds and CWE; then the NVD (time it and note the size of vuln.db)
time dyna_cyber_agent --config agent.yaml --vuln-sync kev
time dyna_cyber_agent --config agent.yaml --vuln-sync nvd          # long the first time; Ctrl+C is safe, it resumes
time dyna_cyber_agent --config agent.yaml --vuln-sync cwe
dyna_cyber_agent --config agent.yaml --vuln-status ; ls -la /var/lib/dyna_cyber_agent/vuln.db

# 2) the search must show KEV and CWE for a famous CVE
dyna_cyber_agent --config agent.yaml --vuln-search CVE-2021-44228  # expected: ACTIVELY EXPLOITED + CWE-20/400/502/917 with names

# 3) the real matching (needs 'packages' already collected: --once with that collector)
dyna_cyber_agent --config agent.yaml --once
dyna_cyber_agent --config agent.yaml --vuln-check
```

Checks to do by hand (and report the outcome):

1. **Spot check**: take 3 matches listed by `--vuln-check` and verify them on the distribution's tracker (Ubuntu:
   `ubuntu.com/security/CVE-xxxx-xxxx`; Debian: `security-tracker.debian.org/tracker/CVE-xxxx-xxxx`). Does the fixed
   version the agent shows match? Is the package really still vulnerable?
2. **False positives on a patched system**: on a fully updated system the `high` matches must be few or zero. On an
   old, non-updated VM they must be many.
3. **Life cycle**: update a package that has a match (`apt install --only-upgrade <pkg>`), wait for the next
   `packages` + `vulns` (or `--once`): the finding must become *resolved*.
4. **Without OSV**: with `osv: false` and `cpe_match: auto` run `--vuln-check` again and compare the numbers: you
   expect more matches, with the tag `upstream_version_match` and the warning "no OSV coverage / using
   upstream-version matching".
5. **Service**: about 20 s after start "vulnerability feeds: synchronisation started" appears, then one line per
   feed; the digest mail contains the "Vulnerability intelligence" section.
6. The log must not contain feed parsing errors (`not an NVD CVE 2.0 response`, `OSV answer not understood`): if it
   does, **report the line and the time**, so I can check the real format.

> Note on testing the feeds: the parsers were written and tried against real responses reconstructed from the
> documentation and from read-only requests, and with a local fake server; **they have not yet been tried for hours
> against the real services**. Your acceptance run is the first complete one.

---

## 15. Web console (graphical interface)

A modern, responsive page (light/dark, also suited to a phone) to see everything and launch targeted analyses. It is
**off by default**. The page is embedded in the binary: nothing to install, no external library, no data leaving the
machine.

```yaml
web:
  enabled: true
  listen: 127.0.0.1     # local only (recommended)
  port: 8484
  # token_file: /etc/dyna_cyber_agent/web.token   # default: <state_dir>/web.token
```

Restart the agent: the log shows the address and the token file (created the first time, mode 0600; read it with
`cat`). Open `http://127.0.0.1:8484/` and paste the token. Without a running daemon (just to browse the data already
collected): `dyna_cyber_agent --config agent.yaml --web`.

**From another machine**: do not open the port on the network (clear-text HTTP). Use an SSH tunnel:
`ssh -L 8484:127.0.0.1:8484 user@agent-machine` and then open `http://127.0.0.1:8484/`.

What you will find:

* **Overview** — counters, findings by severity, vulnerabilities by CVSS, what to look at first, baseline state (with
  learning progress) per target, model state.
* **Incidents** — chains of related findings with their stages, shared addresses/accounts and a timeline; "analyse the
  incident with AI" sends all its findings to the model as one story (§16.2).
* **Findings** — filters (text, severity, status, target, collector), full card with evidence, MITRE with names, AI
  assessment, how to remediate. From here you launch the **targeted AI analysis** on one finding or on the selected
  ones, with a question of your own ("is it consistent with a backup?").
* **Vulnerabilities** — CVEs grouped by machine and package, ordered by **priority**, with CVSS, EPSS, reach
  (listening / local / running), exploited/new, CWE and fixed version; filter "listening on the network only" (§16.3).
* **Map** — a dark, offline map of every address that attempted to access the monitored machines: see §15.1.
* **Ask the agent** — a free question in Italian or English ("what changed on web01 since Tuesday?"): §16.14.
* **Settings** — exclusion filters (packages, ports, users, addresses, paths, rules, CVEs), mail and AI pauses, console preferences, and the **total reset** with a double confirmation: §16.15.
* **AI analysis** — choose target, collector and minimum severity, ask a free question; the assessments are saved.
* **Report** — preview (HTML + TXT, downloadable) of a digest or an alert, with or without the AI summary. **It
  sends nothing.**
* **Mail** and **Status** — history of sent mails and collector health.

Security: every API request needs the token (`Authorization: Bearer`); the page is served with a strict CSP and the
data coming from the analysed machines is always inserted as text, never as HTML. The console is read-only on the
analysed machines; the only writes are in the agent's database (the AI assessments you ask for, and your decisions to
accept a finding as normal or to reopen it: §16.13). The analyses and the questions use llama-server like the rest of
the agent (`llm.enabled: true`); one at a time, queued. The console does not offer "send this report": that stays on the
command line. Accepting is a security decision, so it is as protected as everything else: it needs the token, and every
acceptance is written to the agent's log and kept in the database with its note and time.

### 15.1 Map of access attempts

The agent records **every address** that touches the monitored machines, even with a single attempt (the alarm
rules fire only above a threshold, the map does not): failed and successful SSH logins, SSH-protocol scans, web
attack requests and 4xx errors. For every address and every day it keeps counters, usernames tried, first and last
sighting, for **400 days** (far longer than the snapshots). The counters are increments computed on the log lines
actually read (with the reading position saved): a line is not counted twice, not even after a restart. At startup
the events already present in the findings (brute force, scans, web attacks) are recovered once.

**Locations.** An address becomes coordinates through a **local** database (DB-IP "IP to City Lite", CC BY 4.0,
about 85 MB to download, a few hundred MB on disk in `<state_dir>/geo.db`). No address is ever sent to external
services, and the map is drawn by the browser without downloading tiles: no requests to third parties.

```bash
dyna_cyber_agent --config agent.yaml --geo-update          # downloads the month's file and builds the database (a few minutes)
dyna_cyber_agent --config agent.yaml --geo-import file.csv.gz   # or import a file you downloaded by hand
dyna_cyber_agent --config agent.yaml --geo-status          # shows the database in use and its date
```

Update it once a month (it is the only download; a running daemon picks up the new file within a minute). Without a
database the map still lists the addresses but does not place them. If the automatic download fails, get the
"IP to City Lite" CSV from https://db-ip.com/db/download/ip-to-city-lite and use `--geo-import`.

**What it shows.** Bubbles per city (size = number of attempts, colour = risk, white ring = active in the last
hour), the most active countries, a table of the addresses with details (usernames tried, targets hit, counters).
Risk: **critical** = successful login after at least 3 failures, **high** = 8 or more failures, **medium** = some
failures, a scan or an attack request, **low** = only successful logins. Private addresses (192.168.x, 10.x, ...) have
no position: they are in the "No position" list. Filters by period, target and risk. Zoom with the wheel or the
buttons, drag to pan, click a bubble for its addresses.

**Honest limits.** The position is approximate (usually the provider's city, sometimes only the country: attackers
often use VPNs, rented servers or compromised machines). You only see what ends up in the logs that are read: the
`logs` collector must be active on the target and `sshd`/web must write logs; attempts that happened while the agent
was off are not recovered; a firewall that drops packets before the service leaves no trace in the SSH logs.
Attribution required by the license: *IP geolocation by DB-IP (https://db-ip.com)*; map: Natural Earth (public domain).

---

## 16. Advanced analysis: what a rule on a single observation cannot see

Rules (§7) look at one observation at a time. These nine analyses look *across* time, machines and data sources.
Each one can be switched off on its own under `analysis:` (see §16.10 for the whole block); all of them work on what
the agent has already collected or on public data downloaded to the agent machine. **None of them touches a target
and none needs a new gate**: a gate installed before this version keeps working (nothing new is requested from it
beyond file reads and the commands it already allowed).

| § | Analysis | One-line summary |
|---|---|---|
| 16.1 | Explained by an update | a new program or a restarted service right after `apt upgrade` is marked as probably legitimate |
| 16.2 | Incidents | findings that share an address, account or program are chained into one story with a timeline |
| 16.3 | Vulnerability priority | EPSS (probability of exploitation) and *reach* (does it listen on the network?) rank the CVEs |
| 16.4 | Peer groups | what exists on **one** of five identical machines is reported, even if it is in the baseline |
| 16.5 | Cross-view | the same thing seen through two kernel interfaces: a mismatch is a rootkit indicator |
| 16.6 | Never-seen log messages | the *shape* of every log message is learned; a new shape is a finding |
| 16.7 | Outbound connections | beaconing, countries never contacted before, traffic spikes |
| 16.8 | Logins | impossible travel, a country or an hour the account never used |
| 16.9 | Threat lists | public IP blocklists matched locally (nothing is sent anywhere) |

### 16.1 Explained by an update

**The problem.** After a routine `apt upgrade` the agent sees "executable never seen on this host", "process runs from a
deleted binary" (a service still running the old, replaced file), new units, new modules... all true, all harmless.

**How it works.**

* The `packages` collector remembers the inventory between runs. When a package is installed, upgraded or removed it
  records an **event** with the time `dpkg` wrote its file list (accurate to the second, not "within 6 hours").
* For each new or upgraded package it reads `/var/lib/dpkg/info/<package>.list` and keeps the files that can appear in a
  finding: programs (`/usr/bin`, `/usr/sbin`, `/usr/libexec`...), configuration (`/etc`), systemd units, kernel modules,
  `/opt` and `/usr/local`. Documentation, locales, libraries and language trees are left out. The **first time** the
  whole inventory is read, 600 packages per collection (a laptop with 3,600 packages is complete after about seven
  runs of the `packages` collector, i.e. a day and a half at the default 6 h; run `--once` a few times to speed it up).
* When a finding appears and its evidence mentions a path owned by a package that changed **at most `window` (7 days)
  before** the finding (or up to 5 minutes after: clocks and cycles do not line up exactly), the finding gets the tag
  `explained_by_update` and `evidence.explained_by` = package, kind (installed/upgraded), old and new version, time, path.
* **Guard:** if `dpkg -V` / `rpm -Va` (collector `integrity`) reports that very file as modified, nothing is explained:
  the package does not vouch for it. An attacker who replaces `/usr/sbin/sshd` right after an update is not excused.

**What changes.** The severity of the rule is **not** modified. The finding (a) does not trigger an immediate alert
unless it is *critical*: it travels in the digest; (b) shows a green "probably explained by a package update: name
old → new" note in the mail and in the console; (c) tells the AI analyst, which treats it as a strong benign explanation
unless the other evidence contradicts it.

**Also:** `PKG-005` (low) reports "reboot required" when `/var/run/reboot-required` exists (Debian family): a kernel or
core-library update that has not taken effect yet. It closes by itself after the reboot.

**Limits.** Real ownership needs `dpkg` file lists: on RPM systems only the install/upgrade events are recorded (no
path ownership, so nothing is explained). A process that restarts more than 7 days after the upgrade is not linked
(raise `window`). The explanation is evidence, not proof: that is why critical findings still alert.

### 16.2 Incidents

**The problem.** A brute force, the login that finally worked, the SSH key added afterwards and the connection opened
by the new program are four findings in four places of the mail. Together they are one intrusion.

**How it works (deterministic, no AI involved).** Every open finding is reduced to *entities*:

* **addresses** (`src_ip`, `remote_addr`...): only public ones (a private address would chain your whole LAN);
* **accounts** (`user`, `success_user`, ...): never `root` or system accounts;
* **programs and files**: anything outside the operating system's directories (`/tmp/.x/payload`, `/opt/app/bin/app`,
  `/home/alice/.ssh/authorized_keys`; not `/bin/bash`).

Two findings are linked if they share an entity and appeared **within `window` (24 h)** of each other. A group becomes an
**incident** when it has at least `min_findings` (2) findings from **at least two different rules** (the same rule
firing again is one problem, not a chain). Each finding is placed in an ATT&CK *stage* (credential access, initial
access, persistence, execution, command and control...) from its MITRE techniques; the incident lists the stages in the
order they happened, e.g. *Credential access → Initial access → Persistence on web01*. Its severity is the worst of its
findings, **one level higher when the chain crosses three stages**. When a new finding bridges two incidents they merge
(the older id survives); when a member is resolved or accepted and fewer than two remain, the incident closes.
Vulnerabilities and findings explained by an update never take part.

**Where you see it.**

* **Mail:** an *Incidents* section after the AI summary: title, period, shared addresses/accounts and a **timeline** with
  one line per finding. The three most severe members keep their full card (marked "incident #N"); the others only
  appear in the timeline: twelve findings read as one story. The AI is told to narrate each incident as one story.
* **Alerts:** an incident that reaches `alerting.min_severity` mails **all its not-yet-reported members**, even when
  every one of them is below the threshold (three *medium* findings across three stages are a *high* incident).
* **Console:** the **Incidents** tab (cards, timeline, "analyse the incident with AI").
* **Command line:** `dyna_cyber_agent --config agent.yaml --incidents` recomputes and prints them.

**Limits.** Findings are linked only by what they demonstrably share: an attack that leaves no common address, account
or file will not be chained. A shared *public* address that is legitimate (a CDN, your own office) can chain unrelated
findings: accept the noisy member or narrow `window`.

### 16.3 Vulnerability priority: EPSS and reach

**The problem.** 281 CVEs with CVSS ≥ 7 are not a to-do list. Two questions sort them: *is this likely to be exploited?*
and *can an attacker reach the vulnerable code?*

**EPSS.** The agent downloads the daily EPSS file of FIRST.org (about 3 MB, one request a day, from
`epss.empiricalsecurity.com`; the file of the day appears after noon UTC, so it looks back up to 3 days) into `vuln.db`.
A score is the probability of exploitation activity in the next 30 days. A CVE with **10% or more** is tagged
`epss_high`: among tens of thousands of CVEs that is rare. `dyna_cyber_agent --config agent.yaml --vuln-sync epss`
downloads it now. Nothing about your machines is sent: it is a download.

**Reach.** Using the file ownership of §16.1, the agent knows which package owns the program behind every listening
socket and every running process. Each CVE gets an `exposure`:

| exposure | meaning |
|---|---|
| `listening` | a program of the vulnerable package listens on a non-loopback address (the ports are listed) |
| `listening_local` | it listens on loopback only |
| `running` | a process of the package runs, nothing listens |
| `unknown` | no information: **libraries** are always unknown (every program may use them), and so is everything when file lists are not collected yet. The agent never claims "not reachable" |

**Priority (0–100)** folds it together: CVSS (×5; 25 when unscored) + 25 if actively exploited (KEV) + EPSS (+15 at
50%, +10 at 10%, +4 at 1%) + reach (+15 listening, +8 local listener, +5 running) + 3 if new − 10 for an upstream-only
match (possible false positive). Reports and the console sort by it; the console shows the columns *Priority*, *EPSS*
and *Reach*, and a filter "listening on the network only". The kernel CVEs also get `reboot_pending` when a reboot is
waiting (`PKG-005`).

**Rules.** `VULN-007` (high): a network service with an `epss_high` flaw (it overrides the CVSS bands: reachable code plus
a probable exploit is what gets machines compromised). `VULN-008` (medium): `epss_high` with CVSS < 7 (listed only
thanks to EPSS). The other VULN rules do not fire for the same CVE.

**Limits.** Ownership is per binary package (Debian family). "A service still runs the old code after an update" is not
a CVE finding: it is the *process runs from a deleted binary* finding (PROC rules), now marked "explained by an update"
(§16.1) because it means *restart the service*. EPSS exists only for CVE ids.

### 16.4 Peer groups

**The problem.** A backdoor installed *before* monitoring started is part of the baseline: it is "normal" for that
machine. It is never normal for the four identical machines next to it.

**Configuration.**

```yaml
targets:
  - {name: web01, transport: ssh, ..., group: web}
  - {name: web02, transport: ssh, ..., group: web}
  - {name: web03, transport: ssh, ..., group: web}
  - {name: web04, transport: ssh, ..., group: web}
```

Targets with the same `group` are compared with each other. A group needs at least `analysis.peers.min_group_size`
members (**3** minimum: with two machines there is no majority); smaller groups stay off (`--check` says so). Put in a
group machines that really do the same job.

**What is compared** (current state, from the latest snapshots of `processes`, `network`, `users`, `persistence`,
`system`): accounts (by name: uids differ for no reason) and privileged-group memberships, listening ports, programs
outside the system directories, enabled systemd units, kernel modules, cron entries, SSH keys, sudo rules. Ephemeral
ports and system tools that come and go are ignored.

**What is reported** (collector `peers`, every 30 min, needs recent data of the other members):

* **unique** — present here and absent from at least `min_share` (80%) of the others. `PEER-001` (**high**) for the
  security-sensitive kinds (accounts, privileged groups, SSH keys, sudo rules, kernel modules, cron entries);
  `PEER-002` (medium) for programs, ports and services.
* **missing** — present on at least 80% of the others and absent here: a service that stopped, a security tool that was
  removed (`PEER-003`, low).

These rules do not depend on the baseline: they fire even during the learning phase. Silence a legitimate difference
with `--accept <id>`, or fix the machines so they match.

### 16.5 Cross-view (anti-rootkit)

**The idea.** A rootkit can edit the answer of one kernel interface; editing all of them consistently is much harder, and
no signature is needed, so new rootkits are caught too. Collector `crossview` (every 10 min):

| Compares | Rule |
|---|---|
| the `/proc` directory listing (what `ps` shows) **against** the cgroup membership lists (`cgroup.procs`): a process in a cgroup, readable at `/proc/<pid>/stat`, but missing from the listing | `ROOT-001` critical |
| `/proc/modules` (`lsmod`) **against** `/sys/module/*/initstate` | `ROOT-002` critical |
| listening TCP ports in `/proc/net/tcp` **against** `ss` (netlink) | `ROOT-003` high |

A mismatch must be seen on **two consecutive runs** before it is reported: processes start and stop between the two
reads. The collector also lists the **eBPF programs** the kernel JIT-compiled (read from the symbol names in
`/proc/kallsyms`, once an hour) and the objects pinned in `/sys/fs/bpf`: a new one after the baseline is `BPF-001` /
`BPF-002` (medium), since eBPF is how modern rootkits hide.

**Privileges and cost.** Everything it reads is world-readable (`cgroup.procs`, `/sys/module`, `/proc/net/tcp`,
`/proc/kallsyms` names), and `ss -tulpn` is a command the gate already allows. The hourly read of `kallsyms` is a few MB.

**Limits.** A rootkit that falsifies every interface consistently is not seen. The cgroup view assumes the usual
layout (systemd, cgroup v2 or v1); inside a container the pid namespaces change what is visible. It does not look at the
disk (that is the `integrity` collector).

### 16.6 Never-seen log messages

**The idea.** Wazuh-style tools need a decoder written for every log format. Here every message is reduced to its
**shape**: numbers, addresses, paths, identifiers, hosts and `key=value` values become placeholders, so
`Accepted publickey for alice from 10.0.0.5 port 4211` and the same line with other values are one template. A message
whose shape was not in the baseline is new behaviour, whatever it says.

* **What is fed:** the lines that no dedicated parser understood (the combined `syslog`/`messages`, the journal, and the
  auth/kernel lines that are not logins or kernel events). The combined syslog is now read even when `auth.log` and
  `kern.log` exist (the other logs are not read twice).
* **Learning:** during the baseline window every shape is learned; afterwards a new one is drift. The list of shapes
  already reported is kept in the database, so a restart does not report them again.
* **Rules:** `LOG-050` (**info**: recorded and visible in the console and `--events`, but it does not fill the mails)
  and `LOG-051` (medium) when the new shape contains words such as *denied, failed, segfault, out of memory,
  corrupt, violation*. `LOG-050` findings are not sent to the AI (they would be many).
* **Brakes:** at most `analysis.logs.max_new_per_cycle` (25) new shapes per cycle, alarming ones first; the rest waits.

**Limits.** After a software update many new shapes appear (all `info`). The sample line in the evidence is real log
text: the mail sanitises it like everything else that comes from the machine.

### 16.7 Outbound connections

Collector `netflow` (every 2 min) plus a record the agent keeps of **new** outbound connections (one event per
connection, not per poll; a short connection that only shows up as `TIME_WAIT` still counts; connections already open
when the agent starts are ignored).

* **Beaconing.** Connections to the same address and port at a steady pace are how malware asks "any orders?". Needs at
  least 8 connections over at least 10 minutes with a period between 20 s and 1 h, at least 80% of the intervals within
  25% of the median (and no less than twice the network polling interval). Bursts count once. Because periodic
  software exists (update checks, monitoring), the baseline learns the `net.beacon` identities that were already there:
  `NET-030` (medium) for a new one, `NET-031` (**high**) when the destination is outside your networks **and** the port is
  not 80, 443 or 53.
* **New countries.** Outbound connections are tagged with the country of the address (the offline geolocation
  database of §15.1: `--geo-update`); a country that none of the baseline's connections reached is `NET-032` (low).
* **Traffic spikes.** From `/proc/net/dev`, the transmit rate of every real interface (not `lo`, docker, veth...) is
  compared with an exponentially weighted average kept across restarts. After a **6-hour warm-up**, a rate above
  5× the average (and above 8 deviations) **and** above 512 kB/s for two samples in a row is `NET-033` (medium). A spike
  barely teaches the model that it is normal.

**Limits.** The network is polled every 15 s: a beacon shorter than that is timed with ±15 s of error. UDP (including
DNS tunnelling) is not tracked. A C2 that was already beaconing during the learning phase is learned as normal.

### 16.8 Logins: impossible travel, new country, unusual hour

For every successful SSH login (the source address is located with the offline geolocation database, §15.1):

* **Impossible travel** (`LOG-060`, high): the same account, a previous located login less than 24 h ago, a distance of
  at least `min_distance_km` (500) and an implied speed above `max_speed_kmh` (900). The evidence shows both places, the
  distance, the time and the speed.
* **New country for this account** (`LOG-061`, medium) and **unusual hour** (`LOG-062`, low: a 3-hour slot of the day,
  in **UTC**, never used by the account in the baseline). They are drift of the facets `auth.country` / `auth.hour`,
  so they stay silent while the baseline is learned.

The history is kept for 400 days in the agent's database. **Honest limits:** a VPN or a mobile network moves an
address across the world (accept the finding, or the user will keep triggering it); without the geolocation database
nothing is located and none of this runs; private addresses are never located; the event time is the collection time.

### 16.9 Threat lists

The agent downloads public IP blocklists into `<state_dir>/intel/` and matches addresses **locally**. Nothing about
your machines is sent: the lists come in, nothing goes out. Built-in set (replace it with `threat_intel.lists`):

| Name | Category | Source |
|---|---|---|
| `feodo` | c2 | abuse.ch Feodo Tracker (botnet command-and-control servers) |
| `spamhaus_drop` | attacker | Spamhaus DROP (hijacked / criminal networks) |
| `firehol_level1` | attacker | FireHOL level 1 (aggregate of reliable lists) |
| `et_compromised` | compromised | Emerging Threats compromised hosts |
| `blocklist_de_ssh` | attacker | blocklist.de (SSH attackers) |

They are refreshed every `refresh_every` (12 h); a failed or malformed download **never replaces** a good list
(an HTML error page is rejected). A restart reads the copies from disk without any network. IPv4 only.

Where the match is applied: open outbound connections (`ti` appears in the evidence with list and category), successful
logins, and (as a tag only, they already are attacks) brute force, scans and web attacks.

| Rule | |
|---|---|
| `TI-001` **critical** | an open connection to a **C2** server |
| `TI-002` high | a connection to an address of the *attacker / compromised / scanner* lists |
| `TI-003` **critical** | a **successful login** from a listed address |

`dyna_cyber_agent --config agent.yaml --intel-update` downloads now; `--intel-status` shows what is on disk.

A list that is valid but empty (for example `feodo` when no botnet server is active: only a comment header, `0 range(s)`) is accepted and replaces the old copy. A download with no addresses and anything other than comments (an HTML error page, an empty body) is rejected and the previous copy is kept.
**Check each list's terms of use** before relying on it (some limit commercial use or the download frequency); shared
hosting addresses sometimes land on a list by mistake, so look at what the program is before reacting.

### 16.10 The `analysis:` and `threat_intel:` blocks

```yaml
analysis:
  explain_updates: {enabled: true, window: 7d}            # §16.1
  incidents: {enabled: true, window: 24h, min_findings: 2}  # §16.2
  peers: {enabled: true, min_group_size: 3, min_share: 0.8} # §16.4 (also needs `group:` on the targets)
  logs: {templates: true, max_new_per_cycle: 25}           # §16.6
  outbound: {beaconing: true, new_countries: true, traffic_spikes: true}  # §16.7
  travel: {enabled: true, max_speed_kmh: 900, min_distance_km: 500}       # §16.8
vuln: {epss: true, exposure: true}                          # §16.3
threat_intel: {enabled: true, refresh_every: 12h}           # §16.9 (lists: [...] to replace the built-in set)
```

**Switching an analysis on later.** Analyses that learn a new kind of fact in the baseline (countries, login hours, beacons,
eBPF programs, log message shapes) **learn silently during their own first 24 hours**, even if the baseline of the
target was locked long ago: enabling one, or installing the geolocation database after the learning phase, does not
flood you with everything the machine always did. The same applies after upgrading the agent to this version.

`--check` prints the state of each part and warns about groups that are too small. Targets with `collectors: all` run the
three new collectors (`peers`, `crossview`, `netflow`); with an explicit list, add the ones you want (`crossview`,
`netflow`; `peers` also needs `group:`). `crossview` needs `/proc` and `/sys` readable (no privileges).

### 16.11 How to try each one safely

Do these only on a **test machine** (§14.4), after `--baseline-lock` (all but the first three are drift or need history).

| § | What to do | What you should see |
|---|---|---|
| 16.1 | on a test target: `apt install <small package>` (or `apt install --reinstall`), then wait for the `packages` collector (or `--once`) and for a related finding (e.g. a service restart) | the finding with a green "explained by" note; `--event <id>` shows `evidence.explained_by` |
| 16.2 | generate 2–3 related findings from a test address (failed SSH logins, then add a throw-away key for the same user) | one incident in the console and in `--incidents`; the mail shows the timeline |
| 16.3 | `--vuln-sync epss`, then `--vuln-check <target>` and open the console *Vulnerabilities* tab | the EPSS and Reach columns; a listening service ranks above a library with the same CVSS |
| 16.4 | three or more test machines with the same `group:`; add a user on one | `PEER-001` on that machine |
| 16.5 | cannot be provoked without a rootkit; run it for a day and check that it reports nothing (no false positive) and that `bpf.program` entries appear in `--baseline-status` | silence = correct |
| 16.6 | after the baseline: run `logger -t mytest "something never said before"` on the test machine | `LOG-050` (info) in `--events --all` |
| 16.7 | a loop that connects every 60 s to an outside test server (`while true; do curl -s https://example.org >/dev/null; sleep 60; done`) after the baseline | `NET-030` after ~10–15 minutes |
| 16.8 | an SSH login from a VPN exit in another country shortly after one from yours (needs the geo database) | `LOG-060` / `LOG-061` |
| 16.9 | `--intel-update`, then connect to an address from a list (take one from `<state_dir>/intel/firehol_level1.list`; only open a TCP connection, e.g. `nc -w2 <ip> 80`) | `TI-002` |

---

### 16.12 Simulating an attack from another country (map and incident)

Only on a **test machine**, never on production. The lines below only write text into the test machine's log: nothing
connects to the addresses used. You need `--geo-update` first, or the map has no coordinates.

```bash
ATT=1.1.1.1        # public address in another country (Australia); documentation/private ranges are not located
VICTIM=mario       # a user that exists on the test machine (not root)

# 1. brute force: 12 failures (threshold: 8 in 10 minutes)
for i in $(seq 1 12); do
  logger -i -p auth.info -t sshd "Failed password for invalid user admin from $ATT port $((40000+i)) ssh2"
done
sleep 70           # one cycle of the `logs` collector (30 s)

# 2. the attacker gets in with a real account after failing
logger -i -p auth.info -t sshd "Failed password for $VICTIM from $ATT port 41000 ssh2"
logger -i -p auth.info -t sshd "Accepted password for $VICTIM from $ATT port 41001 ssh2"
sleep 70

# 3. the same user from a second country shortly after (impossible travel)
logger -i -p auth.info -t sshd "Accepted publickey for $VICTIM from 80.67.172.162 port 50000 ssh2: RSA SHA256:abc"
```

What you should see:

* **Map:** one point per address, even for a single attempt (the map is fed by every address that touched the machine, not
  only by those above a rule threshold).
* **Findings:** the brute force, the login after failures, and `LOG-060` (and `LOG-061` for a new country).
* **One incident** (`--incidents`, console *Incidents* tab; the update runs every 20 s) because the findings share the
  address and the account, from at least two different rules. `root` and private or documentation addresses never link
  findings. The mail shows the incident with its timeline.
* To add a threat-list hit pick the attacker address from `<state_dir>/intel/blocklist_de_ssh.list`: the login also
  becomes `TI-003` (critical) and raises the incident.

If a real attack from abroad is wanted instead, make 10–15 wrong SSH attempts with a non-existent user from a VPN or a VPS
in another country, against the test machine only; check which country the geo database reports for that address.

The findings and map points stay in the agent's database: use a separate `state_dir` for these trials.

---

### 16.13 Accepting a finding as normal (console and command line)

Some findings are correct but harmless: a new program that is your backup job, a port a colleague opened on purpose.
Instead of seeing them again and again, accept them.

* **Console:** open a finding and press *Accept as normal...*: write the reason (optional but recommended) and choose
  how long it holds (for good / 7 / 30 / 90 days). In the *Findings* tab you can also tick several rows and press
  *Accept selected as normal*. An accepted finding shows when it was accepted, when it reopens and the reason;
  *Reopen* takes it back (with the filter on "accepted", the same button reopens the selected rows).
* **Command line:** `--accept <id> --note "backup job" --days 30` and `--reopen <id>`.

What happens:

1. The finding becomes `accepted`: it leaves the open list, the alert and digest mails and the counters. An incident
   that depended on it is closed at the next update (every 20 s).
2. What is new in it (process, port, user, cron entry... the "drift") joins the **baseline** as normal. If the same
   thing comes back it stays silent: it is the same finding, and it stays accepted.
3. The decision is stored with note, time and expiry. The AI sees the note when you ask it questions about that period
   (§16.14: "accepted as normal: backup job"), so it does not present it as a threat.
4. With a deadline, the agent checks every 20 s. When it passes, what the decision had added to the baseline is removed,
   the finding is open again and **is reported again** (it is a new alert). A forgotten exception cannot hide a
   problem for ever.
5. *Reopen* does the same at once.

Cautions:

* A finding with no drift (a brute force from one address, a CVE) is only silenced for the same rule, machine and
  subject: another address is another finding.
* Accepting does not fix anything, it records that **you** judged it normal. Do not accept critical findings you have not
  understood, and prefer a deadline when in doubt. `--events --all` lists what was accepted.
* If two findings share the same new item, taking one back removes the item from the baseline; the other one stays
  accepted, but a *new* finding about that item would be reported.
* It changes only the agent's database. Nothing happens on the machines.

Try it: on a test machine provoke any finding (for instance the new-program test of §14.4), accept it from the console
"for 7 days" with a reason, check that it disappears from *Open*, appears under *Accepted* with the reason, and that
provoking it again stays silent; then *Reopen* it and see it come back at the next collection.

---

### 16.14 Ask the agent (console)

The **Ask the agent** tab answers free questions, in Italian or English: *"what changed on web01 since Tuesday?"*,
*"were there logins from new countries in the last 48 hours?"*, *"what happened yesterday?"*.

The model does not browse the machines and runs nothing. The agent does the work first and gives the model only the result:

1. **Period.** It is read from the question: *today*, *yesterday* (the whole day; *since yesterday* runs until now),
   *since Tuesday* / *Tuesday* (from that midnight / that day only; the same weekday as today means last week's),
   *last 36 hours*, *last 3 days*, *last hour*, *last week*, *this week*, *last month* (and the Italian equivalents).
   Never more than 90 days. If the question names none, the **last 7 days** are used and the answer says so. The
   selector under the question overrides the text.
2. **Machines.** The configured target names that appear in the question; none named = all. The selector overrides.
3. **Facts.** From its own database the agent collects: counts (findings active and new in the period, open now,
   resolved, accepted as normal, incidents, package changes, mails sent), the 40 most severe findings, up to 8
   incidents, up to 40 package changes (installed / upgraded / removed), the busiest attack sources and the collection
   problems. Findings the administrator accepted carry the reason. Time of day is UTC in the facts; "midnight" in the
   question is the agent host's local midnight.
4. **Answer.** The model writes the answer from those facts only, uses the agent's numbers, cites findings as `#id`
   and, when the facts are not enough, says in *what the data does not say* what is missing. Under the answer you see the
   **cited findings** (click to open), the **period** as understood, the machines and the counts that were given to
   the model, so you can check the answer against the data.

Limits to know:

* It only knows what the agent recorded: if the agent was stopped, or a collector failed (it is listed in the facts),
  there is nothing about that time. Snapshots older than `retention_days` are pruned.
* With more than 40 findings in the period the model sees the most severe ones; the page says how many it was given.
* Each question stands alone (no memory of the previous ones): repeat machine and period.
* A small local model can still misread the facts. Treat the answer as a guide and open the cited findings.
* The question (600 characters at most) and the facts go only to your own llama-server. One AI job at a time (with
  the analyses and AI reports); it takes seconds to minutes. Needs `llm.enabled: true`.
* The question is treated as a request, never as an instruction that can change the rules the model follows; the text
  that comes from the machines is treated as untrusted data, as everywhere else.

Try it: after the simulation of §16.12 ask *"what happened on <machine> in the last hour?"*: the answer must mention the
brute force and the login, cite their findings and show the period "from ... to now". Then ask something that did not
happen (*"were any packages removed yesterday?"*): it must say that nothing was recorded, not invent anything.

---

### 16.15 Settings: filters, pauses and total reset (console)

The **Settings** tab gathers what you can change without touching the YAML file. Everything is stored in the agent's
own database; nothing is written on the analysed machines.

**Exclusion filters.** A filter says "do not report this". Pick a *kind*, type a *value*, optionally limit it to one
machine, add a reason and choose how long it lasts (for good, 7, 30 or 90 days).

| Kind | Value | Example | What it silences |
|---|---|---|---|
| Rule | rule id | `LOG-050`, `LOG-05*` | the rule produces no findings |
| Package | package name | `linux-*` | vulnerability and package findings for it (also its binaries) |
| CVE | CVE id | `CVE-2026-1234`, `CVE-2024-*` | that vulnerability, everywhere |
| Listening port | `22`, `tcp/22`, `udp/5353`, `8000-8100` | `8080` | new/hidden listening sockets on that port |
| User | account name | `backup`, `svc-*` | actions of that account (logins, sudo, cron, keys); not files, processes or sockets |
| Address or network | IPv4, `a.b.c.d/n` | `192.168.1.0/24` | findings about that source; the address is left out of the attack map |
| Path | file or folder | `/opt/app/`, `/srv/data/*.log` | findings on those paths |
| Program | path or name | `/usr/bin/backup-agent`, `backup-*` | findings about that executable |

How it behaves:

* The agent **keeps reading** what is excluded and the baseline keeps learning it: only the *findings* are dropped.
  Open findings the filter covers are **closed** at once (the console says how many); they come back, as new findings,
  if you remove the filter. A filter with a deadline stops working on its own (it stays in the list as *expired*).
* A filter on one machine does not touch the others.
* **Refused on purpose**: wildcards alone (`*`), the user `root` (also through a wildcard like `r*`), networks wider
  than /8, whole system folders (`/usr/*`, `/etc/`), `..` in paths. The message says why.
* **Export / Import** (JSON) to copy the filters to another installation or keep a backup: up to 200 items per import;
  invalid ones are listed and skipped, the others go in.
* The same decisions can be taken for one finding with **Accept as normal** (§16.13); filters are for a whole class.

**Pauses.** *Mails*: 1 h, 4 h, 24 h or 3 days (a maintenance window). Findings are still collected and go out in the
first mail after the pause: nothing is lost. *AI assessment of new findings*: pause it to free the model; the findings
wait to be assessed. Analyses and questions you start from the console still work. Both are shown with a badge and
survive a restart.

**Console preferences** (saved only in your browser): refresh of the overview (never, 15 s, 30 s, 1 min, 5 min) and the
tab opened first.

**Information** (read-only): version, host, language, machines, retention, alert thresholds and recipients, model,
vulnerability feeds, database path and size, and what each table holds. The configuration itself is still changed in
the YAML file.

**Total reset.** *Danger zone → Total reset…* opens a two-step dialog:

1. It lists what will be deleted with the real counts (findings, snapshots, baseline, AI analyses, mail history,
   incidents, map days, package changes, logins, connections, accepted decisions, filters). You may tick **keep the
   exclusion filters**, and must tick *I understand*.
2. You type the word `RESET`; only then the red button works. The server checks the word as well: a request without it
   is refused.

Before deleting, the agent saves a copy of the database next to it (`<db>.before-reset-<timestamp>`), then empties
every table in one transaction and compacts the file. The dialog shows how many rows went and where the copy is:
**delete that copy by hand** when you no longer need it (it holds the old data).

What stays: the public databases (CVE, threat lists, locations), the configuration, the keys and tokens, the log files.
What starts over: the baseline learns again from zero (the "novelty" rules stay quiet during `baseline.learning`),
incidents, map and history are empty. The agent keeps running; its in-memory state (for instance the processes it has
already seen) is cleared by **restarting the service**, which is what to do after a reset.

Try it (on a test installation, never on the production one): add `port 8080` and check that the finding disappears
from the list; remove it and check that it returns at the next collection. Add `user root` and read the refusal. Pause
the mails for 1 h, run a simulation (§16.12) and check that no mail goes out, then press *Resume* and check that it
does. Finally run the reset keeping the filters: the counters go to zero, the filters stay, the copy exists, and the
console keeps working.

---
