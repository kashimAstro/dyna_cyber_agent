<p align="center"><img src="cyber_agent.jpeg" alt="dyna_cyber_agent: a security analyst in front of a server room" width="100%"></p>

<p align="center"><b>English</b> · <a href="README.it.md">Italiano</a></p>

# dyna_cyber_agent

A **24/7 security analyst** for Linux servers, written in C++20. It watches one or more machines **read-only**,
detects anomalies and intrusion attempts, checks whether the installed software has **known vulnerabilities
(CVE/CWE)**, has a **local LLM** (llama-server) assess the problems, and alerts you with clear mails in HTML and
plain text. No cloud: your data stays on your machines.

> **Read-only.** On the analysed machine the agent never writes: it reads `/proc`, `/etc`, the logs, and only runs
> commands from a whitelist hard-coded in the program. The only state it writes is its own database, on the machine
> where it runs.

## What it does

| Area | In short |
|---|---|
| **Collection** | processes (SHA-256 hashes, parents, deleted binaries), network (ports, sockets, pipes), users and SSH keys, logs (auth, web, kernel, journald), persistence (cron, systemd, preload, modules), system and `/dev`, files in `/tmp` and SUID files, package integrity, software inventory |
| **Detection** | a baseline learned over N days (what is new?) + 151 extensible YAML rules with MITRE ATT&CK and CWE references; brute force, successful login after failures, scans, shells from web servers, anomalous SUID files, persistence |
| **Vulnerabilities** | matching against OSV (distro-aware), NVD, CISA KEV and CWE downloaded locally; tells new or exploited vulnerabilities apart from old ones; ranks them by **EPSS** and by *reach* (does it listen on the network?) |
| **Beyond rules** | findings chained into **incidents** with a timeline; "explained by a package update"; **peer groups** (what exists on one of five identical machines); **cross-view** anti-rootkit checks (processes, modules, ports, eBPF); never-seen log message shapes; beaconing, new countries and traffic spikes; impossible travel; public **threat lists** matched locally |
| **AI analysis** | assesses every finding, links related findings (attack chains), writes **one single report per mail** without repeating earlier mails; defences against prompt injection |
| **Mail** | immediate alerts and a periodic digest, modern HTML (light/dark) + complete plain text, SMTP with retries |
| **Web console** | responsive page: overview, findings, CVEs, a **dark map of access attempts**, targeted AI analyses, report preview |
| **Targets** | the local machine, or remote machines over **SSH** with a small read-only gate (nothing compiled to install on the target) |

## Quick start

```bash
# 1. dependencies (Debian/Ubuntu): C++20 compiler, cmake, spdlog, sqlite3, libcurl, zlib
sudo apt install build-essential cmake ninja-build libspdlog-dev libsqlite3-dev libcurl4-openssl-dev zlib1g-dev

# 2. build and test (CMake downloads yaml-cpp, nlohmann_json and Catch2 if they are missing)
make            # = cmake + build      (make help lists every target)
make test       # about 25 s, no network

# 3. configure: start from the example
mkdir -p ~/agent && cp config/agent.example.yaml ~/agent/agent.yaml    # edit rules_dir, state_dir, recipients, smtp, targets
build/dyna_cyber_agent --config ~/agent/agent.yaml --check              # validates configuration and rules

# 4. run (in the foreground; for production see the systemd section of USAGE.md)
build/dyna_cyber_agent --config ~/agent/agent.yaml
```

During the first days (`baseline.learning`, default 7) the agent **learns** normal behaviour: the "novelty" rules
(new process, port, user) stay quiet, while log, file and vulnerability rules are always active. `--baseline-status`
shows when learning ends; `--baseline-lock` closes it early.

## Main commands

```text
dyna_cyber_agent --config <file> [mode]
  (none)              daemon: collects, analyses, sends mail
  --check             validate configuration and rules      --once          one full collection, printed
  --events [--all]    list open findings                    --event <id>    detail of a finding
  --accept <id>       accept a finding (enters the baseline) --baseline-status | --baseline-lock
  --vuln-sync | --vuln-status | --vuln-search <q> | --vuln-check        CVE database
  --llm-ping | --analyze | --llm-prompt                                 language model
  --report-preview alert|digest|test [--out dir] | --send-test-mail | --notifications
  --ssh-test <target> | --print-gate                                    SSH targets
  --geo-update | --geo-import <file> | --geo-status                     locations for the map
  --incidents | --intel-update | --intel-status                          incidents, threat lists
  --web               web console only (browse, no collection)
```

## Web console and map

Enable it in `agent.yaml` (off by default, loopback only, token access):

```yaml
web: { enabled: true, listen: 127.0.0.1, port: 8484 }
```

The token is created in `<state_dir>/web.token`; open `http://127.0.0.1:8484/` (remotely with
`ssh -L 8484:127.0.0.1:8484 host`). The **map** is drawn by the browser, with no external tiles, and shows every
address that attempted to access your machines; positions come from a **local** database (`--geo-update`, DB-IP City
Lite, CC BY 4.0): no address is ever sent to third parties.

## Configuration in brief

A single YAML file ([`config/agent.example.yaml`](config/agent.example.yaml)): `targets` (local or SSH, with
collectors and intervals), `baseline`, `language` (it | en), `llm` (llama-server URL, focus), `alerting` (thresholds, SMTP,
digest), `vuln` (feeds, thresholds), `web`, `geo`. Rules are YAML files in `rules/default/` (`rules_dir`) and reload
with `SIGHUP`.

## Security

* A non-configurable command whitelist; on SSH targets only the read-only gate through a narrow `sudo` rule.
* No host key is ever accepted automatically; secrets (SMTP, NVD, token) always come from files with strict permissions.
* Text coming from the analysed machines is treated as untrusted: neutralised in mails (no clickable links) and in
  the console (never inserted as HTML), isolated from the LLM prompt, with invented ids discarded.
* A lock prevents two instances on the same `state_dir`; a hardened systemd unit is in `deploy/`.
* Privacy: public feeds are downloaded on the agent machine; with `vuln.osv: true` the names and versions of the
  source packages go to api.osv.dev (switch off with `vuln: { osv: false }`).

## Project layout

```text
src/{core,transport,collectors,analysis,store,llm,vuln,report,geo,web,app}   C++ code
rules/default/*.yaml     detection rules                web/            console (single page) and map data
config/                  example configuration          deploy/         systemd, logrotate, sudoers, deb package
tests/                   Catch2 (~160 cases)            scripts/        collaudo.sh (data collection for trials)
Makefile  CMakeLists.txt build                          USAGE*.md       full guide (USAGE.md English, USAGE.it.md Italian)
```

## Documentation

Everything is detailed in **[USAGE.md](USAGE.md)** (Italian: [USAGE.it.md](USAGE.it.md)): build and installation
(§1, §10), configuration (§5), remote machines over SSH (§6), rules (§7), the LLM (§8), mail and reports (§9),
CVE/CWE vulnerabilities (§13), acceptance testing and safe simulations (§14), web console and map (§15).

## Development

`make test` runs the suite (zero warnings required: `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`),
`make ui-check` checks the console's JavaScript, `make debug` builds into `build-debug/`, `make package` produces
`.tar.gz` and `.deb`. The tests never touch the network or llama-server: they use fake transports, HTTP and SMTP.
