<p align="center"><img src="cyber_agent.jpeg" alt="dyna_cyber_agent: un analista di sicurezza davanti a una sala server" width="100%"></p>

<p align="center"><b>Italiano</b> · <a href="README.md">English</a></p>

# dyna_cyber_agent

Un **analista di sicurezza attivo 24 ore su 24** per server Linux, scritto in C++20. Controlla una o più macchine
**in sola lettura**, rileva anomalie e tentativi di intrusione, verifica se il software installato ha **vulnerabilità
note (CVE/CWE)**, fa valutare i problemi a un **LLM locale** (llama-server) e ti avvisa con mail chiare in HTML e testo.
Niente cloud: i dati restano sulle tue macchine.

> **Sola lettura.** Sulla macchina analizzata l'agente non scrive mai: legge `/proc`, `/etc`, i log e lancia solo
> comandi di una whitelist scritta nel codice. L'unico stato scritto è il suo database, sulla macchina dove gira.

## Cosa fa

| Area | In breve |
|---|---|
| **Raccolta** | processi (hash SHA-256, genitori, binari cancellati), rete (porte, socket, pipe), utenti e chiavi SSH, log (auth, web, kernel, journald), persistenza (cron, systemd, preload, moduli), sistema e `/dev`, file in `/tmp` e SUID, integrità dei pacchetti, inventario software |
| **Rilevamento** | baseline appresa in N giorni (cosa è nuovo?) + ~151 regole YAML estendibili con riferimenti MITRE ATT&CK e CWE; brute force, accesso riuscito dopo fallimenti, scansioni, shell da web server, SUID anomali, persistenza |
| **Vulnerabilità** | confronto con OSV (distro-aware), NVD, CISA KEV e CWE scaricati in locale; distingue le vulnerabilità nuove o sfruttate da quelle vecchie; le ordina per **EPSS** e per *raggiungibilità* (è in ascolto sulla rete?) |
| **Oltre le regole** | finding collegati in **incidenti** con cronologia; "spiegato da un aggiornamento"; **gruppi di pari** (cosa esiste su una di cinque macchine identiche); controlli anti-rootkit a **viste incrociate** (processi, moduli, porte, eBPF); forme di messaggi di log mai viste; beaconing, paesi nuovi e picchi di traffico; viaggio impossibile; **liste di minacce** pubbliche confrontate in locale |
| **Analisi AI** | valuta ogni finding, collega finding correlati (catene d'attacco), scrive **un solo resoconto per mail** senza ripetere le mail precedenti; difese contro la prompt injection |
| **Mail** | avvisi immediati e digest periodico, HTML moderno (chiaro/scuro) + testo completo, SMTP con retry |
| **Console web** | pagina responsive: panoramica, finding, CVE, **mappa dark dei tentativi di accesso**, analisi AI mirate, anteprima report |
| **Bersagli** | macchina locale oppure remota via **SSH** con un piccolo gate di sola lettura (nulla da installare di compilato sul bersaglio) |

## Avvio rapido

```bash
# 1. dipendenze (Debian/Ubuntu): compilatore C++20, cmake, spdlog, sqlite3, libcurl, zlib
sudo apt install build-essential cmake ninja-build libspdlog-dev libsqlite3-dev libcurl4-openssl-dev zlib1g-dev

# 2. compila e collauda (yaml-cpp, nlohmann_json e Catch2 li scarica CMake se mancano)
make            # = cmake + build      (make help per tutti i target)
make test       # circa 20 s, nessuna rete

# 3. configura: parti dall'esempio
mkdir -p ~/agent && cp config/agent.example.yaml ~/agent/agent.yaml    # modifica rules_dir, state_dir, recipients, smtp, target
build/dyna_cyber_agent --config ~/agent/agent.yaml --check              # valida configurazione e regole

# 4. avvia (in primo piano; per la produzione vedi la sezione systemd in USAGE.it.md)
build/dyna_cyber_agent --config ~/agent/agent.yaml
```

Per i primi giorni (`baseline.learning`, default 7) l'agente **impara** il comportamento normale: le regole di
"novità" (processo, porta, utente nuovi) restano mute, mentre log, file e vulnerabilità sono sempre attivi.
Con `--baseline-status` vedi quando finisce; `--baseline-lock` la chiude prima.

## Comandi principali

```text
dyna_cyber_agent --config <file> [modalità]
  (nessuna)           demone: raccoglie, analizza, invia mail
  --check             valida configurazione e regole        --once          una raccolta completa e stampa
  --events [--all]    elenca i finding aperti               --event <id>    dettaglio di un finding
  --accept <id>       accetta un finding (entra in baseline) --baseline-status | --baseline-lock
  --vuln-sync | --vuln-status | --vuln-search <q> | --vuln-check        database CVE
  --llm-ping | --analyze | --llm-prompt                                 modello linguistico
  --report-preview alert|digest|test [--out dir] | --send-test-mail | --notifications
  --ssh-test <target> | --print-gate                                    bersagli SSH
  --geo-update | --geo-import <file> | --geo-status                     posizioni per la mappa
  --incidents | --intel-update | --intel-status                          incidenti, liste di minacce
  --web               solo console web (consultazione, senza raccolta)
```

## Console web e mappa

Abilitala in `agent.yaml` (spenta di default, solo su loopback, accesso con token):

```yaml
web: { enabled: true, listen: 127.0.0.1, port: 8484 }
```

Il token viene creato in `<state_dir>/web.token`; apri `http://127.0.0.1:8484/` (da remoto con
`ssh -L 8484:127.0.0.1:8484 host`). La **mappa** disegna con il browser, senza tile esterni, tutti gli indirizzi che
hanno tentato l'accesso; le posizioni arrivano da un database **locale** (`--geo-update`, DB-IP City Lite, CC BY 4.0):
nessun indirizzo viene inviato a terzi.

## Configurazione in breve

Un solo file YAML ([`config/agent.example.yaml`](config/agent.example.yaml)): `targets` (locale o SSH, con collector
e intervalli), `baseline`, `language` (it | en), `llm` (URL di llama-server, focus), `alerting` (soglie, SMTP, digest), `vuln`
(feed, soglie), `web`, `geo`. Le regole sono file YAML in `rules/default/` (`rules_dir`) e si ricaricano con `SIGHUP`.

## Sicurezza

* Whitelist di comandi non configurabile; sui bersagli SSH solo il gate di sola lettura via `sudo` mirato.
* Nessuna chiave host accettata in automatico; segreti (SMTP, NVD, token) sempre da file con permessi stretti.
* Il testo che arriva dalle macchine analizzate è trattato come non fidato: neutralizzato nelle mail (niente link
  cliccabili) e nella console (mai inserito come HTML), isolato dal prompt dell'LLM, con id inventati scartati.
* Un lock impedisce due istanze sullo stesso `state_dir`; unità systemd rinforzata in `deploy/`.
* Privacy: i feed pubblici si scaricano sulla macchina dell'agente; con `vuln.osv: true` nomi e versioni dei
  pacchetti sorgente vanno ad api.osv.dev (disattivabile con `vuln: { osv: false }`).

## Struttura del progetto

```text
src/{core,transport,collectors,analysis,store,llm,vuln,report,geo,web,app}   codice C++
rules/default/*.yaml     regole di rilevamento          web/            console (pagina unica) e dati della mappa
config/                  configurazione di esempio      deploy/         systemd, logrotate, sudoers, pacchetto deb
tests/                   Catch2 (~160 casi)             scripts/        collaudo.sh (raccolta dati per le prove)
Makefile  CMakeLists.txt build                          USAGE*.md       guida completa (USAGE.md inglese, USAGE.it.md italiano)
```

## Documentazione

Tutti i dettagli sono in **[USAGE.it.md](USAGE.it.md)** (in inglese: [USAGE.md](USAGE.md)): compilazione e installazione (§1, §10), configurazione (§5),
macchine remote via SSH (§6), regole (§7), LLM (§8), mail e report (§9), vulnerabilità CVE/CWE (§13),
collaudo e simulazioni sicure (§14), console web e mappa (§15).

## Sviluppo

`make test` esegue la suite (zero warning richiesti: `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`),
`make ui-check` controlla il JavaScript della console, `make debug` compila in `build-debug/`,
`make package` produce `.tar.gz` e `.deb`. I test non toccano mai la rete né llama-server: usano trasporti,
HTTP e SMTP finti.
