<p align="right"><a href="USAGE.md">English</a> · <b>Italiano</b></p>

# dyna_cyber_agent — guida all'uso

Agente di sicurezza in C++ che sorveglia una o più macchine Linux **in sola lettura**, rileva anomalie,
controlla se il software installato e' soggetto a **vulnerabilita' note (CVE) e a classi di debolezza (CWE)**
scaricando periodicamente i feed pubblici, le fa valutare a un LLM locale (llama-server) e le segnala
all'amministratore via mail (HTML + testo). Una **console web** locale con mappa degli attacchi permette di consultare tutto.
Oltre alle singole regole collega i finding in **incidenti**, riconosce cio' che un aggiornamento spiega, ordina le CVE per
sfruttabilita' reale e raggiungibilita', confronta macchine con lo stesso ruolo, incrocia le viste del kernel contro i
rootkit, impara la forma dei messaggi di log, sorveglia traffico in uscita e login e confronta liste pubbliche di minacce (§16).

```
 collector ──► snapshot ──► baseline + regole ──► finding ──► LLM (analista) ──► mail HTML/TXT
 (processi, rete, utenti,    (SQLite)     (cosa e' nuovo/       (deduplicati)  (valuta, correla,   (alert + digest)
  log, persistenza, sistema,              cosa e' malevolo)                     consiglia)
  file, integrita' pacchetti,
  software installato) ◄── feed CVE / CISA KEV / CWE / OSV (scaricati sulla macchina dell'agente)
      ▲
  trasporto: locale  oppure  SSH (gate di sola lettura)
```

**Garanzia di sola lettura.** Sulla macchina analizzata l'agente non scrive mai: legge `/proc`, `/etc`, ecc. e
esegue solo comandi da una whitelist scritta nel codice (non configurabile). L'unico stato scritto è il
database dell'agente (`state_dir`), sulla macchina dove gira l'agente.

---

## 1. Requisiti e compilazione

| Cosa | Dettaglio |
|---|---|
| Sistema | Linux; sul bersaglio servono gli strumenti GNU (coreutils/findutils): `base64`, `find -printf`, `stat -c`, `sha256sum`, `head`, `grep` |
| Compilatore | g++ con C++20, CMake ≥ 3.20, Ninja (consigliato) |
| Librerie | spdlog, SQLite3, libcurl, zlib (di sistema); yaml-cpp, nlohmann_json e Catch2 vengono scaricate da CMake se mancano |
| Per SSH | client OpenSSH (`/usr/bin/ssh`) sulla macchina dell'agente |
| Per l'LLM | `llama-server` (llama.cpp) con un modello GGUF, es. Qwen3-Coder Q8 |

```bash
make                  # configura con CMake e compila (vedi `make help`)
make test             # circa 210 casi di test, ~25 s, nessuno usa la rete
./build/dyna_cyber_agent --help       # elenco comandi
```

Senza `make`: `cmake -S . -B build -G Ninja && cmake --build build && ctest --test-dir build --output-on-failure`.

Se la macchina non ha accesso a Internet, installa `libyaml-cpp-dev`, `nlohmann-json3-dev` e `catch2` prima di compilare.

Pacchetto installabile (binario, regole, unita' systemd, esempi): dalla cartella `build`

```bash
cpack                                   # produce dyna-cyber-agent_<versione>_amd64.deb e un .tar.gz  (oppure: make package)
sudo apt install ./dyna-cyber-agent_0.9.0_amd64.deb
```

Il `.deb` crea l'utente `dyna_cyber_agent`, le cartelle, copia le regole e una configurazione di esempio in
`/etc/dyna_cyber_agent/` (senza mai sovrascrivere file esistenti) e **non avvia** nulla: vedi §10.

---

## 2. Avvio rapido (monitorare questa macchina)

```bash
# 1) configurazione minima
mkdir -p ~/agent && cp config/agent.example.yaml ~/agent/agent.yaml
$EDITOR ~/agent/agent.yaml            # lascia solo il target "localhost"; imposta state_dir e rules_dir

# 2) controlla che tutto sia valido (config + regole), senza contattare nessuno
./build/dyna_cyber_agent --config ~/agent/agent.yaml --check

# 3) prima fotografia: nei primi giorni l'agente IMPARA cosa e' normale e non segnala drift
./build/dyna_cyber_agent --config ~/agent/agent.yaml --once

# 4) in esecuzione continua (Ctrl+C per fermare)
./build/dyna_cyber_agent --config ~/agent/agent.yaml
```

Config minima per provare (senza LLM e senza mail):

```yaml
state_dir: /home/utente/agent/state
rules_dir: /home/utente/claude/dyna_cyber_agent/rules/default
llm: { enabled: false }
targets:
  - { name: localhost, transport: local }
```

---

## 3. Comandi

`dyna_cyber_agent --config <file> [modalita']`

| Modalita' | Cosa fa |
|---|---|
| *(nessuna)* | gira in continuo fino a SIGINT/SIGTERM: un thread per target, pulizia dati vecchi, LLM, mail e, se abilitata, la console web |
| `--check` | valida config e regole, controlla SMTP/LLM configurati (senza contattarli), self-test locale |
| `--once` | esegue ogni collector una volta, salva, analizza, stampa snapshot e nuovi finding; se c'e' LLM/mail li usa subito |
| `--events [--all]` | elenca i finding aperti (`--all` include quelli accettati) |
| `--event <id>` | dettaglio di un finding: evidenze, cosa manca alla baseline, valutazione dell'LLM |
| `--accept <id>` | "questo e' normale": lo marca accettato e aggiunge il suo drift alla baseline |
| `--baseline-status` | per ogni target: LEARNING o ENFORCING, inizio e fine dell'apprendimento e numero di elementi appresi |
| `--baseline-lock` | termina subito la fase di apprendimento di tutti i target |
| `--analyze` | fa valutare all'LLM i finding aperti che non hanno ancora una valutazione |
| `--llm-prompt` | **stampa** il prompt esatto che andrebbe all'LLM (nessuna rete) |
| `--llm-ping` | controlla che llama-server sia pronto e confronta la dimensione del contesto |
| `--report-preview alert\|digest\|test [--out dir]` | scrive i file `.html`/`.txt` della mail; **non invia nulla** |
| `--send-test-mail` | invia una mail di prova ai destinatari configurati |
| `--notifications` | elenca le mail inviate o fallite |
| `--ssh-test <target\|all>` | prova connessione SSH, strumenti remoti e privilegi; non raccoglie nulla |
| `--print-gate` | stampa lo script gate da installare sul bersaglio (modalita' rinforzata); non serve `--config` |
| `--version` | stampa la versione |
| `--vuln-sync [kev\|nvd\|cwe\|epss\|all]` | scarica ora i feed CVE / CISA KEV / CWE / EPSS (riprendibile; Ctrl+C e' sicuro) |
| `--vuln-status` | stato del database vulnerabilita' e del confronto per ogni target |
| `--vuln-search <testo\|CVE-id>` | cerca un CVE nel database locale (punteggio, CWE, se sfruttato attivamente) |
| `--vuln-check [target]` | confronta ora l'inventario software di un target con il database (interroga OSV: vedi §13.6) |
| `--incidents` | concatena ora i finding aperti in incidenti e li elenca con la cronologia (§16.2) |
| `--intel-update` | scarica ora le liste pubbliche di IP di threat intelligence (§16.9) |
| `--intel-status` | mostra le liste di minacce su disco (voci, data) |
| `--geo-update` | scarica il database offline delle posizioni degli IP usato dalla mappa (§15.1) |
| `--geo-import <file>` | costruisce quel database da un CSV / `.csv.gz` scaricato a mano |
| `--geo-status` | mostra il database delle posizioni in uso |
| `--web` | serve solo la console web (senza raccolta): consulta i dati gia' raccolti (§15) |

Codici di uscita: `0` ok, `1` errore (config, rete, collector fallito), `2` uso errato della riga di comando.

---

## 4. Flusso di lavoro tipico

### 4.1 Apprendimento della baseline

Per i primi `baseline.learning` giorni (default 7) l'agente **impara** processi, binari (con hash), porte in
ascolto, destinazioni in uscita, utenti, chiavi SSH e regole sudo. In questa fase scattano solo le regole
"assolute" (es. shell lanciata da nginx, binario cancellato in `/tmp`), non quelle di novita'.

**Cosa succede esattamente durante l'apprendimento**

* Tutto cio' che vede entra in baseline **senza generare finding**: nuovo processo, nuova porta, nuovo utente,
  nuovo cron, nuova chiave SSH. Se in quei giorni qualcosa di anomalo gira sulla macchina, viene imparato come normale:
  per questo conviene farlo su una macchina in stato noto.
* Restano **sempre attive**: le regole assolute (shell da web server, binario cancellato, ecc.), le regole sui log
  (brute force, login riuscito dopo molti fallimenti), l'integrita' dei file e le **vulnerabilita' (CVE)**, che non
  dipendono dalla baseline.
* La finestra parte dal **primo snapshot** del target. `--baseline-status` mostra quando e' iniziata, quando finisce e
  quanti giorni mancano; all'avvio il log riporta lo stesso. `--baseline-lock` la chiude prima.
* Le **correlazioni** (catene d'attacco) dell'AI nascono dai finding: con l'apprendimento attivo ci sono pochi finding
  di "novita'" da collegare, quindi le correlazioni sono rare. Finito l'apprendimento diventano piu' frequenti. Non e' un
  difetto del modello: gli manca la materia prima.

```bash
dyna_cyber_agent --config agent.yaml --baseline-status
# localhost: LEARNING, 241 identities
#   learning started 2026-10-22 08:00:00 UTC, window 7 day(s)
#   ends 2026-10-29 08:00:00 UTC (5 day(s) left): ...
```

Quando la macchina ha mostrato il suo comportamento normale (un ciclo completo di lavoro: backup notturni,
cron, deploy), chiudi l'apprendimento:

```bash
dyna_cyber_agent --config agent.yaml --baseline-lock
# localhost: ENFORCING (locked), 241 identities
```

> Il conto dei 7 giorni parte al primo snapshot del target: se il demone resta spento, la finestra scade
> comunque con pochi dati. Meglio lasciarlo girare di continuo, o usare `--baseline-lock` quando sei pronto.

### 4.2 Esaminare e chiudere i finding

```bash
dyna_cyber_agent --config agent.yaml --events
# #2 [medium] PROC-007 Executable never seen on this host | web01 | proc|/opt/tool/run|1000 | seen 3x ... | open

dyna_cyber_agent --config agent.yaml --event 2        # dettaglio, evidenze e valutazione AI
dyna_cyber_agent --config agent.yaml --accept 2       # e' legittimo: entra nella baseline, non verra' piu' segnalato
```

Un finding non accettato resta aperto e compare nei digest; le ripetizioni non generano nuove mail (deduplica).

**Ciclo di vita.** I finding sui dati *di stato* (processi, porte, file, configurazione, pacchetti, vulnerabilita')
si **risolvono da soli** quando la condizione sparisce: aggiorni un pacchetto e le sue vulnerabilita' passano a
*resolved*; se il problema ritorna, il finding si riapre **senza rimandare la mail**. Il digest conta quanti ne
sono stati risolti nel periodo. I finding dei **log** sono storia e restano aperti finche' non li accetti.
`--events --all` mostra anche quelli accettati e risolti.

### 4.3 Dopo un aggiornamento software

Aggiornare un pacchetto cambia l'hash dei binari (`PROC-008`) e puo' far apparire processi "nuovi". Dopo un
aggiornamento pianificato, esamina i finding e accettali (`--accept`), oppure rilancia l'apprendimento
cancellando il database di quel target (vedi §10).

---

## 5. Configurazione (`agent.yaml`)

Un esempio completo e commentato e' in `config/agent.example.yaml`. Gli errori di configurazione bloccano
l'avvio con un messaggio preciso (nome della chiave e motivo). Una chiave impostata a `null`, `~` o lasciata vuota
vale "non impostata".

### 5.1 Generale

| Chiave | Default | Significato |
|---|---|---|
| `language` | `it` | `it` oppure `en`. **L'unica impostazione di lingua**: etichette delle mail (HTML e TXT), testo scritto dall'AI e console web. I titoli delle regole e i nomi MITRE/CWE sono sempre in inglese. Sostituisce i vecchi `alerting.language` e `llm.language`, che ora vengono rifiutati |
| `log_level` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `critical`, `off` |
| `log_file` | *(vuoto)* | se impostato, scrive anche su file (oltre a stderr) |
| `state_dir` | `/var/lib/dyna_cyber_agent` | database SQLite (`agent.db`: snapshot, baseline, finding, analisi, mail, sorgenti degli attacchi; `vuln.db`; `geo.db`) e token della console web |
| `retention_days` | `14` | gli snapshot piu' vecchi vengono cancellati (finding, baseline e storico delle sorgenti di attacco restano) |
| `rules_dir` | `/etc/dyna_cyber_agent/rules` | cartella con i file `.yaml` delle regole (anche in sottocartelle). Deve essere una cartella, non un pattern |
| `baseline.learning` | `7d` | durata dell'apprendimento (`30s`, `5m`, `2h`, `7d`) |

Un solo agente alla volta puo' usare uno `state_dir`: un file di lock (`agent.lock`) fa rifiutare l'avvio di una seconda
istanza. Tieni la cartella privata (`chmod 750`): contiene baseline ed evidenze.

### 5.2 Target

```yaml
targets:
  - name: localhost            # nome univoco, appare nei report
    transport: local           # local | ssh
    collectors: all            # oppure [processes, network, users]
    interval: { processes: 30s, network: 15s, users: 5m }   # opzionale; questi sono i default
```

`collectors: all` abilita tutti i tredici collector (vedi §5.5). I target sono raccolti **in parallelo**: un host
lento o irraggiungibile non rallenta gli altri.

`group: web` (opzionale) mette il target in un gruppo di pari: le macchine con lo stesso gruppo sono confrontate fra loro
(§16.4; almeno 3 membri).

Chiavi specifiche dei log (collector `logs`):

| Chiave | Default | Significato |
|---|---|---|
| `log_paths` | *(autorilevamento)* | elenco di file di log; prefisso `auth:`, `web:`, `kernel:` o `syslog:` per forzare il tipo; `*` e `?` ammessi solo nel nome del file, es. `web:/srv/logs/*.access.log` |
| `log_backfill_kb` | `0` | alla prima lettura di un log legge anche gli ultimi N KB (0 = parte dalla fine, senza rileggere la storia) |

Chiavi SSH (`transport: ssh`):

| Chiave | Default | Significato |
|---|---|---|
| `host`, `user`, `key` | *(obbligatori)* | destinazione e chiave privata dell'agente |
| `port` | `22` | |
| `known_hosts` | `~/.ssh/known_hosts` | file con le chiavi host; la verifica e' **sempre** attiva |
| `proxy_jump` | — | bastion: `utente@host[:porta]` |
| `gate` | `stream` | `stream` = nulla da installare; `installed` = esegue lo script gia' presente sul bersaglio |
| `gate_path` | — | (solo `installed`) percorso assoluto, es. `/usr/local/bin/dyna_cyber_agent-gate` |
| `sudo` | `false` | (solo `installed`) esegue il gate con `sudo -n` per leggere i processi di tutti |
| `connect_timeout` | `10` | secondi per connessione + autenticazione |
| `op_timeout` | `30` | secondi per ogni gruppo di letture |
| `ssh_binary` | `/usr/bin/ssh` | percorso assoluto del client ssh |

La chiave privata deve essere **leggibile dall'utente con cui gira l'agente**. Una chiave creata con `sudo` in una cartella
solo-root non lo e': SSH ripiega in silenzio sulla password e il test fallisce con `Permission denied (publickey,password)`.

### 5.3 LLM

```yaml
llm:
  enabled: true
  url: http://127.0.0.1:8080
  timeout: 300              # secondi per richiesta (un modello Q8 grande puo' essere lento)
  temperature: 0.2
  max_tokens: 4096
  context_tokens: 32768     # non oltre il -c di llama-server (verificalo con --llm-ping)
  max_findings_per_call: 8
  batch_window: 30s         # raggruppa i finding vicini in una sola chiamata
  model: ""                 # opzionale
  api_key_file: ""          # solo se llama-server usa --api-key
  focus_file: ""            # istruzioni dell'admin, vedi §8
```

### 5.4 Mail

```yaml
alerting:
  min_severity: high        # info | low | medium | high | critical: soglia degli avvisi immediati
  alert_delay: 2m           # attesa per la valutazione AI e per raggruppare finding correlati
  cooldown: 5m              # pausa minima tra due avvisi (i critical la saltano)
  max_per_hour: 6           # tetto massimo di avvisi all'ora
  subject_prefix: "[dyna_cyber_agent]"
  recipients: [admin@example.com]
  smtp:
    host: smtp.example.com
    port: 587
    tls: starttls           # starttls | ssl | none  (none con password e' rifiutato, salvo localhost)
    user: agent
    password_file: /etc/dyna_cyber_agent/smtp.pass     # chmod 600
    from: "dyna_cyber_agent <agent@example.com>"
    timeout: 30
  digest:
    enabled: true
    every: 24h              # oppure  at: "08:00"  (ora locale)
    min_severity: low
    send_when_empty: false  # true = invia anche "nessuna novita'" (battito di vita). Un collector fermo forza sempre la mail
```

Senza `recipients` l'agente funziona normalmente ma non invia mail. Lo stesso indirizzo scritto due volte (o con maiuscole
diverse) riceve una sola copia.

**Relay SMTP interno senza autenticazione** (tipico di una LAN): **non** mettere `user:` ne' `password_file:` e usa
`tls: none`. L'agente rifiuta di inviare credenziali su una connessione non cifrata (salvo verso `localhost`), quindi
se resta un `user:` (anche quello della configurazione di esempio) la configurazione viene rifiutata e l'errore indica
il campo responsabile.

```yaml
  smtp: { host: 192.168.1.25, port: 25, tls: none, from: "dyna_cyber_agent <agent@tuodominio.lan>" }
```

---

### 5.5 I collector

*Per le vulnerabilita' (CVE/CWE) c'e' una sezione `vuln:` dedicata: vedi §13.4.*


| Collector | Intervallo | Cosa osserva | Privilegi / costo |
|---|---|---|---|
| `processes` | 30 s | processi, eseguibili con hash SHA-256, genitore, memoria rwx, binari cancellati o in `/tmp` | root o `CAP_SYS_PTRACE` per vedere tutti i processi |
| `network` | 15 s | socket TCP/UDP/raw/unix/packet e processo proprietario | come sopra per i proprietari |
| `users` | 5 min | account, gruppi, stato password (mai l'hash), chiavi SSH, regole sudo | root per `shadow` e `sudoers` |
| `logs` | 30 s | `auth.log`/`secure` (sshd, sudo, su, useradd...), access log nginx/apache, `kern.log`, journald | gruppo `adm` (o root) per leggere i log |
| `persistence` | 5 min | cron (sistema e utenti), unita' systemd, file di avvio shell (`.bashrc`, `profile.d`...), `rc.local`, `init.d`, `ld.so.preload` | root per i crontab altrui |
| `system` | 10 min | moduli kernel e taint, sysctl di sicurezza, mount, DNS e `/etc/hosts`, `sshd_config`, interfacce promiscue, nodi in `/dev` | quasi tutto leggibile senza privilegi |
| `files` | 30 min (SUID ogni 6 h) | file SUID/SGID, eseguibili/nascosti/setuid in `/tmp` `/var/tmp` `/dev/shm` (i file ordinari sono solo contati), file scrivibili da tutti nelle cartelle di sistema, eseguibili in `/usr/local` `/opt` `/srv` | la ricerca SUID percorre **tutto il disco** a priorita' minima (nice 19, ionice idle): su dischi grandi puo' durare 10+ minuti, per questo gira al massimo ogni 6 ore; il primo `--once` e' lento |
| `integrity` | 6 h | confronto dei file installati con i pacchetti (`dpkg -V` / `rpm -Va`) | pesante sul disco; root per leggere tutti i file |
| `packages` | 6 h | distribuzione, kernel e **tutti i pacchetti installati** (con il pacchetto sorgente), da `/var/lib/dpkg/status` o `rpm -qa`; anche installazioni/aggiornamenti/rimozioni e i file di cui ogni pacchetto e' proprietario (§16.1) | leggero (3.600 pacchetti in ~30 ms; gli elenchi file si leggono 600 pacchetti per volta) |
| `vulns` | 1 h | confronta l'inventario con il database CVE (vedi §13); **non legge nulla dal bersaglio**, lavora sulla macchina dell'agente | richiede `packages`; usa rete verso OSV se abilitato |
| `peers` | 30 min | confronta il target con gli altri membri del suo `group:` (§16.4); **non legge nulla dal bersaglio** | richiede `group:` con 3+ membri e dati recenti degli altri |
| `crossview` | 10 min | la stessa cosa attraverso due interfacce del kernel (processi, moduli, porte) e i programmi eBPF (§16.5) | tutto cio' che legge e' leggibile da tutti; `kallsyms` si legge una volta all'ora |
| `netflow` | 2 min | connessioni in uscita a ritmo costante e velocita' del traffico in uscita (§16.7); lavora su cio' che `network` ha registrato piu' `/proc/net/dev` | leggero |

I log sono letti **in modo incrementale**: solo le righe nuove dall'ultima volta. Gli offset sono nel database,
quindi un riavvio non perde ne' ripete righe. La rotazione (anche con riuso dell'inode) e' riconosciuta e la
coda del file ruotato viene comunque letta. Se mancano i file classici l'agente usa `journalctl`.
Gli eventi dei log sono aggregati: 10 login falliti dallo stesso indirizzo sono **un** finding che conta le
ripetizioni, e un login riuscito dopo 3 o piu' fallimenti dallo stesso indirizzo e' segnalato come critico.
Il tempo degli eventi e' quello della raccolta: fuso orario e anno mancante dei log syslog non contano.

Per limitare i collector (o evitare quelli pesanti su un target): `collectors: [processes, network, users, logs]`.

## 6. Monitorare macchine remote via SSH

### 6.1 Come funziona (e perche' e' sicuro)

L'agente avvia il client `ssh` di sistema con opzioni rigide (`BatchMode`, `StrictHostKeyChecking=yes`,
niente agent/forwarding/password). Dall'altra parte gira il **gate**: un piccolo script `sh` che accetta solo
richieste di sola lettura (`read`, `readlink`, `ls`, `stat`, `sha256`, ...) e puo' eseguire solo una lista
fissa di comandi. Le richieste viaggiano a gruppi: una scansione completa di `/proc` richiede pochi round trip
invece di migliaia. Il gate (protocollo **versione 2**) sa anche leggere i log dal punto in cui eri arrivato,
leggere il journal e lanciare le sole scansioni di filesystem predefinite (`find` a priorita' minima).
Se aggiorni l'agente e il gate installato e' di una versione precedente, `--ssh-test` e il log lo segnalano:
basta rieseguire `--print-gate` sul bersaglio.

Due modalita':

| | `gate: stream` (default) | `gate: installed` (consigliata in produzione) |
|---|---|---|
| Installazione sul bersaglio | nessuna | script root-owned + riga sudoers + `command=` in authorized_keys |
| Se la chiave viene rubata | l'attaccante ha una shell come `audit-ro` | puo' solo inviare le richieste di sola lettura del gate |
| Visibilita' processi altrui | solo se l'utente ssh e' privilegiato | completa, con `sudo: true` |

**Non installi l'agente sui bersagli.** Sul bersaglio va solo il gate: un unico script di testo (nessun binario compilato,
nessun database, nessun LLM). Analisi, database, LLM e mail restano sulla macchina dell'agente. Puoi leggere lo script
prima di installarlo: `dyna_cyber_agent --print-gate | less`.

### 6.2 Passo per passo (modalita' rinforzata)

**Sulla macchina dell'agente** — chiave dedicata e chiavi host:

```bash
sudo mkdir -p /etc/dyna_cyber_agent/keys && sudo chmod 700 /etc/dyna_cyber_agent/keys
sudo ssh-keygen -t ed25519 -N '' -C dyna_cyber_agent@monitor01 -f /etc/dyna_cyber_agent/keys/web01

# chiave host del bersaglio: acquisiscila e VERIFICA l'impronta per un canale indipendente (es. console)
ssh-keyscan -p 22 -t ed25519 web01.example.com | sudo tee -a /etc/dyna_cyber_agent/known_hosts
ssh-keygen -lf /etc/dyna_cyber_agent/known_hosts            # confronta con `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` sul bersaglio
```

L'agente non accetta mai chiavi host nuove da solo (niente trust-on-first-use).

> I file in `/etc/dyna_cyber_agent/keys/` devono essere leggibili dall'utente con cui gira l'agente. Se li crei con `sudo`
> e poi avvii l'agente come utente normale, fai `chown` a quell'utente oppure tieni la chiave nella sua home
> (es. `~/agent/keys/web01`, modo 600) e punta `key:` li'.

**Sul bersaglio** — utente, gate e sudo (da amministratore):

```bash
sudo useradd -m -s /bin/sh audit-ro            # la shell deve essere compatibile POSIX (sh/bash/dash)
```

Il gate deve essere di proprieta' di root e **non scrivibile da `audit-ro`** (gira come root tramite sudo!). Installalo
dalla macchina dell'agente in due passi (un semplice `... | ssh host 'sudo tee ...'` fallisce quando sudo chiede la
password, perche' la pipe occupa lo stdin e non c'e' un terminale):

```bash
# sulla macchina dell'agente
dyna_cyber_agent --print-gate > /tmp/dyna_cyber_agent-gate           # facoltativo: leggilo
scp /tmp/dyna_cyber_agent-gate admin@web01:/tmp/dyna_cyber_agent-gate
ssh -t admin@web01 'sudo install -o root -g root -m 755 /tmp/dyna_cyber_agent-gate /usr/local/bin/dyna_cyber_agent-gate && rm /tmp/dyna_cyber_agent-gate'
```

Poi, sul bersaglio:

```bash
# sudo: audit-ro puo' lanciare SOLO il gate
echo 'audit-ro ALL=(root) NOPASSWD: /usr/local/bin/dyna_cyber_agent-gate' | sudo tee /etc/sudoers.d/dyna_cyber_agent
sudo chmod 440 /etc/sudoers.d/dyna_cyber_agent && sudo visudo -c

# authorized_keys di audit-ro: la chiave puo' eseguire solo il gate
sudo -u audit-ro mkdir -p -m 700 /home/audit-ro/.ssh
echo 'command="sudo -n /usr/local/bin/dyna_cyber_agent-gate",restrict ssh-ed25519 AAAA...chiave-pubblica... dyna_cyber_agent@monitor01' \
  | sudo -u audit-ro tee /home/audit-ro/.ssh/authorized_keys
```

Incolla il contenuto di `web01.pub` al posto di `AAAA...chiave-pubblica...`: una sola riga, preceduta dall'opzione `command=`.
La home non deve essere scrivibile da altri; `.ssh` e' `700` e `authorized_keys` `600`, di proprieta' di `audit-ro`.

**Nella config dell'agente:**

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

**Verifica** (non raccoglie nulla; l'output qui sotto e' un esempio, i valori cambiano):

```bash
dyna_cyber_agent --config agent.yaml --ssh-test web01
# web01: connected to 'web01' in 85 ms (gate: installed + sudo)
#   remote tools: base64=ok find=ok stat=ok sha256sum=ok head=ok grep=ok ... find_printf=ok stat_c=ok uid=0
#   scan test: 212/214 process stat files read in 310 ms
#   run test: ok (Linux 6.8.0 ...)
```

Infine **riavvia l'agente**: la configurazione e' letta solo all'avvio (un `SIGHUP` ricarica le regole, non i target).
Il nuovo target avvia una propria finestra di apprendimento (§4.1).

### 6.3 Modalita' veloce senza installare nulla

Per un primo test basta la config SSH senza `gate`/`sudo` (modalita' `stream`). Funziona subito, ma l'utente
`audit-ro` normale **non puo' leggere `/proc/<pid>/exe`, `fd` e `maps` dei processi di altri utenti**: i processi
altrui e i proprietari dei socket risulteranno invisibili (l'agente lo segnala nei warning e `--ssh-test`
stampa una nota). Per vederli servono privilegi: gate installato con `sudo` (sopra), oppure l'utente `root`
(sconsigliato).

### 6.4 Problemi frequenti

| Sintomo | Causa / rimedio |
|---|---|
| `Host key verification failed` | la chiave host non e' in `known_hosts`: aggiungila (§6.2) |
| `Permission denied (publickey)` | chiave pubblica non in `authorized_keys`, permessi sbagliati su `~/.ssh`, o `key:` non punta alla chiave privata |
| `Load key "...": Permission denied` seguito da `Permission denied (publickey,password)` | l'utente dell'agente non puo' leggere il file della chiave privata (vedi la nota nel §6.2) |
| `unexpected greeting ... is the gate installed and up to date?` | il comando remoto non e' il gate: percorso `gate_path` errato, `sudo` che chiede la password, o gate di versione diversa (reinstalla con `--print-gate`) |
| `MISSING` in `--ssh-test` | il bersaglio non ha gli strumenti GNU (es. BusyBox/Alpine non e' supportato) |
| `unreachable ...; retrying later` | dopo un errore l'agente aspetta 15 s prima di riprovare; il target e' segnalato nel digest come "NON AGGIORNATO" |
| `command not available over ssh` | quel comando non e' nella lista del gate (vedi `Gate::commands()` in `src/transport/gate.cpp`) |

---

## 7. Regole

Le regole sono file YAML in `rules_dir` (un esempio per ogni tipo in `rules/default/`: **151 regole** in `processes`, `network`, `users`, `logs`,
`persistence`, `system`, `files`, `vulns`, `peers`, `crossview` e `intel`, tutte con tag MITRE ATT&CK, descrizione e rimedio). Una regola sbagliata (operatore, regex, tipo o faccetta inesistente) **blocca l'avvio** con
file e nome della regola: non puo' non scattare in silenzio per un refuso.

```yaml
- id: LOCAL-001                      # univoco in tutte le cartelle
  title: Interprete in ascolto sulla rete
  severity: high                     # info | low | medium | high | critical
  mitre: [T1571]
  description: Un interprete di script ascolta su un indirizzo non locale.
  remediation: Identifica il processo e verifica da dove arriva lo script.
  match:
    type: socket.inet                # tipo di osservazione (tabella sotto)
    tags_all: [listening, exposed]   # tutti i tag; oppure tags_any: [...]
    drift: net.listen                # (opz.) richiede che l'elemento NON sia nella baseline: "any" o una faccetta
    drift_absent: [process.exe]      # (opz.) faccette che NON devono essere in drift
    where:                           # (opz.) tutte le condizioni (AND)
      - {field: owners.comm, op: regex, value: '^(python|perl|ruby|php|node)'}
      - any:                         # any / all / not si possono annidare
          - {field: local_port, op: gt, value: 1024}
          - {not: {field: proto, op: equals, value: tcp}}
```

Operatori: `equals`, `in` (lista), `startswith`, `endswith`, `contains` (anche con lista = uno qualsiasi),
`regex` (ECMAScript, ricerca), `exists` (true/false), `gt`, `gte`, `lt`, `lte`. Un campo che e' un array (es.
`owners.comm`) vale se **almeno un** elemento soddisfa la condizione; `owners.0.comm` indica il primo.
Una regola senza nessuna condizione e' rifiutata (scatterebbe su tutto). Un elenco facoltativo `cwe: [CWE-732]` indica la
classe di debolezza a cui la regola si riferisce.

Campi per tipo di osservazione:

| `type` | Campi principali | Tag |
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
| `log.source` | attivita' per indirizzo per la mappa degli attacchi (§15.1); nessuna regola la usa | — |
| `cron.entry` | `file` `schedule` `user` `command` `owner_crontab` | `reboot` `command_in_volatile_dir` `pipe_to_shell` `base64_exec` `reverse_shell` |
| `cron.script` / `startup.file` | `path` `sha256` `size` `kind` `owner` | `ld_preload` `alias_hijack` `anti_forensics` `reverse_shell` `pipe_to_shell` `base64_exec` `volatile_dir_reference` `ssh_rc` |
| `systemd.unit` | `path` `name` `exec[]` `user` `wanted_by[]` `schedule` `listen` `sha256` | `admin_unit` `exec_in_volatile_dir` `hidden_unit` + i tag dei contenuti sospetti |
| `systemd.enabled` / `preload.entry` | `unit` `wants_dir` / `library` | `ld_so_preload` |
| `kernel.module` / `kernel.taint` | `name` `size` `used_by[]` `taint` / `value` `flags` | `module_unsigned` `module_out_of_tree` `unsigned_module` |
| `sysctl.value` | `key` `value` `expected` | `weak_setting` |
| `mount.entry` / `net.dns` / `net.hosts_entry` | `mountpoint` `fstype` `options[]` / `nameserver` / `ip` `names[]` | `exec_allowed_in_tmp` `fuse_mount` |
| `sshd.option` | `name` `value` `value_lc` | `weak_setting` `permit_root_login` `permit_empty_passwords` `permit_user_environment` `password_authentication` `authorized_keys_command` `gateway_ports` `permit_tunnel` |
| `net.iface` | `name` `flags` `promisc` | `promiscuous` |
| `dev.node` | `path` `type` `mode` `uid` | `regular_file_in_dev` `hidden_file` `executable` `world_writable_device` |
| `file.entry` | `preset` (`suid` `volatile` `writable` `localexec`) `type` `mode` `user` `size` `mtime` `path` `magic` | `suid` `sgid` `suid_root` `outside_system_dirs` `suid_gtfobin` `executable` `hidden` `binary_executable_format` `script_file` `setuid_or_setgid` `world_writable_file` `world_writable_dir` `in_binary_dir` |
| `pkg.verify` | `path` `flags` `config` `manager` | `system_binary_modified` `content_changed` `config_file` `missing` `permissions_changed` |
| `vuln.match` | `cve` `package` `installed_version` `fixed_version` `cvss` `kev` `cwes[]` `published` `confidence` (vedi §13), `epss` `epss_percentile` `exposure` `ports[]` `priority` `exposed_likely_exploited` (§16.3) | `kev` `recent` `established` `fix_available` `no_fix_known` `upstream_version_match` `unscored` `kernel` `epss_high` `listening` `listening_local` `running` `reboot_pending` |
| `os.reboot_required` | `required` `packages[]` | `reboot_pending` |
| `peer.deviation` | `group` `kind` (`unique`/`missing`) `facet` `item` `peers` `peers_with_it` | `peer_unique` `peer_missing` `sensitive` |
| `crossview.hidden_pid` / `hidden_module` / `hidden_port` | `pid` `comm` / `name` / `port` e `seen_in` `missing_from` | `hidden_process` `hidden_module` `hidden_port` |
| `bpf.program` / `bpf.pinned` | `tag` `name` / `name` `is_dir` | — |
| `log.template` | `program` `template` `hash` `sample` `count` `alarming` | `alarming_words` |
| `net.beacon` | `dest` `port` `comm` `events` `period_s` `jitter` `uncommon_external` | `beacon` `external_dest` |
| `net.traffic_spike` | `interface` `rate_kbps` `usual_kbps` | `traffic_spike` |

Faccette di baseline (per `drift` / `drift_absent`): `process.exe` `process.binary` `process.lineage`
`process.user` `net.listen` `net.raw` `net.outbound` `net.unix` `net.packet` `user.account` `user.privgroup`
`ssh.key` `sudo.rule` `auth.login` `auth.sudo` `cron.entry` `cron.script` `systemd.unit` `systemd.enabled`
`startup.file` `kernel.module` `kernel.taint` `sysctl.value` `mount.entry` `net.dns` `net.hosts` `sshd.option`
`dev.node` `file.suid` `file.localexec` `bpf.program` `bpf.pinned` `log.template` `net.beacon` `net.country` `auth.country`
`auth.hour`. Le porte oltre la 32767 e i numeri nei nomi dei socket unix sono normalizzati, cosi'
le porte casuali non generano rumore.

Per provare una regola nuova: salvala in `rules_dir` e lancia `dyna_cyber_agent --config agent.yaml --check`.

---

## 8. Valutazione con l'LLM (Qwen3-Coder Q8 su llama-server)

L'LLM **non rileva**: valuta i finding gia' prodotti dalle regole (verdetto, rischio, spiegazione,
azioni consigliate, correlazioni tra finding). Non ha strumenti e non puo' agire su nessuna macchina.
Le **vulnerabilita' (CVE)** non vengono valutate una per una dal modello (lo score e la fonte sono gia' nel dato): al
modello arrivano solo in forma aggregata, per il resoconto unico della mail (§9.2).

Avvio del server (esempio):

```bash
llama-server -m Qwen3-Coder-30B-A3B-Instruct-Q8_0.gguf -c 32768 --jinja -ngl 99 --host 127.0.0.1 --port 8080
```

```bash
dyna_cyber_agent --config agent.yaml --llm-ping        # server pronto? contesto sufficiente?
dyna_cyber_agent --config agent.yaml --llm-prompt      # vedi cosa verrebbe inviato (nessuna rete)
dyna_cyber_agent --config agent.yaml --analyze         # valuta i finding aperti senza valutazione
dyna_cyber_agent --config agent.yaml --event 7         # mostra anche la valutazione AI
```

Sicurezza: i dati della macchina sono trattati come **non fidati** (possono contenere testo che tenta di
manipolare l'LLM). Il prompt lo dichiara, la risposta e' validata (id inventati scartati, enum controllati,
testo ripulito) e, se l'evidenza contiene istruzioni rivolte all'AI, l'agente aggiunge il flag
`prompt_injection_suspected` e alza il rischio a *medium* — il modello non puo' rimuoverlo. Il giudizio AI
affianca la severita' della regola: puo' alzarla, **mai abbassarla** nelle mail.

Se llama-server non risponde, i finding restano salvati senza valutazione e l'agente riprova ogni 10 minuti
(dopo 3 chiamate fallite sospende l'LLM per 5 minuti).

**Istruzioni all'analista** (`llm.focus_file`): un file di testo libero, ad esempio

```
Questa e' una macchina di produzione con nginx + php-fpm. Fai particolare attenzione a shell lanciate dal
web server, a nuove porte in ascolto e a modifiche delle chiavi SSH. Il deploy avviene ogni martedi'
con l'utente "deploy": i suoi processi in /srv/app sono normali.
```

Guida l'enfasi della valutazione ma non puo' scavalcare le regole di sicurezza del prompt.

---

## 9. Mail e report

```bash
dyna_cyber_agent --config agent.yaml --report-preview alert --out /tmp/prev   # /tmp/prev/alert.html + alert.txt
dyna_cyber_agent --config agent.yaml --report-preview digest
dyna_cyber_agent --config agent.yaml --send-test-mail                          # verifica SMTP
dyna_cyber_agent --config agent.yaml --notifications                           # storico invii
```

(Le anteprime non chiamano mai l'LLM, quindi la loro sezione AI e' la nota "non disponibile". La console web puo' generare
le stesse anteprime con la sintesi AI: §15.)

### 9.1 Perche' ricevo una mail

Due tipi di mail, con regole diverse:

* **Avviso** (immediato) — solo per un problema **di sicurezza nuovo** con severita' ≥ `min_severity`, oppure una
  vulnerabilita' **attivamente sfruttata (KEV)** o **appena pubblicata**. Le vulnerabilita' "vecchie" (pubblicate prima di
  `vuln.new_within_days`) **non fanno mai scattare un avviso**: viaggiano solo nel digest. Per le vulnerabilita' la
  gravita' e' quella della regola; l'AI non la alza. Parte dopo `alert_delay`, al massimo una ogni `cooldown` (i *critical*
  no) e `max_per_hour` all'ora. **Tutto** cio' che e' in coda finisce in quella mail e viene segnato come segnalato:
  niente "goccia a goccia" nelle mail successive. Un **incidente** che raggiunge `min_severity` porta con se' tutti i suoi
  membri, anche quelli che da soli sono sotto la soglia; un finding che un aggiornamento spiega (§16.1) aspetta il digest
  a meno che sia critical. Se l'SMTP e' giu' l'invio e' ritentato con backoff (5, 10, 20, 40, 60
  minuti) riusando la stessa analisi AI: nulla va perso e un riavvio non duplica.
* **Digest** (periodico, `digest.every` / `digest.at`) — parte **solo se c'e' qualcosa di nuovo o risolto nel periodo**
  oppure un collector e' fermo ("NON AGGIORNATO" dopo 3 intervalli). Con `send_when_empty: true` parte sempre.
  I problemi nuovi sono in dettaglio; quelli gia' segnalati compaiono in una lista compatta "Ancora aperti".

Se ricevi la **stessa mail due volte** controlla `recipients` (lo stesso indirizzo scritto due volte o con maiuscole
diverse viene ora ignorato con un avviso nel log) e che non giri una seconda istanza: l'agente prende un lock
`<state_dir>/agent.lock` e rifiuta di partire se un'altra istanza usa lo stesso `state_dir`.

### 9.2 Com'e' fatta una mail

1. **Intestazione** — rischio massimo, periodo, conteggi per gravita'.
2. **Analisi AI** — *un solo* resoconto per mail: titolo, sintesi, priorita' (azioni in ordine), eventuali correlazioni.
   Il modello riceve anche i riassunti delle ultime mail inviate con l'istruzione di **non ripeterli**: dice solo cio' che
   e' nuovo o cambiato. Le vulnerabilita' vi compaiono al massimo in due frasi. Se il modello non e' raggiungibile la
   mail parte comunque, con una nota al posto della sintesi.
3. **Incidenti** — quando i finding si concatenano (§16.2): titolo con le fasi, periodo, indirizzi e account in comune e una
   **cronologia**; i tre membri piu' gravi mantengono una scheda completa, gli altri vivono solo nella cronologia.
4. **Finding di sicurezza** — le schede dettagliate (evidenze, valutazione AI del singolo finding, azioni consigliate). Un
   finding che un aggiornamento spiega porta una nota verde "probabilmente spiegato da un aggiornamento" (§16.1).
5. **Ancora aperti** (digest) — promemoria compatto di cio' che era gia' stato segnalato.
6. **Vulnerabilita' e riferimenti** (in fondo) — quadro complessivo (quante, per gravita' CVSS, KEV, con correzione),
   elenco compatto per macchina e pacchetto (CVE, CVSS, KEV/NUOVA, CWE, versione corretta) e i riferimenti aggregati:
   **MITRE ATT&CK** (con nome della tecnica), **CWE** (con nome) e le notizie dei feed (nuove voci KEV, ecc.). Le
   vulnerabilita' sono ordinate per **priorita'** (§16.3): prima le sfruttate, poi quelle probabilmente sfruttate e
   raggiungibili dalla rete, con EPSS e raggiungibilita' accanto a ogni CVE.
7. **Stato dei collector** e nota finale.

Limiti per mail: `max_items` finding di sicurezza (default 30) e 60 vulnerabilita' (le sfruttate e le piu' gravi
per prime); il resto e' contato ("altre N") e consultabile con `--events`.

Ogni mail e' `multipart/alternative`: HTML moderno (tema chiaro/scuro) e testo semplice con tutte le evidenze.
Il contenuto proveniente dalla macchina e' sempre neutralizzato: HTML escaped, nessun link cliccabile
(`http://` diventa `hxxp://`), niente caratteri di controllo o di inversione del testo.

---

## 10. Esecuzione in produzione

### 10.1 Installazione

Con il pacchetto (consigliato): `sudo apt install ./dyna-cyber-agent_<versione>_amd64.deb` (vedi §1). Crea:

```
/usr/bin/dyna_cyber_agent                  il binario
/etc/dyna_cyber_agent/agent.yaml           configurazione (da modificare)   root:dyna_cyber_agent 0640
/etc/dyna_cyber_agent/rules/               copia delle regole (modificabile; non viene sovrascritta)
/etc/dyna_cyber_agent/keys/                chiavi SSH dell'agente           dyna_cyber_agent 0700, file 0600
/var/lib/dyna_cyber_agent/                 database (agent.db, vuln.db, geo.db)   dyna_cyber_agent 0750
/var/log/dyna_cyber_agent/                 log (se imposti log_file)        + rotazione in /etc/logrotate.d
/lib/systemd/system/dyna_cyber_agent.service    unita' systemd rinforzata
/usr/share/dyna_cyber_agent/               USAGE.md, esempi, regole originali, sudoers/authorized_keys d'esempio
```

Poi: modifica `agent.yaml` (target, mail, LLM), controlla con `dyna_cyber_agent --config /etc/dyna_cyber_agent/agent.yaml --check`
e avvia:

```bash
sudo systemctl enable --now dyna_cyber_agent
journalctl -u dyna_cyber_agent -f              # righe "FINDING #..." per i nuovi rilevamenti
```

Installazione manuale: copia il binario, le regole e `deploy/dyna_cyber_agent.service`, crea l'utente
(`useradd --system --home /var/lib/dyna_cyber_agent --shell /usr/sbin/nologin dyna_cyber_agent`) e le cartelle sopra. `make install` installa sotto `PREFIX` (default `/usr/local`).

### 10.2 L'unita' systemd e perche' e' fatta cosi'

L'unita' fornita (`deploy/dyna_cyber_agent.service`) toglie all'agente tutto cio' che non serve (`NoNewPrivileges`,
`ProtectSystem=strict`, filtro delle chiamate di sistema, famiglie di indirizzi limitate, `MemoryDenyWriteExecute`...)
e scrive solo in `/var/lib/dyna_cyber_agent` e `/var/log/dyna_cyber_agent`. Tre scelte da conoscere:

* **Niente `PrivateTmp` e niente `PrivateDevices`**: l'agente deve vedere il `/tmp` e il `/dev` **veri** della
  macchina che controlla. Con `PrivateTmp=yes` vedrebbe un `/tmp` vuoto tutto suo e non troverebbe mai nulla.
* **`ProtectHome=read-only`**: legge le home (file di avvio degli utenti) ma non le modifica.
* **Capability `CAP_SYS_PTRACE` e `CAP_DAC_READ_SEARCH`**: servono per leggere `exe`, `fd` e `maps` di *tutti* i
  processi e i file riservati (`shadow`, `sudoers`) del target **locale**. Se monitori solo bersagli SSH con
  gate + sudo, togli le due righe `AmbientCapabilities` e `CapabilityBoundingSet`: l'agente gira senza privilegi.

### 10.3 Gestione

* **Ricaricare le regole senza riavviare**: modifica i file e `sudo systemctl reload dyna_cyber_agent` (invia SIGHUP).
  Se una regola e' sbagliata l'agente **mantiene le regole attuali** e lo scrive nel log
  (`rules NOT reloaded, keeping the current ones: ...`): un refuso non lo rende cieco.
* **Permessi**: l'agente lavora con `umask 027` e avvisa se `state_dir` e' leggibile o scrivibile da tutti.
  I file creati (database, anteprime) sono `0640`. Il token web e' `0600`.
* **Backup**: copia `state_dir/agent.db` (baseline, finding, storico, sorgenti degli attacchi). `vuln.db` e `geo.db` sono ricostruibili dai feed.
* **Ripartire da zero per un target**: ferma l'agente, cancella il database (o il solo target) e riavvia: riparte
  l'apprendimento.
* **Aggiornare l'agente con gate installato**: il gate ha un numero di protocollo; se cambia, `--ssh-test` lo
  segnala e basta rieseguire `--print-gate` sul bersaglio.
* **Log**: con `log_file` la rotazione e' in `/etc/logrotate.d/dyna_cyber_agent` (`copytruncate`, senza riavvio); senza
  `log_file` i log vanno a journald.

---

## 11. Esempi d'uso

**Un server, in locale, senza mail.** Config minima del §2 e `dyna_cyber_agent --config agent.yaml`.

**Tre server via SSH con digest quotidiano alle 08:00.**

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

**Indagare un allarme.** Arriva la mail "ALTO: 1 finding - web01" →

```bash
dyna_cyber_agent --config agent.yaml --events
dyna_cyber_agent --config agent.yaml --event 12          # evidenze complete + valutazione AI + azioni consigliate
# se e' legittimo:
dyna_cyber_agent --config agent.yaml --accept 12
```

**Controllare l'impaginazione delle mail senza inviarle.**

```bash
dyna_cyber_agent --config agent.yaml --report-preview alert --out /tmp/prev && xdg-open /tmp/prev/alert.html
```

---

## 12. Cosa l'agente (ancora) non fa

* Non legge i log applicativi diversi da auth, web (nginx/apache) e kernel: database, mail server, ecc. non sono
  analizzati (si possono aggiungere con `log_paths`, ma verrebbero trattati come syslog generico).
* L'analisi dei log web e' per firme (SQLi, traversal, RCE, Log4Shell, webshell, scanner): non e' un WAF e non
  vede attacchi cifrati o nel corpo delle richieste POST.
* `sshd_config`: legge le opzioni globali (prima di `Match`); non calcola la configurazione effettiva con tutte le
  condizioni `Match`.
* Rootkit: confronta viste indipendenti del kernel (§16.5), il che prende i modi comuni di nascondere un processo, un
  modulo o una porta, ma un rootkit che falsifica *ogni* interfaccia in modo coerente non si vede. Segnala inoltre moduli
  kernel nuovi, programmi eBPF, `ld.so.preload`, interfacce promiscue e binari diversi dal pacchetto.
* **Vulnerabilita'**: vede solo il software installato dal gestore di pacchetti (dpkg/rpm). Binari compilati a mano,
  container, pacchetti pip/npm/gem non sono nell'inventario. Per le distribuzioni non coperte da OSV il confronto
  e' per versione upstream e puo' sbagliare in entrambe le direzioni (§13.7). EPSS e raggiungibilita' (§16.3) le ordinano,
  ma la raggiungibilita' e' nota solo per i programmi di proprieta' di un pacchetto (non per le librerie).
* I processi di breve durata possono generare qualche finding di basso valore subito dopo il lock della
  baseline: accettali con `--accept`.
* `dpkg -V` / `rpm -Va` sono lenti e un utente non privilegiato non puo' leggere tutti i file: il collector
  `integrity` funziona davvero solo con root (o gate + sudo).
* Il bersaglio deve avere strumenti GNU; BusyBox/Alpine non e' supportato.
* Senza privilegi sul bersaglio i processi di altri utenti e molti log restano invisibili (vedi §6.3).
* L'analisi AI e' un supporto: verifica sempre le evidenze prima di agire.

---

## 13. Vulnerabilita' note (CVE) e debolezze (CWE)

### 13.1 Cosa fa

L'agente risponde a una domanda semplice: **"il software installato sui miei sistemi e' soggetto a vulnerabilita'
note, comprese quelle pubblicate ieri?"**

```
 bersaglio ──(collector packages)──► inventario (pacchetti + sorgente, distribuzione, kernel)
                                              │
   feed pubblici scaricati sulla macchina     ▼
   dell'agente, mai sui bersagli:      ┌──────────────────┐        ┌─────────────────────────┐
   • CISA KEV   (sfruttate in the wild)│ matching (vulns) │──────► │ finding + regole VULN-* │──► mail / digest
   • NVD        (CVE, CVSS, CWE, CPE)  │  OSV + NVD/CPE   │        │ (si chiudono da soli    │
   • MITRE CWE  (nomi delle debolezze) └──────────────────┘        │  quando aggiorni)       │
   • OSV.dev    (avvisi delle distro)                              └─────────────────────────┘
```

* **Ogni 6 ore** (`vuln.refresh_every`) un thread in background aggiorna i feed. Il download NVD e' *incrementale*
  (solo i CVE modificati dall'ultima volta) e **riprendibile**: se si interrompe o l'NVD limita le richieste,
  riparte dalla stessa pagina.
* **Ogni ora** (`vuln.match_every`) il collector `vulns` confronta l'ultimo inventario di ogni target con il database.
* Un CVE **nuovo** che colpisce un pacchetto installato diventa un finding la prima volta che compare (e una mail se
  supera `alerting.min_severity`); quando aggiorni il pacchetto il finding si **risolve da solo**.
* Il **digest** ha una sezione "Intelligence sulle vulnerabilita'": stato dei feed, nuove voci CISA KEV del periodo,
  quante sfruttate attivamente sono presenti sui tuoi sistemi, nuove vulnerabilita' trovate e le classi di debolezza
  (CWE) piu' frequenti.

### 13.2 Quanto e' affidabile il confronto

Il problema classico: le distribuzioni correggono le vulnerabilita' *senza cambiare la versione upstream*
(`openssl 3.0.2-0ubuntu1.12` contiene correzioni uscite in openssl 3.0.10). Confrontare solo i numeri di versione
con l'NVD segnala falsi positivi su quasi ogni Ubuntu/Debian. Per questo ci sono due strade, con una fiducia dichiarata
(`confidence` nell'evidenza):

| | **OSV** (fiducia `high`) | **NVD/CPE** (fiducia `low`, tag `upstream_version_match`) |
|---|---|---|
| Dati | avvisi di sicurezza della distribuzione (Debian, Ubuntu, Rocky, AlmaLinux) | intervalli di versione *upstream* dei record NVD |
| Backport delle distro | **tenuti in conto** (versione corretta, es. `3.0.2-0ubuntu1.14`) | ignorati: possibili falsi positivi |
| Quando si usa | automaticamente se la distribuzione e' coperta | se OSV non copre la distribuzione o non risponde (`cpe_match: auto`), o sempre (`always`) |

Le regole (`rules/default/vulns.yaml`) fanno scattare **una sola regola per match**:

| Regola | Condizione | Severita' |
|---|---|---|
| VULN-001 | CVE nel catalogo **CISA KEV** (sfruttato attivamente), fiducia alta | **critica** |
| VULN-002 | CVE pubblicato di recente (`new_within_days`), CVSS ≥ 9, fiducia alta | alta |
| VULN-003 | recente, 7 ≤ CVSS < 9 | media |
| VULN-004 | non recente, CVSS ≥ 9, non corretto | media |
| VULN-005 | non recente, 7 ≤ CVSS < 9 | bassa |
| VULN-006 | recente ma senza punteggio (non ancora analizzato dall'NVD) | bassa |
| VULN-010 | KEV ma fiducia bassa (solo versione upstream): *"possibilmente colpito, verifica"* | media |
| VULN-011 | fiducia bassa, CVSS ≥ 7 | bassa |

I match con punteggio sotto `min_cvss` (default 7) sono **contati ma non elencati** (per non produrre migliaia di
finding): li vedi nei totali di `--vuln-check` e `--vuln-status`. I CVE KEV sono sempre elencati.
Il punteggio viene dall'NVD; se manca, dal vettore CVSS dell'avviso OSV (calcolato dall'agente), e solo come ultima
risorsa dalla priorita' della distribuzione (stimata: l'evidenza riporta `score_source`).

La gravita' di una vulnerabilita' e' **sempre quella della regola**: l'AI non valuta i CVE uno per uno e non puo' promuovere
un CVE vecchio a un avviso.

### 13.3 E i CWE?

Un **CWE e' una classe di debolezza** ("Out-of-bounds Write", "SQL Injection"), non qualcosa a cui un sistema
sia "soggetto" in se': lo e' tramite i CVE che la istanziano, o tramite una cattiva configurazione. L'agente li usa cosi':

* **CVE → CWE**: ogni finding di vulnerabilita' riporta i CWE del CVE con il nome (es. `CWE-787 Out-of-bounds Write`).
* **Configurazione → CWE**: 36 regole di configurazione e attacco sono annotate con il loro CWE (`cwe:` nel file
  della regola): ad esempio permessi troppo larghi → CWE-732, password vuota → CWE-258, SQL injection → CWE-89.
* **Tendenze**: il digest elenca le classi di debolezza piu' frequenti tra le nuove vulnerabilita' trovate sui tuoi sistemi.
* **Nomi**: c'e' una tabella integrata di ~90 CWE comuni (i report sono leggibili anche offline); il catalogo MITRE
  scaricato ha la precedenza e copre tutte le debolezze citate dai CVE.

Per aggiungere un CWE a una regola tua: `cwe: [CWE-732]` accanto a `mitre:` (formato controllato all'avvio).

### 13.4 Configurazione (`vuln:`)

```yaml
vuln:
  enabled: true
  refresh_every: 6h          # aggiornamento dei feed (minimo 30m: i servizi pubblici vanno trattati con riguardo)
  match_every: 1h            # ogni quanto i target sono riconfrontati
  kev: true                  # CISA Known Exploited Vulnerabilities
  nvd: true                  # record CVE (punteggi, CWE, intervalli CPE)
  cwe: true                  # nomi e descrizioni delle debolezze
  osv: true                  # avvisi delle distribuzioni (accurato): invia nome+versione dei pacchetti a osv.dev (§13.6)
  cpe_match: auto            # auto | always | never
  nvd_initial_days: 120      # primo caricamento: CVE modificati negli ultimi N giorni
  nvd_api_key_file: ""       # opzionale: chiave API NVD (10 volte piu' richieste al secondo), file chmod 600
  min_cvss: 7.0              # sotto questo punteggio i match sono solo contati (una CVE con EPSS >= 10% e' elencata comunque)
  new_within_days: 14        # "recente" = pubblicato (o entrato nel KEV) negli ultimi N giorni
  epss: true                 # EPSS, probabilita' di sfruttamento (file giornaliero, ~3 MB; §16.3)
  exposure: true             # ordina per raggiungibilita': il pacchetto vulnerabile ascolta sulla rete / e' in esecuzione? (§16.3)
  # db_path: /var/lib/dyna_cyber_agent/vuln.db
  # kev_url / nvd_url / cwe_url / osv_url / epss_url ({date} = AAAA-MM-GG): per usare un mirror interno (http:// ammesso per mirror locali)
  # timeout: 120
```

**Tempi del primo caricamento NVD.** Il NVD modifica circa **900 CVE al giorno**; con `nvd_initial_days: 120` sono
~100.000 record in ~100 richieste da 1000. Senza chiave API l'agente rispetta il limite pubblico (una richiesta ogni
6,5 s): **~11 minuti**; con chiave ~1-2 minuti. La chiave e' gratuita: chiedila su
https://nvd.nist.gov/developers/request-an-api-key (ti arriva una mail di conferma con la chiave). Salvala in un file
leggibile solo da te (`chmod 600`) e indicalo in `nvd_api_key_file`. Puoi lanciare il caricamento a mano con
`dyna_cyber_agent --config ... --vuln-sync nvd` (Ctrl+C e' sicuro) prima di avviare il servizio; un timeout come
"Timeout was reached after 1000 CVEs; will resume" non perde nulla: quanto scaricato e' salvato e la volta dopo si
riparte da li'.
Lo spazio su disco di `vuln.db` dipende da `nvd_initial_days`: controllalo nel collaudo (§14).

Senza il caricamento NVD il matching via OSV funziona comunque (OSV porta il proprio punteggio); l'NVD aggiunge
punteggi ufficiali, CWE e il ripiego CPE. Il collector avvisa se il database e' vuoto.

### 13.5 Comandi

```bash
dyna_cyber_agent --config agent.yaml --vuln-sync all          # kev + nvd + cwe adesso (anche solo: kev | nvd | cwe)
dyna_cyber_agent --config agent.yaml --vuln-status            # cosa c'e' nel database, ultimi aggiornamenti, stato per target
dyna_cyber_agent --config agent.yaml --vuln-search CVE-2021-44228
dyna_cyber_agent --config agent.yaml --vuln-search "log4j"    # ricerca nel testo
dyna_cyber_agent --config agent.yaml --vuln-check web01       # confronta ora l'inventario di web01 (stampa i match)
```

Esempio di output (valori di un test con dati finti):

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

Il collector `vulns` e' incluso in `collectors: all`; per un target che elenca i collector a mano servono
`packages` **e** `vulns`.

### 13.6 Rete e privacy

L'agente contatta questi servizi **dalla macchina dove gira** (mai dai bersagli):

| Servizio | URL | Cosa invia |
|---|---|---|
| CISA KEV | `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | nulla (download) |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | solo intervalli di date o un CVE-id; l'eventuale chiave API nell'header `apiKey` |
| MITRE CWE | `cwe-api.mitre.org/api/v1/cwe/weakness/<id>` | solo numeri CWE |
| EPSS di FIRST.org | `epss.empiricalsecurity.com/epss_scores-<data>.csv.gz` | nulla (un download al giorno) |
| **OSV** | `api.osv.dev/v1/querybatch` e `/v1/vulns/<id>` | **nome e versione dei pacchetti sorgente installati** e l'ecosistema (es. `Ubuntu:22.04:LTS`). Nessun hostname, indirizzo o altro dato del sistema |

Se l'elenco dei pacchetti non deve uscire dalla tua rete: `vuln.osv: false` (il confronto passa ai dati NVD/CPE,
meno accurato, e usa solo feed in sola scarica) oppure punta `osv_url` a un mirror interno. Per spegnere tutto:
`vuln.enabled: false`.

### 13.7 Limiti e cose da sapere

* **Distribuzioni coperte da OSV**: Debian, Ubuntu (ecosistema `Ubuntu:AA.MM[:LTS]`), Rocky Linux, AlmaLinux.
  Per Rocky/Alma il nome del pacchetto negli avvisi OSV non e' stato verificato in questa versione: verificalo nel
  collaudo. RHEL, CentOS, Fedora, SUSE, Arch, Alpine non sono coperti: si usa il confronto CPE (fiducia bassa).
* Vede il **software dei gestori di pacchetti**. Non vede binari compilati a mano, immagini/container, librerie
  pip/npm/gem, firmware.
* Le correzioni "ESM"/Ubuntu Pro non sono considerate (ecosistema `Ubuntu:Pro:...`).
* L'NVD analizza i CVE con ritardo: un CVE appena pubblicato puo' non avere ancora punteggio (regola VULN-006).
* Un'assenza di match **non e' una garanzia**: e' "nessuna vulnerabilita' *nota ai feed* per questi pacchetti".
* EPSS e' una stima statistica, non una certezza: un punteggio basso non e' "sicuro". La raggiungibilita' (§16.3) e' nota
  solo per i programmi dei pacchetti di cui sono stati raccolti gli elenchi file (il primo inventario richiede qualche passata).

---

## 14. Collaudo: cosa provare e cosa riportarmi

Questa sezione e' la procedura per provare l'agente sul campo e farmi avere risultati utili per correggere cio' che non
va. Regole del gioco:

* **Usa una macchina di prova** per le simulazioni (§14.4): alcune creano file, utenti o righe di log (tutte
  *reversibili*, con il comando di pulizia). L'agente, per conto suo, non scrive mai sul bersaglio.
* Dopo ogni passo annota **esito** (OK / KO / dubbio) e, se KO o dubbio, il testo esatto dell'errore o del finding.
* I tempi contano (collector lenti, primo caricamento NVD): segnali quelli che ti sembrano troppo lunghi.

### 14.1 Lo script che raccoglie tutto

`scripts/collaudo.sh` esegue in ordine controlli e raccolta e produce un archivio da mandarmi:

```bash
# conservativo: nulla esce dalla macchina oltre a quanto fa un normale --once
# (attenzione: con la configurazione predefinita `--once` interroga anche OSV con nomi e versioni dei pacchetti;
#  per evitarlo imposta `vuln: { osv: false }` nella config prima di lanciare lo script)
scripts/collaudo.sh --config /etc/dyna_cyber_agent/agent.yaml --out ~/collaudo-1

# completo (contatta i servizi: leggi cosa fa ogni opzione con --help)
scripts/collaudo.sh --config /etc/dyna_cyber_agent/agent.yaml --out ~/collaudo-2 \\
    --with-llm --with-vuln-sync --with-vuln-check --redact
```

Opzioni: `--with-llm` (ping + analisi), `--with-vuln-sync` (scarica i feed), `--with-vuln-check` (interroga OSV con
i **nomi e le versioni dei pacchetti**), `--with-mail-test` (invia **una** mail), `--redact` (maschera indirizzi IPv4
e e-mail), `--skip-once` (solo controlli di configurazione e connessione). Produce una cartella e un `.tar.gz`
con un `SUMMARY.txt` (un esito per passo) e l'output di ogni comando. **Rileggi l'archivio prima di mandarlo**: ci
sono nomi di host, righe di comando dei processi e indirizzi (`--redact` non basta per tutto).

### 14.2 Percorso consigliato

| # | Passo | Dove | Cosa fare | Esito atteso |
|---|---|---|---|---|
| A | Compilazione e test | build | `make && make test` | nessun warning; "100% tests passed" (circa 210 casi, ~25 s) |
| B | Monitor locale | macchina di prova | config minima del §2, poi `--check`, `--once` | 3 collector in pochi ms; qualche finding "assoluto" (vedi B sotto) |
| C | SSH | 1 bersaglio | §6: prima `stream`, poi `installed` + `sudo`; `--ssh-test <target>` | connessione, strumenti `ok`, `uid=0` con sudo; scansione `/proc` < 1 s su LAN |
| D | Log | macchina di prova | simulazioni log (§14.4) | finding LOG-* entro ~30 s dall'evento |
| E | Persistenza/sistema/file | macchina di prova | simulazioni §14.4 dopo il `--baseline-lock` | un finding per ogni simulazione; `resolved` dopo la pulizia |
| F | LLM | server llama | `--llm-ping`, `--llm-prompt`, `--analyze` | valutazioni in italiano, JSON valido, nessun id inventato |
| G | Mail | SMTP vero | `--report-preview`, `--send-test-mail` | mail leggibile in HTML e testo |
| H | Vulnerabilita' | macchina Ubuntu/Debian | §14.5 | feed scaricati, match plausibili |
| I | Servizio | VM | installa il `.deb`, avvia con systemd (§10), `systemd-analyze security dyna_cyber_agent` | nessun "Permission denied" nel journal; collector regolari |
| J | Robustezza | VM | lascia girare 24 h; prova a spegnere SMTP, llama-server, un bersaglio SSH; `kill -9` e riavvio | nessun crash; log chiari; nessuna mail duplicata |
| K | Console e mappa | qualsiasi | §15: apri la console web; `--geo-update`; fai qualche login simulato | tutte le schede si caricano; la mappa posiziona gli indirizzi pubblici |
| L | Analisi avanzate | macchina/e di prova | §16.11: una simulazione per analisi, dopo `--baseline-lock`; `--incidents`, `--intel-update` | ogni finding compare come descritto; `crossview` tace su una macchina pulita |

**B - cosa guardare.** Con `collectors: [processes, network, users, logs, persistence, system, packages]` (senza `files`
e `integrity`, lenti, al primo giro). Il primo `--once` e' in *apprendimento*: scattano solo regole assolute (es.
`SYS-004` impostazioni deboli, `PERS-018`). Poi `--baseline-lock`, un secondo `--once`, e annota **ogni** finding che ti
sembra un falso positivo con `rule id` e `subject` (la colonna dopo il nome della macchina in `--events`).
Aggiungi `files` e `integrity` in un secondo momento e **cronometra** il primo `--once` (la ricerca SUID puo' durare
10+ minuti).

### 14.3 Cosa mandarmi

1. L'archivio di `collaudo.sh` (indica con quali opzioni lo hai lanciato).
2. Per ogni passo della tabella: esito e note (modello sotto).
3. L'elenco dei **falsi positivi** (regola + oggetto) e dei **falsi negativi** (simulazione che non ha prodotto il
   finding atteso: indica il passo, il comando e quanto hai aspettato).
4. Tempi: primo `--once` con tutti i collector, primo `--vuln-sync nvd`, durata di `--ssh-test`.
5. Numeri: dimensione di `agent.db` e `vuln.db` (`ls -la`), memoria dell'agente dopo 24 h (`ps -o rss,etime -p <pid>`).
6. Qualunque cosa ti abbia sorpreso, anche se non e' un errore.

Modello (copia e compila):

```
Macchina agente : <distribuzione, versione, cpu/ram>
Bersagli        : <n, distribuzione, locale/ssh (stream|installed+sudo)>
Versione        : <dyna_cyber_agent --version>

A compilazione/test : OK | KO  - note:
B monitor locale    : OK | KO  - falsi positivi: ...
C ssh               : OK | KO  - tempi scan test: ... - note:
D log               : OK | KO  - simulazioni riuscite: ... mancate: ...
E persist./sistema  : OK | KO  - ...
F llm               : OK | KO  - tempo per chiamata: ... qualita' valutazioni: ...
G mail              : OK | KO  - client usato: ... resa HTML: ...
H vulnerabilita'    : OK | KO  - durata sync nvd: ... vuln.db: ... match: ...
I servizio          : OK | KO  - systemd-analyze security: ...
J robustezza        : OK | KO  - rss dopo 24h: ... db: ... incidenti: ...
K console / mappa   : OK | KO  - ...
Altro: ...
```

### 14.4 Simulazioni sicure (solo su una macchina di prova)

Esegui **dopo** aver imparato e bloccato la baseline (`--baseline-lock`), poi `dyna_cyber_agent --config ... --once` e
`--events`. Ogni riga indica cosa deve apparire e come ripulire. Le simulazioni dei log scrivono nel log *della
macchina di prova* con `logger` (azione tua, non dell'agente); funzionano dove `auth.log`/`secure` o journald
ricevono `authpriv`.

| Simulazione | Comando | Finding atteso | Pulizia |
|---|---|---|---|
| Brute force riuscito (log) | `for i in $(seq 1 10); do logger -p authpriv.notice -t sshd "Failed password for root from 203.0.113.50 port 4000$i ssh2"; done; logger -p authpriv.notice -t sshd "Accepted password for root from 203.0.113.50 port 50000 ssh2"` | LOG-001, **LOG-002 (critico)**, LOG-004, LOG-005 | nulla (le righe restano nel log): `--accept <id>` |
| Nuovo utente (log + stato) | `logger -p authpriv.notice -t useradd "new user: name=testx, UID=1999, GID=1999, home=/home/testx, shell=/bin/bash"` e `sudo useradd -M -s /bin/bash agenttest` | LOG-012, USR-003 | `sudo userdel agenttest` |
| Attacco web (se c'e' nginx) | `curl -s "http://localhost/index.php?id=1%27%20UNION%20SELECT%201,2,3--" -A sqlmap/1.5 -o /dev/null` | LOG-020 (o 021), LOG-029 | nulla |
| Eseguibile nascosto in /tmp | `touch /tmp/.agenttest && chmod +x /tmp/.agenttest` | FILE-005 | `rm /tmp/.agenttest` |
| File SUID in /tmp | `sudo cp /bin/true /tmp/agenttest-suid && sudo chmod u+s /tmp/agenttest-suid` | FILE-007 (critico) | `sudo rm /tmp/agenttest-suid` |
| Cron sospetto | `echo '@reboot root /tmp/.agenttest/run' \\| sudo tee /etc/cron.d/agenttest` | PERS-002, PERS-003, PERS-004 | `sudo rm /etc/cron.d/agenttest` |
| Alias ruba-password | `echo "alias sudo='/tmp/fakesudo'" >> ~/.bashrc` | PERS-014, PERS-015, PERS-018 | togli la riga |
| ASLR indebolito | `sudo sysctl -w kernel.randomize_va_space=1` | SYS-004, SYS-005 | `sudo sysctl -w kernel.randomize_va_space=2` |
| Chiave SSH nuova | aggiungi una chiave qualunque a `~/.ssh/authorized_keys` | USR-004 | togli la riga |
| Porta nuova in ascolto | `python3 -m http.server 8099 --bind 0.0.0.0 &` | NET-001 (poi `kill %1`) | `kill %1` |

Dopo la pulizia lancia un altro `--once`: i finding sui dati *di stato* devono passare a **resolved**
(`--events --all`); quelli dei log restano. Se una simulazione non produce il finding atteso, riportami comando,
attesa e l'output di `--once` di quel collector.

Cosa serve a ogni regola dei log, per evitare sorprese: `LOG-001` (brute force) scatta con **8 o piu'** tentativi falliti
dallo stesso indirizzo in 10 minuti e solo per indirizzi **non privati**; `LOG-002` (successo dopo i fallimenti) richiede
almeno **3** fallimenti prima del login riuscito, dallo stesso indirizzo, e scatta anche per indirizzi privati. `LOG-001`
e' *medium*: con `min_severity: high` compare nel digest, non come mail immediata; `LOG-002` e' *critical* e produce
l'avviso. Gli indirizzi 203.0.113.0/24 usati sopra sono indirizzi di documentazione: nella mappa finiscono nell'elenco
"senza posizione".

Quanto deve imparare la baseline prima delle simulazioni? Su una macchina di prova bastano un paio d'ore: lascia girare i
collector per qualche ciclo, controlla che `--baseline-status` mostri un numero di identita' stabile, poi
`--baseline-lock`. Le regole di novita' (porta, utente, cron, chiave nuovi) funzionano solo dopo; quelle sui log, sui file
e sulle impostazioni di sistema funzionano anche durante l'apprendimento. In produzione tieni l'intera finestra (§4.1).
**Non** fare le simulazioni prima del lock, altrimenti la porta o l'utente di prova verrebbero imparati come normali.

### 14.5 Collaudo delle vulnerabilita'

Su una macchina **Debian o Ubuntu** (cosi' si prova OSV):

```bash
# 1) feed veloci e CWE; poi l'NVD (cronometra e annota la dimensione di vuln.db)
time dyna_cyber_agent --config agent.yaml --vuln-sync kev
time dyna_cyber_agent --config agent.yaml --vuln-sync nvd          # lungo la prima volta; Ctrl+C e' sicuro, riprende
time dyna_cyber_agent --config agent.yaml --vuln-sync cwe
dyna_cyber_agent --config agent.yaml --vuln-status ; ls -la /var/lib/dyna_cyber_agent/vuln.db

# 2) la ricerca deve mostrare KEV e CWE per un CVE celebre
dyna_cyber_agent --config agent.yaml --vuln-search CVE-2021-44228  # atteso: ACTIVELY EXPLOITED + CWE-20/400/502/917 con i nomi

# 3) il confronto reale (richiede 'packages' gia' raccolto: --once con quel collector)
dyna_cyber_agent --config agent.yaml --once
dyna_cyber_agent --config agent.yaml --vuln-check
```

Controlli da fare a mano (e riportarmi l'esito):

1. **Verifica a campione**: prendi 3 match elencati da `--vuln-check` e controllali sul tracker della distribuzione
   (Ubuntu: `ubuntu.com/security/CVE-xxxx-xxxx`; Debian: `security-tracker.debian.org/tracker/CVE-xxxx-xxxx`). La
   versione corretta indicata dall'agente coincide? Il pacchetto e' davvero ancora vulnerabile?
2. **Falsi positivi sul patched**: su un sistema completamente aggiornato i match `high` devono essere pochi o zero.
   Su una VM vecchia e non aggiornata devono essere molti.
3. **Ciclo di vita**: aggiorna un pacchetto con match (`apt install --only-upgrade <pkg>`), attendi il prossimo
   `packages` + `vulns` (o `--once`): il finding deve passare a *resolved*.
4. **Senza OSV**: con `osv: false` e `cpe_match: auto` rilancia `--vuln-check` e confronta i numeri: ti aspetti piu'
   match, con tag `upstream_version_match` e l'avviso "no OSV coverage / using upstream-version matching".
5. **Servizio**: dopo ~20 s dall'avvio compare "vulnerability feeds: synchronisation started" e poi una riga per
   ogni feed; la mail digest contiene la sezione "Intelligence sulle vulnerabilita'".
6. Nel log non devono esserci errori di parsing dei feed (`not an NVD CVE 2.0 response`, `OSV answer not understood`):
   se ci sono, **riportami la riga e l'ora**, cosi' controllo il formato reale.

> Nota sul collaudo dei feed: i parser sono stati scritti e provati su risposte reali ricostruite dalla
> documentazione e da richieste di sola lettura, e con un server finto locale; **non sono ancora stati provati
> per ore contro i servizi veri**. Il tuo collaudo e' la prima prova completa.

---

## 15. Console web (interfaccia grafica)

Una pagina moderna e responsive (chiaro/scuro, adatta anche al telefono) per vedere tutto e lanciare analisi mirate.
E' **spenta di default**. La pagina e' incorporata nel binario: niente da installare, nessuna libreria esterna, nessun dato
che esce dalla macchina.

```yaml
web:
  enabled: true
  listen: 127.0.0.1     # solo locale (consigliato)
  port: 8484
  # token_file: /etc/dyna_cyber_agent/web.token   # default: <state_dir>/web.token
```

Riavvia l'agente: il log indica l'indirizzo e il file del token (creato la prima volta, modo 0600, leggilo con `cat`).
Apri `http://127.0.0.1:8484/` e incolla il token. Senza demone attivo (solo consultazione dei dati gia' raccolti):
`dyna_cyber_agent --config agent.yaml --web`.

**Da un'altra macchina**: non aprire la porta in rete (HTTP in chiaro). Usa un tunnel SSH:
`ssh -L 8484:127.0.0.1:8484 utente@macchina-agente` e poi apri `http://127.0.0.1:8484/`.

Cosa trovi:

* **Panoramica** — contatori, finding per gravita', vulnerabilita' per CVSS, cosa guardare per primo, stato della
  baseline (con avanzamento dell'apprendimento) per target, stato del modello.
* **Incidenti** — catene di finding collegati con le loro fasi, indirizzi/account in comune e una cronologia; "analizza
  l'incidente con l'AI" manda al modello tutti i suoi finding come un'unica storia (§16.2).
* **Finding** — filtri (testo, gravita', stato, target, collector), scheda completa con evidenze, MITRE con i nomi,
  valutazione AI, come rimediare. Da qui lanci l'**analisi mirata con l'AI** su un finding o su quelli selezionati, con una
  domanda tua ("e' compatibile con un backup?").
* **Vulnerabilita'** — CVE raggruppate per macchina e pacchetto, ordinate per **priorita'**, con CVSS, EPSS,
  raggiungibilita' (in ascolto / locale / in esecuzione), sfruttata/nuova, CWE e versione corretta; filtro "solo in ascolto
  in rete" (§16.3).
* **Mappa** — mappa scura (offline) di tutti gli indirizzi che hanno tentato un accesso alle macchine controllate:
  vedi §15.1.
* **Analisi AI** — scegli target, collector e gravita' minima, fai una domanda libera; le valutazioni vengono salvate.
* **Report** — anteprima (HTML + TXT, scaricabili) di digest o avviso, con o senza la sintesi AI. **Non invia nulla.**
* **Mail** e **Stato** — storico degli invii e salute dei collector.

Sicurezza: ogni richiesta alle API richiede il token (`Authorization: Bearer`); la pagina e' servita con CSP rigida e i
dati provenienti dalle macchine analizzate sono sempre inseriti come testo, mai come HTML. La console e' in sola lettura
sulle macchine analizzate; le uniche scritture sono nel database dell'agente (le valutazioni AI richieste da te).
Le analisi usano llama-server come il resto dell'agente (`llm.enabled: true`); una alla volta, in coda. La console non
offre "accetta in baseline" ne' "invia questo report": restano da riga di comando, essendo decisioni di sicurezza.

### 15.1 Mappa dei tentativi di accesso

L'agente registra **ogni indirizzo** che tocca le macchine controllate, anche con un solo tentativo (le regole di
allarme scattano solo sopra una soglia, la mappa no): login SSH falliti e riusciti, scansioni del protocollo SSH,
richieste web d'attacco ed errori 4xx. Per ogni indirizzo e per ogni giorno si conservano contatori, utenti provati,
primo e ultimo avvistamento, per **400 giorni** (molto piu' degli snapshot). I contatori sono incrementi calcolati sulle
righe di log effettivamente lette (con la posizione di lettura salvata): una riga non viene contata due volte, neanche
dopo un riavvio. All'avvio gli eventi gia' presenti nei finding (brute force, scansioni, attacchi web) vengono recuperati
una sola volta.

**Posizioni.** Un indirizzo si trasforma in coordinate con un database **locale** (DB-IP "IP to City Lite", CC BY 4.0,
circa 85 MB da scaricare, poche centinaia di MB su disco in `<state_dir>/geo.db`). Nessun indirizzo viene mai inviato a
servizi esterni, e la mappa e' disegnata dal browser senza scaricare tile: niente richieste verso terzi.

```bash
dyna_cyber_agent --config agent.yaml --geo-update          # scarica il file del mese e crea il database (qualche minuto)
dyna_cyber_agent --config agent.yaml --geo-import file.csv.gz   # oppure importa un file scaricato a mano
dyna_cyber_agent --config agent.yaml --geo-status          # mostra database in uso e data
```

Aggiornalo una volta al mese (e' l'unico download; il demone in esecuzione usa il nuovo file entro un minuto).
Senza database la mappa elenca comunque gli indirizzi, ma non li posiziona. Se il download automatico fallisce, scarica
il CSV "IP to City Lite" da https://db-ip.com/db/download/ip-to-city-lite e usa `--geo-import`.

**Cosa mostra.** Bolle per citta' (dimensione = numero di tentativi, colore = rischio, anello bianco = attivo
nell'ultima ora), elenco dei paesi piu' attivi, tabella degli indirizzi con dettagli (utenti provati, target colpiti,
contatori). Rischio: **critico** = accesso riuscito dopo almeno 3 fallimenti, **alto** = 8 o piu' falliti, **medio** =
qualche fallimento, scansione o richiesta d'attacco, **basso** = solo accessi riusciti. Gli indirizzi privati
(192.168.x, 10.x, ...) non hanno una posizione: stanno nell'elenco "Senza posizione". Filtri per periodo, target e rischio.
Zoom con la rotella o i pulsanti, trascina per spostarti, clic su una bolla per vederne gli indirizzi.

**Limiti onesti.** La posizione e' approssimata (di solito la citta' del provider, a volte solo il paese: chi attacca
usa spesso VPN, server affittati o macchine compromesse). Si vede solo cio' che finisce nei log letti: servono i
collector `logs` attivi sul target e `sshd`/web che scrivano log; i tentativi avvenuti mentre l'agente era spento non
si recuperano; un firewall che scarta i pacchetti prima del servizio non lascia traccia nei log SSH.
Attribuzione richiesta dalla licenza: *IP geolocation by DB-IP (https://db-ip.com)*; mappa: Natural Earth (pubblico dominio).

---

## 16. Analisi avanzate: cio' che una regola su una singola osservazione non vede

Le regole (§7) guardano un'osservazione alla volta. Queste nove analisi guardano **attraverso** il tempo, le macchine e
le fonti di dati. Ognuna si puo' spegnere da sola sotto `analysis:` (il blocco completo e' al §16.10); tutte lavorano su
cio' che l'agente ha gia' raccolto o su dati pubblici scaricati sulla macchina dell'agente. **Nessuna tocca un bersaglio
e nessuna richiede un nuovo gate**: un gate installato prima di questa versione continua a funzionare (non gli viene
chiesto nulla di piu' di letture di file e dei comandi che gia' ammetteva).

| § | Analisi | In una riga |
|---|---|---|
| 16.1 | Spiegato da un aggiornamento | un programma nuovo o un servizio riavviato subito dopo `apt upgrade` e' marcato come probabilmente legittimo |
| 16.2 | Incidenti | i finding che condividono un indirizzo, un account o un programma sono concatenati in un'unica storia con cronologia |
| 16.3 | Priorita' delle vulnerabilita' | EPSS (probabilita' di sfruttamento) e *raggiungibilita'* (e' in ascolto sulla rete?) ordinano le CVE |
| 16.4 | Gruppi di pari | cio' che esiste su **una** di cinque macchine identiche viene segnalato, anche se e' nella baseline |
| 16.5 | Viste incrociate | la stessa cosa vista da due interfacce del kernel: una discordanza e' un indizio di rootkit |
| 16.6 | Messaggi di log mai visti | si impara la *forma* di ogni messaggio di log; una forma nuova e' un finding |
| 16.7 | Connessioni in uscita | beaconing, paesi mai contattati prima, picchi di traffico |
| 16.8 | Login | viaggio impossibile, un paese o un'ora che l'account non ha mai usato |
| 16.9 | Liste di minacce | blocklist pubbliche di IP confrontate in locale (nulla viene inviato) |

### 16.1 Spiegato da un aggiornamento

**Il problema.** Dopo un normale `apt upgrade` l'agente vede "eseguibile mai visto su questo host", "processo da un
binario cancellato" (un servizio che gira ancora con il vecchio file sostituito), unit nuove, moduli nuovi... tutto vero,
tutto innocuo.

**Come funziona.**

* Il collector `packages` ricorda l'inventario da una volta all'altra. Quando un pacchetto viene installato, aggiornato o
  rimosso registra un **evento** con l'ora in cui `dpkg` ha scritto il suo elenco file (precisa al secondo, non "entro 6 ore").
* Per ogni pacchetto nuovo o aggiornato legge `/var/lib/dpkg/info/<pacchetto>.list` e tiene i file che possono comparire in
  un finding: programmi (`/usr/bin`, `/usr/sbin`, `/usr/libexec`...), configurazione (`/etc`), unit systemd, moduli del
  kernel, `/opt` e `/usr/local`. Documentazione, localizzazioni, librerie e alberi dei linguaggi sono lasciati fuori. La
  **prima volta** legge l'intero inventario, 600 pacchetti per raccolta (un portatile con 3.600 pacchetti e' completo dopo
  circa sette passate del collector `packages`, cioe' meno di due giorni con le 6 h di default; con qualche `--once` si accelera).
* Quando compare un finding la cui evidenza cita un percorso di proprieta' di un pacchetto cambiato **al massimo
  `window` (7 giorni) prima** del finding (o fino a 5 minuti dopo: orologi e cicli non coincidono esattamente), il finding
  riceve il tag `explained_by_update` e `evidence.explained_by` = pacchetto, tipo (installato/aggiornato), versione
  vecchia e nuova, ora, percorso.
* **Salvaguardia:** se `dpkg -V` / `rpm -Va` (collector `integrity`) segnala proprio quel file come modificato, non si
  spiega nulla: il pacchetto non garantisce per quel file. Chi sostituisce `/usr/sbin/sshd` subito dopo un aggiornamento
  non e' scusato.

**Cosa cambia.** La gravita' della regola **non** viene modificata. Il finding (a) non fa scattare un avviso immediato
a meno che sia *critical*: viaggia nel digest; (b) mostra nella mail e nella console una nota verde "probabilmente
spiegato da un aggiornamento: nome vecchia → nuova"; (c) lo dice all'analista AI, che lo tratta come una forte
spiegazione benigna salvo che il resto delle evidenze la contraddica.

**Inoltre:** `PKG-005` (low) segnala "riavvio necessario" quando esiste `/var/run/reboot-required` (famiglia Debian): un
aggiornamento del kernel o di una libreria di base che non ha ancora effetto. Si chiude da solo dopo il riavvio.

**Limiti.** La vera proprieta' dei file richiede gli elenchi di `dpkg`: sui sistemi RPM si registrano solo gli eventi di
installazione/aggiornamento (nessuna proprieta' dei percorsi, quindi nessuna spiegazione). Un processo che si riavvia
oltre 7 giorni dopo l'aggiornamento non viene collegato (alza `window`). La spiegazione e' un indizio, non una prova:
per questo i finding critical avvisano comunque.

### 16.2 Incidenti

**Il problema.** Un brute force, il login che alla fine e' riuscito, la chiave SSH aggiunta dopo e la connessione aperta
dal programma nuovo sono quattro finding in quattro punti della mail. Insieme sono un'unica intrusione.

**Come funziona (deterministico, senza AI).** Ogni finding aperto viene ridotto a *entita'*:

* **indirizzi** (`src_ip`, `remote_addr`...): solo quelli pubblici (un indirizzo privato concatenerebbe tutta la tua LAN);
* **account** (`user`, `success_user`, ...): mai `root` ne' gli account di sistema;
* **programmi e file**: qualsiasi cosa fuori dalle cartelle del sistema operativo (`/tmp/.x/payload`, `/opt/app/bin/app`,
  `/home/alice/.ssh/authorized_keys`; non `/bin/bash`).

Due finding sono collegati se condividono un'entita' e sono comparsi **entro `window` (24 h)** l'uno dall'altro. Un gruppo
diventa un **incidente** quando ha almeno `min_findings` (2) finding di **almeno due regole diverse** (la stessa regola che
scatta di nuovo e' un solo problema, non una catena). Ogni finding e' collocato in una *fase* ATT&CK (accesso alle
credenziali, accesso iniziale, persistenza, esecuzione, comando e controllo...) in base alle sue tecniche MITRE;
l'incidente elenca le fasi nell'ordine in cui sono avvenute, per esempio *Accesso alle credenziali → Accesso iniziale →
Persistenza su web01*. La sua gravita' e' la peggiore dei suoi finding, **di un livello piu' alta quando la catena attraversa
tre fasi**. Se un nuovo finding fa da ponte tra due incidenti questi si fondono (sopravvive l'id piu' vecchio); quando un
membro viene risolto o accettato e ne restano meno di due, l'incidente si chiude. Le vulnerabilita' e i finding spiegati
da un aggiornamento non partecipano.

**Dove lo vedi.**

* **Mail:** una sezione *Incidenti* dopo la sintesi AI: titolo, periodo, indirizzi/account in comune e una **cronologia** con
  una riga per finding. I tre membri piu' gravi mantengono la scheda completa (marcata "incidente #N"); gli altri compaiono
  solo nella cronologia: dodici finding si leggono come un'unica storia. All'AI viene chiesto di raccontare ogni incidente
  come una sola storia.
* **Avvisi:** un incidente che raggiunge `alerting.min_severity` manda in mail **tutti i suoi membri non ancora segnalati**,
  anche se ciascuno e' sotto la soglia (tre finding *medium* su tre fasi sono un incidente *high*).
* **Console:** la scheda **Incidenti** (schede, cronologia, "analizza l'incidente con l'AI").
* **Riga di comando:** `dyna_cyber_agent --config agent.yaml --incidents` li ricalcola e li stampa.

**Limiti.** I finding sono collegati solo da cio' che condividono in modo dimostrabile: un attacco che non lascia un
indirizzo, un account o un file in comune non sara' concatenato. Un indirizzo *pubblico* condiviso e legittimo (una CDN, il
tuo ufficio) puo' concatenare finding non correlati: accetta il membro rumoroso o restringi `window`.

### 16.3 Priorita' delle vulnerabilita': EPSS e raggiungibilita'

**Il problema.** 281 CVE con CVSS ≥ 7 non sono una lista di cose da fare. Due domande le ordinano: *e' probabile che venga
sfruttata?* e *un attaccante puo' raggiungere il codice vulnerabile?*

**EPSS.** L'agente scarica il file EPSS giornaliero di FIRST.org (circa 3 MB, una richiesta al giorno, da
`epss.empiricalsecurity.com`; il file del giorno compare dopo mezzogiorno UTC, quindi guarda indietro fino a 3 giorni) in
`vuln.db`. Un punteggio e' la probabilita' di attivita' di sfruttamento nei prossimi 30 giorni. Una CVE con **10% o piu'** ha il
tag `epss_high`: tra decine di migliaia di CVE e' raro. `dyna_cyber_agent --config agent.yaml --vuln-sync epss` lo scarica
subito. Nulla delle tue macchine viene inviato: e' un download.

**Raggiungibilita'.** Con la proprieta' dei file del §16.1 l'agente sa quale pacchetto possiede il programma dietro ogni
socket in ascolto e ogni processo in esecuzione. Ogni CVE riceve una `exposure`:

| exposure | significato |
|---|---|
| `listening` | un programma del pacchetto vulnerabile e' in ascolto su un indirizzo non loopback (le porte sono elencate) |
| `listening_local` | e' in ascolto solo su loopback |
| `running` | gira un processo del pacchetto, nulla e' in ascolto |
| `unknown` | nessuna informazione: le **librerie** sono sempre sconosciute (qualsiasi programma puo' usarle), e cosi' tutto quando gli elenchi file non sono ancora raccolti. L'agente non dichiara mai "non raggiungibile" |

La **priorita' (0–100)** mette tutto insieme: CVSS (×5; 25 se senza punteggio) + 25 se attivamente sfruttata (KEV) + EPSS
(+15 al 50%, +10 al 10%, +4 all'1%) + raggiungibilita' (+15 in ascolto, +8 in ascolto locale, +5 in esecuzione) + 3 se nuova
− 10 per un match solo di versione upstream (possibile falso positivo). Report e console ordinano per essa; la console mostra le
colonne *Priorita'*, *EPSS* e *Raggiungibilita'* e un filtro "solo in ascolto in rete". Le CVE del kernel ricevono anche
`reboot_pending` quando c'e' un riavvio in attesa (`PKG-005`).

**Regole.** `VULN-007` (high): un servizio di rete con una falla `epss_high` (scavalca le fasce CVSS: codice raggiungibile piu'
un exploit probabile e' cio' che fa compromettere le macchine). `VULN-008` (medium): `epss_high` con CVSS < 7 (elencata solo
grazie a EPSS). Le altre regole VULN non scattano per la stessa CVE.

**Limiti.** La proprieta' e' per pacchetto binario (famiglia Debian). "Un servizio gira ancora con il vecchio codice dopo
un aggiornamento" non e' un finding CVE: e' il finding *processo da un binario cancellato* (regole PROC), ora marcato
"spiegato da un aggiornamento" (§16.1) perche' significa *riavvia il servizio*. EPSS esiste solo per gli id CVE.

### 16.4 Gruppi di pari

**Il problema.** Una backdoor installata *prima* dell'inizio del monitoraggio fa parte della baseline: per quella macchina e'
"normale". Non e' mai normale per le quattro macchine identiche accanto.

**Configurazione.**

```yaml
targets:
  - {name: web01, transport: ssh, ..., group: web}
  - {name: web02, transport: ssh, ..., group: web}
  - {name: web03, transport: ssh, ..., group: web}
  - {name: web04, transport: ssh, ..., group: web}
```

I target con lo stesso `group` sono confrontati fra loro. Un gruppo richiede almeno `analysis.peers.min_group_size` membri
(**3** al minimo: con due macchine non esiste una maggioranza); i gruppi piu' piccoli restano spenti (lo dice `--check`).
Metti in un gruppo macchine che fanno davvero lo stesso lavoro.

**Cosa si confronta** (stato attuale, dagli ultimi snapshot di `processes`, `network`, `users`, `persistence`, `system`):
account (per nome: gli uid differiscono senza motivo) e appartenenza a gruppi privilegiati, porte in ascolto, programmi fuori
dalle cartelle di sistema, unit systemd abilitate, moduli del kernel, voci cron, chiavi SSH, regole sudo. Porte effimere e
strumenti di sistema che vanno e vengono sono ignorati.

**Cosa si segnala** (collector `peers`, ogni 30 min, servono dati recenti degli altri membri):

* **unico** — presente qui e assente da almeno `min_share` (80%) degli altri. `PEER-001` (**high**) per i tipi sensibili
  alla sicurezza (account, gruppi privilegiati, chiavi SSH, regole sudo, moduli del kernel, voci cron); `PEER-002` (medium)
  per programmi, porte e servizi.
* **mancante** — presente su almeno l'80% degli altri e assente qui: un servizio che si e' fermato, uno strumento di
  sicurezza che e' stato rimosso (`PEER-003`, low).

Queste regole non dipendono dalla baseline: scattano anche durante l'apprendimento. Una differenza legittima si fa tacere
con `--accept <id>`, oppure si allineano le macchine.

### 16.5 Viste incrociate (anti-rootkit)

**L'idea.** Un rootkit puo' modificare la risposta di una interfaccia del kernel; modificarle tutte in modo coerente e' molto
piu' difficile, e non servono firme, quindi si prendono anche i rootkit nuovi. Collector `crossview` (ogni 10 min):

| Confronta | Regola |
|---|---|
| l'elenco della cartella `/proc` (cio' che mostra `ps`) **con** le liste di appartenenza ai cgroup (`cgroup.procs`): un processo in un cgroup, leggibile in `/proc/<pid>/stat`, ma assente dall'elenco | `ROOT-001` critical |
| `/proc/modules` (`lsmod`) **con** `/sys/module/*/initstate` | `ROOT-002` critical |
| le porte TCP in ascolto in `/proc/net/tcp` **con** `ss` (netlink) | `ROOT-003` high |

Una discordanza deve essere vista in **due passate consecutive** prima di essere segnalata: i processi nascono e muoiono fra
le due letture. Il collector elenca anche i **programmi eBPF** compilati dal kernel (letti dai nomi dei simboli in
`/proc/kallsyms`, una volta all'ora) e gli oggetti fissati in `/sys/fs/bpf`: uno nuovo dopo la baseline e' `BPF-001` /
`BPF-002` (medium), perche' l'eBPF e' il modo in cui si nascondono i rootkit moderni.

**Privilegi e costo.** Tutto cio' che legge e' leggibile da tutti (`cgroup.procs`, `/sys/module`, `/proc/net/tcp`, nomi di
`/proc/kallsyms`) e `ss -tulpn` e' un comando che il gate ammette gia'. La lettura oraria di `kallsyms` e' di qualche MB.

**Limiti.** Un rootkit che falsifica *ogni* interfaccia in modo coerente non si vede. La vista cgroup presuppone la
struttura usuale (systemd, cgroup v2 o v1); dentro un container i namespace dei pid cambiano cio' che e' visibile. Non guarda
il disco (quello e' il collector `integrity`).

### 16.6 Messaggi di log mai visti

**L'idea.** Strumenti in stile Wazuh richiedono un decoder scritto per ogni formato di log. Qui ogni messaggio e' ridotto
alla sua **forma**: numeri, indirizzi, percorsi, identificatori, host e valori `chiave=valore` diventano segnaposto, cosi'
`Accepted publickey for alice from 10.0.0.5 port 4211` e la stessa riga con altri valori sono un unico modello. Un messaggio
la cui forma non era nella baseline e' un comportamento nuovo, qualunque cosa dica.

* **Cosa entra:** le righe che nessun parser dedicato ha capito (il `syslog`/`messages` combinato, il journal e le righe di
  auth/kernel che non sono login ne' eventi del kernel). Il syslog combinato ora viene letto anche quando esistono
  `auth.log` e `kern.log` (gli altri log non sono letti due volte).
* **Apprendimento:** durante la finestra della baseline ogni forma e' appresa; poi una nuova e' drift. L'elenco delle forme
  gia' segnalate e' conservato nel database, quindi un riavvio non le segnala di nuovo.
* **Regole:** `LOG-050` (**info**: registrato e visibile nella console e in `--events`, ma non riempie le mail) e `LOG-051`
  (medium) quando la nuova forma contiene parole come *denied, failed, segfault, out of memory, corrupt, violation*. I
  finding `LOG-050` non vengono mandati all'AI (sarebbero molti).
* **Freni:** al massimo `analysis.logs.max_new_per_cycle` (25) forme nuove per ciclo, prima quelle allarmanti; il resto aspetta.

**Limiti.** Dopo un aggiornamento software compaiono molte forme nuove (tutte `info`). La riga d'esempio nell'evidenza e'
testo di log vero: la mail la neutralizza come tutto cio' che arriva dalla macchina.

### 16.7 Connessioni in uscita

Collector `netflow` (ogni 2 min) piu' un registro che l'agente tiene delle **nuove** connessioni in uscita (un evento per
connessione, non per poll; una connessione breve che compare solo come `TIME_WAIT` conta lo stesso; le connessioni gia'
aperte all'avvio dell'agente sono ignorate).

* **Beaconing.** Connessioni allo stesso indirizzo e porta a ritmo costante sono il modo in cui il malware chiede "ci sono
  ordini?". Servono almeno 8 connessioni in almeno 10 minuti, con periodo tra 20 s e 1 h, almeno l'80% degli intervalli entro il
  25% della mediana (e non meno di due volte l'intervallo di campionamento della rete). Le raffiche contano una volta. Poiche'
  esiste software periodico (controlli di aggiornamento, monitoraggio), la baseline impara le identita' `net.beacon` che
  c'erano gia': `NET-030` (medium) per una nuova, `NET-031` (**high**) quando la destinazione e' fuori dalle tue reti **e** la
  porta non e' 80, 443 o 53.
* **Paesi nuovi.** Le connessioni in uscita sono marcate con il paese dell'indirizzo (il database di geolocalizzazione
  offline del §15.1: `--geo-update`); un paese che nessuna connessione della baseline aveva raggiunto e' `NET-032` (low).
* **Picchi di traffico.** Da `/proc/net/dev`, la velocita' di trasmissione di ogni interfaccia reale (non `lo`, docker, veth...)
  e' confrontata con una media mobile esponenziale conservata tra i riavvii. Dopo **6 ore di riscaldamento**, una velocita'
  oltre 5 volte la media (e oltre 8 deviazioni) **e** oltre 512 kB/s per due campioni di fila e' `NET-033` (medium). Un picco
  insegna appena al modello che e' normale.

**Limiti.** La rete e' campionata ogni 15 s: un beacon piu' breve e' datato con ±15 s di errore. L'UDP (compreso il tunnel
DNS) non e' tracciato. Un C2 che gia' faceva beaconing durante l'apprendimento e' appreso come normale.

### 16.8 Login: viaggio impossibile, paese nuovo, ora insolita

Per ogni login SSH riuscito (l'indirizzo di provenienza e' localizzato con il database offline del §15.1):

* **Viaggio impossibile** (`LOG-060`, high): lo stesso account, un login localizzato precedente meno di 24 h prima, una
  distanza di almeno `min_distance_km` (500) e una velocita' implicita sopra `max_speed_kmh` (900). L'evidenza mostra i due
  luoghi, la distanza, il tempo e la velocita'.
* **Paese nuovo per questo account** (`LOG-061`, medium) e **ora insolita** (`LOG-062`, low: una fascia di 3 ore del giorno,
  in **UTC**, mai usata dall'account nella baseline). Sono drift delle faccette `auth.country` / `auth.hour`, quindi tacciono
  mentre la baseline e' in apprendimento.

Lo storico e' conservato per 400 giorni nel database dell'agente. **Limiti onesti:** una VPN o una rete mobile sposta un
indirizzo per il mondo (accetta il finding, oppure l'utente lo fara' scattare di continuo); senza il database di
geolocalizzazione nulla viene localizzato e niente di tutto cio' gira; gli indirizzi privati non sono mai localizzati; l'ora
dell'evento e' quella della raccolta.

### 16.9 Liste di minacce

L'agente scarica blocklist pubbliche di IP in `<state_dir>/intel/` e confronta gli indirizzi **in locale**. Nulla delle tue
macchine viene inviato: le liste entrano, nulla esce. Insieme predefinito (sostituiscilo con `threat_intel.lists`):

| Nome | Categoria | Fonte |
|---|---|---|
| `feodo` | c2 | abuse.ch Feodo Tracker (server di comando e controllo di botnet) |
| `spamhaus_drop` | attacker | Spamhaus DROP (reti dirottate / criminali) |
| `firehol_level1` | attacker | FireHOL livello 1 (aggregato di liste affidabili) |
| `et_compromised` | compromised | Emerging Threats, host compromessi |
| `blocklist_de_ssh` | attacker | blocklist.de (attaccanti SSH) |

Sono aggiornate ogni `refresh_every` (12 h); un download fallito o malformato **non sostituisce mai** una lista buona (una
pagina d'errore HTML viene rifiutata). Un riavvio legge le copie dal disco senza alcuna rete. Solo IPv4.

Dove si applica il confronto: connessioni in uscita aperte (`ti` compare nell'evidenza con lista e categoria), login riusciti
e (solo come tag, sono gia' attacchi) brute force, scansioni e attacchi web.

| Regola | |
|---|---|
| `TI-001` **critical** | una connessione aperta verso un server **C2** |
| `TI-002` high | una connessione verso un indirizzo delle liste *attacker / compromised / scanner* |
| `TI-003` **critical** | un **login riuscito** da un indirizzo in lista |

`dyna_cyber_agent --config agent.yaml --intel-update` scarica subito; `--intel-status` mostra cosa c'e' su disco.

Una lista valida ma vuota (per esempio `feodo` quando nessun server botnet e' attivo: solo l'intestazione di commenti, `0 range(s)`) viene accettata e sostituisce la copia vecchia. Un download senza indirizzi e con qualcosa di diverso dai commenti (una pagina di errore HTML, un corpo vuoto) viene rifiutato e resta la copia precedente.
**Controlla le condizioni d'uso di ogni lista** prima di farci affidamento (alcune limitano l'uso commerciale o la
frequenza di download); gli indirizzi di hosting condiviso a volte finiscono in una lista per errore, quindi guarda che
programma e' prima di reagire.

### 16.10 I blocchi `analysis:` e `threat_intel:`

```yaml
analysis:
  explain_updates: {enabled: true, window: 7d}            # §16.1
  incidents: {enabled: true, window: 24h, min_findings: 2}  # §16.2
  peers: {enabled: true, min_group_size: 3, min_share: 0.8} # §16.4 (servono anche i `group:` sui target)
  logs: {templates: true, max_new_per_cycle: 25}           # §16.6
  outbound: {beaconing: true, new_countries: true, traffic_spikes: true}  # §16.7
  travel: {enabled: true, max_speed_kmh: 900, min_distance_km: 500}       # §16.8
vuln: {epss: true, exposure: true}                          # §16.3
threat_intel: {enabled: true, refresh_every: 12h}           # §16.9 (lists: [...] per sostituire l'insieme predefinito)
```

**Attivare un'analisi in un secondo tempo.** Le analisi che imparano nella baseline un nuovo tipo di fatto (paesi, ore di
login, beacon, programmi eBPF, forme dei messaggi di log) **imparano in silenzio durante le proprie prime 24 ore**, anche se
la baseline del target e' stata bloccata da tempo: attivarne una, o installare il database di geolocalizzazione dopo la
fase di apprendimento, non ti sommerge con tutto cio' che la macchina ha sempre fatto. Lo stesso vale dopo l'aggiornamento
dell'agente a questa versione.

`--check` stampa lo stato di ogni parte e avvisa dei gruppi troppo piccoli. I target con `collectors: all` eseguono i tre
nuovi collector (`peers`, `crossview`, `netflow`); con un elenco esplicito aggiungi quelli che vuoi (`crossview`, `netflow`;
`peers` richiede anche `group:`). `crossview` richiede `/proc` e `/sys` leggibili (nessun privilegio).

### 16.11 Come provare ciascuna in sicurezza

Fallo solo su una **macchina di prova** (§14.4), dopo `--baseline-lock` (tutte tranne le prime tre sono drift o richiedono storico).

| § | Cosa fare | Cosa dovresti vedere |
|---|---|---|
| 16.1 | su un target di prova: `apt install <piccolo pacchetto>` (o `apt install --reinstall`), poi aspetta il collector `packages` (o `--once`) e un finding collegato (es. il riavvio di un servizio) | il finding con la nota verde "spiegato da"; `--event <id>` mostra `evidence.explained_by` |
| 16.2 | genera 2–3 finding collegati da un indirizzo di prova (login SSH falliti, poi aggiungi una chiave usa e getta per lo stesso utente) | un incidente nella console e in `--incidents`; la mail mostra la cronologia |
| 16.3 | `--vuln-sync epss`, poi `--vuln-check <target>` e apri la scheda *Vulnerabilita'* della console | le colonne EPSS e Raggiungibilita'; un servizio in ascolto sta sopra una libreria con lo stesso CVSS |
| 16.4 | tre o piu' macchine di prova con lo stesso `group:`; aggiungi un utente su una | `PEER-001` su quella macchina |
| 16.5 | non si puo' provocare senza un rootkit; lascialo girare un giorno e controlla che non segnali nulla (nessun falso positivo) e che le voci `bpf.program` compaiano in `--baseline-status` | il silenzio e' corretto |
| 16.6 | dopo la baseline: esegui `logger -t mytest "qualcosa mai detto prima"` sulla macchina di prova | `LOG-050` (info) in `--events --all` |
| 16.7 | un ciclo che si connette ogni 60 s a un server esterno di prova (`while true; do curl -s https://example.org >/dev/null; sleep 60; done`) dopo la baseline | `NET-030` dopo ~10–15 minuti |
| 16.8 | un login SSH da un'uscita VPN in un altro paese poco dopo uno dal tuo (serve il database geo) | `LOG-060` / `LOG-061` |
| 16.9 | `--intel-update`, poi connettiti a un indirizzo di una lista (prendine uno da `<state_dir>/intel/firehol_level1.list`; apri solo una connessione TCP, es. `nc -w2 <ip> 80`) | `TI-002` |

---
