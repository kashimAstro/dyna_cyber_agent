#include "report/labels.h"

namespace agent::report {
namespace {

const Labels kIt = {
    "Allerta di sicurezza", "Report di sicurezza", "Mail di prova",
    "Rischio massimo", "Generato il", "Host dell'agente", "Periodo", "Finding aperti", "Nuovi nel periodo", "Finding",
    "Valutazione dell'analista AI", "Correlazioni (possibile catena d'attacco)", "Stato dei collector", "Bersaglio", "Regola",
    "Soggetto", "Visto", "Primo rilevamento", "Ultimo rilevamento", "x",
    "Valutazione AI", "Verdetto", "Confidenza", "Azioni consigliate", "Verifiche aggiuntive", "Evidenze", "Non presente nella baseline",
    "MITRE ATT&CK", "NUOVO", "gia' noto",
    "Il testo osservato contiene quello che sembra un tentativo di manipolare l'analisi AI: considerarlo un indicatore di attacco.",
    "altri %zu finding non mostrati: usa `dyna_cyber_agent --events` per l'elenco completo", "Nessun nuovo problema: tutto tranquillo.",
    "Collector", "Ultimo successo", "Ultimo errore", "NON AGGIORNATO", "riusciti", "falliti", "mai",
    "La valutazione AI e' un supporto: verifica sempre le evidenze prima di agire. Il rischio mostrato e' il maggiore tra quello della regola e quello dell'AI.",
    "Per accettare un finding come normale (aggiorna la baseline): dyna_cyber_agent --config <file> --accept <id>",
    "Questa e' una mail di prova inviata da dyna_cyber_agent. Se la leggi, la configurazione SMTP funziona.",
    "Valutazione AI non disponibile (disattivata o non raggiungibile).", "Risolti nel periodo", "Debolezze (CWE)", "Intelligence sulle vulnerabilita'",
    {"info", "basso", "medio", "alto", "critico"},
    {"probabilmente malevolo", "sospetto", "probabilmente benigno", "servono piu' dati"}};

const Labels kEn = {
    "Security alert", "Security report", "Test mail",
    "Highest risk", "Generated", "Agent host", "Period", "Open findings", "New in period", "Findings",
    "AI analyst assessment", "Correlations (possible attack chain)", "Collector health", "Target", "Rule",
    "Subject", "Seen", "First seen", "Last seen", "x",
    "AI assessment", "Verdict", "Confidence", "Recommended actions", "Additional checks", "Evidence", "Not in baseline",
    "MITRE ATT&CK", "NEW", "already known",
    "The observed text contains what looks like an attempt to manipulate the AI analysis: treat it as an attack indicator.",
    "%zu more finding(s) not shown: run `dyna_cyber_agent --events` for the full list", "No new problems: all quiet.",
    "Collector", "Last success", "Last error", "STALE", "ok", "failed", "never",
    "The AI assessment is advisory: verify the evidence before acting. The risk shown is the higher of the rule's and the AI's.",
    "To accept a finding as normal (updates the baseline): dyna_cyber_agent --config <file> --accept <id>",
    "This is a test mail sent by dyna_cyber_agent. If you can read it, the SMTP configuration works.",
    "AI assessment not available (disabled or unreachable).", "Resolved in period", "Weaknesses (CWE)", "Vulnerability intelligence",
    {"info", "low", "medium", "high", "critical"},
    {"likely malicious", "suspicious", "likely benign", "needs more data"}};

}  // namespace

const Labels& labels(const std::string& lang) { return lang == "en" ? kEn : kIt; }
const char* severityLabel(const Labels& l, Severity s) { return l.sev[static_cast<int>(s)]; }
const char* verdictLabel(const Labels& l, const std::string& v) {
  if (v == "likely_malicious") return l.verdicts[0];
  if (v == "suspicious") return l.verdicts[1];
  if (v == "likely_benign") return l.verdicts[2];
  return l.verdicts[3];
}

}  // namespace agent::report
