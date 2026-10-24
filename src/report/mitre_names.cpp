#include "report/mitre_names.h"

#include <map>

namespace agent {

std::string mitreName(const std::string& id) {
  static const std::map<std::string, std::string> names = {
      {"T1021.004", "Remote Services: SSH"},
      {"T1036", "Masquerading"},
      {"T1036.005", "Masquerading: Match Legitimate Name or Location"},
      {"T1040", "Network Sniffing"},
      {"T1053.003", "Scheduled Task/Job: Cron"},
      {"T1055", "Process Injection"},
      {"T1056", "Input Capture"},
      {"T1059", "Command and Scripting Interpreter"},
      {"T1059.004", "Command and Scripting Interpreter: Unix Shell"},
      {"T1068", "Exploitation for Privilege Escalation"},
      {"T1070.003", "Indicator Removal: Clear Command History"},
      {"T1070.004", "Indicator Removal: File Deletion"},
      {"T1071", "Application Layer Protocol"},
      {"T1078", "Valid Accounts"},
      {"T1078.003", "Valid Accounts: Local Accounts"},
      {"T1083", "File and Directory Discovery"},
      {"T1095", "Non-Application Layer Protocol"},
      {"T1098", "Account Manipulation"},
      {"T1098.004", "Account Manipulation: SSH Authorized Keys"},
      {"T1105", "Ingress Tool Transfer"},
      {"T1110", "Brute Force"},
      {"T1110.001", "Brute Force: Password Guessing"},
      {"T1110.003", "Brute Force: Password Spraying"},
      {"T1133", "External Remote Services"},
      {"T1136.001", "Create Account: Local Account"},
      {"T1190", "Exploit Public-Facing Application"},
      {"T1200", "Hardware Additions"},
      {"T1203", "Exploitation for Client Execution"},
      {"T1205", "Traffic Signaling"},
      {"T1222.002", "File and Directory Permissions Modification: Linux and Mac"},
      {"T1496", "Resource Hijacking"},
      {"T1498.001", "Network Denial of Service: Direct Network Flood"},
      {"T1499", "Endpoint Denial of Service"},
      {"T1505.003", "Server Software Component: Web Shell"},
      {"T1531", "Account Access Removal"},
      {"T1543.002", "Create or Modify System Process: Systemd Service"},
      {"T1546", "Event Triggered Execution"},
      {"T1546.004", "Event Triggered Execution: Unix Shell Configuration Modification"},
      {"T1547", "Boot or Logon Autostart Execution"},
      {"T1547.006", "Boot or Logon Autostart Execution: Kernel Modules and Extensions"},
      {"T1548", "Abuse Elevation Control Mechanism"},
      {"T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid"},
      {"T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"},
      {"T1552.001", "Unsecured Credentials: Credentials In Files"},
      {"T1554", "Compromise Host Software Binary"},
      {"T1559", "Inter-Process Communication"},
      {"T1562", "Impair Defenses"},
      {"T1562.001", "Impair Defenses: Disable or Modify Tools"},
      {"T1564", "Hide Artifacts"},
      {"T1564.001", "Hide Artifacts: Hidden Files and Directories"},
      {"T1565", "Data Manipulation"},
      {"T1565.001", "Data Manipulation: Stored Data Manipulation"},
      {"T1571", "Non-Standard Port"},
      {"T1572", "Protocol Tunneling"},
      {"T1574", "Hijack Execution Flow"},
      {"T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking"},
      {"T1595", "Active Scanning"},
      {"T1595.002", "Active Scanning: Vulnerability Scanning"},
      {"T1595.003", "Active Scanning: Wordlist Scanning"},
      {"T1620", "Reflective Code Loading"},
  };
  const auto it = names.find(id);
  return it == names.end() ? std::string() : it->second;
}

std::string mitreTactic(const std::string& id) {
  static const std::map<std::string, std::string> tactic = {
      {"T1021", "lateral-movement"},      {"T1036", "defense-evasion"},   {"T1040", "credential-access"},   {"T1053", "persistence"},
      {"T1055", "defense-evasion"},       {"T1056", "credential-access"}, {"T1059", "execution"},           {"T1068", "privilege-escalation"},
      {"T1070", "defense-evasion"},       {"T1071", "command-and-control"}, {"T1078", "initial-access"},    {"T1083", "discovery"},
      {"T1095", "command-and-control"},   {"T1098", "persistence"},       {"T1105", "command-and-control"}, {"T1110", "credential-access"},
      {"T1133", "initial-access"},        {"T1136", "persistence"},       {"T1190", "initial-access"},      {"T1200", "initial-access"},
      {"T1203", "execution"},             {"T1205", "command-and-control"}, {"T1222", "defense-evasion"},  {"T1496", "impact"},
      {"T1498", "impact"},                {"T1499", "impact"},            {"T1505", "persistence"},         {"T1531", "impact"},
      {"T1543", "persistence"},           {"T1546", "persistence"},       {"T1547", "persistence"},         {"T1548", "privilege-escalation"},
      {"T1552", "credential-access"},     {"T1554", "persistence"},       {"T1559", "execution"},           {"T1562", "defense-evasion"},
      {"T1564", "defense-evasion"},       {"T1565", "impact"},            {"T1571", "command-and-control"}, {"T1572", "command-and-control"},
      {"T1574", "persistence"},           {"T1595", "reconnaissance"},    {"T1620", "defense-evasion"},     {"T1041", "exfiltration"},
      {"T1048", "exfiltration"},          {"T1568", "command-and-control"}, {"T1090", "command-and-control"}, {"T1573", "command-and-control"},
  };
  const auto it = tactic.find(id.substr(0, id.find('.')));
  return it == tactic.end() ? std::string() : it->second;
}

std::string tacticName(const std::string& id, const std::string& lang) {
  static const std::map<std::string, std::pair<std::string, std::string>> names = {  // id -> {en, it}
      {"reconnaissance", {"Reconnaissance", "Ricognizione"}},
      {"initial-access", {"Initial access", "Accesso iniziale"}},
      {"execution", {"Execution", "Esecuzione"}},
      {"persistence", {"Persistence", "Persistenza"}},
      {"privilege-escalation", {"Privilege escalation", "Escalation dei privilegi"}},
      {"defense-evasion", {"Defense evasion", "Elusione delle difese"}},
      {"credential-access", {"Credential access", "Accesso alle credenziali"}},
      {"discovery", {"Discovery", "Esplorazione"}},
      {"lateral-movement", {"Lateral movement", "Movimento laterale"}},
      {"collection", {"Collection", "Raccolta"}},
      {"command-and-control", {"Command and control", "Comando e controllo"}},
      {"exfiltration", {"Exfiltration", "Esfiltrazione"}},
      {"impact", {"Impact", "Impatto"}},
      {"other", {"Other activity", "Altra attivita'"}},
  };
  const auto it = names.find(id);
  if (it == names.end()) return id;
  return lang == "en" ? it->second.first : it->second.second;
}

}  // namespace agent
