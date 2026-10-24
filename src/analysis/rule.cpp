#include "analysis/rule.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

#include "analysis/identity.h"
#include "core/util.h"

namespace agent {
namespace {

void resolve(const nlohmann::json& j, const std::vector<std::string>& segs, size_t i, std::vector<nlohmann::json>& out) {
  if (i == segs.size()) {
    out.push_back(j);
    return;
  }
  if (j.is_object()) {
    const auto it = j.find(segs[i]);
    if (it != j.end()) resolve(*it, segs, i + 1, out);
  } else if (j.is_array()) {
    if (const auto idx = util::parseUint(segs[i])) {
      if (*idx < j.size()) resolve(j[static_cast<size_t>(*idx)], segs, i + 1, out);
    } else {
      for (const auto& e : j) resolve(e, segs, i, out);  // fan out, same segment
    }
  }
}

bool numeric(const nlohmann::json& j) { return j.is_number(); }

bool leafMatches(const Condition& c, const nlohmann::json& v) {
  const std::string& op = c.op;
  if (op == "equals") return v == c.value;
  if (op == "in") return std::any_of(c.value.begin(), c.value.end(), [&](const auto& e) { return e == v; });
  if (op == "gt" || op == "gte" || op == "lt" || op == "lte") {
    if (!numeric(v)) return false;
    const double a = v.get<double>(), b = c.value.get<double>();
    return op == "gt" ? a > b : op == "gte" ? a >= b : op == "lt" ? a < b : a <= b;
  }
  if (!v.is_string()) return false;
  const std::string& s = v.get_ref<const std::string&>();
  if (op == "regex") return std::regex_search(s, *c.regex);
  auto any_of_values = [&](auto pred) {
    if (c.value.is_array()) return std::any_of(c.value.begin(), c.value.end(), [&](const auto& e) { return e.is_string() && pred(e.template get<std::string>()); });
    return pred(c.value.template get<std::string>());
  };
  if (op == "startswith") return any_of_values([&](const std::string& p) { return util::startsWith(s, p); });
  if (op == "endswith") return any_of_values([&](const std::string& p) { return util::endsWith(s, p); });
  if (op == "contains") return any_of_values([&](const std::string& p) { return s.find(p) != std::string::npos; });
  return false;
}

nlohmann::json yamlToJson(const YAML::Node& n) {
  if (n.IsSequence()) {
    nlohmann::json a = nlohmann::json::array();
    for (const auto& e : n) a.push_back(yamlToJson(e));
    return a;
  }
  if (n.IsMap()) {
    nlohmann::json o = nlohmann::json::object();
    for (const auto& kv : n) o[kv.first.as<std::string>()] = yamlToJson(kv.second);
    return o;
  }
  if (!n.IsScalar()) return nullptr;
  const std::string s = n.as<std::string>();
  if (n.Tag() == "!") return s;  // quoted scalar: always a string
  if (s == "true") return true;
  if (s == "false") return false;
  if (auto u = util::parseUint(s)) return *u;
  try {
    size_t pos = 0;
    const double d = std::stod(s, &pos);
    if (pos == s.size()) return d;
  } catch (...) {}
  return s;
}

const std::set<std::string> kOps{"equals", "in", "startswith", "endswith", "contains", "regex", "exists", "gt", "gte", "lt", "lte"};

Result<Condition> parseCondition(const YAML::Node& n) {
  if (!n.IsMap()) return err("condition must be a mapping");
  Condition c;
  for (const char* grp : {"all", "any"}) {
    if (n[grp]) {
      c.kind = std::string(grp) == "all" ? Condition::Kind::All : Condition::Kind::Any;
      if (!n[grp].IsSequence() || n[grp].size() == 0) return err(std::string("'") + grp + "' needs a non-empty list");
      for (const auto& e : n[grp]) {
        auto ch = parseCondition(e);
        if (!ch) return ch;
        c.children.push_back(std::move(ch.value()));
      }
      return c;
    }
  }
  if (n["not"]) {
    c.kind = Condition::Kind::Not;
    auto ch = parseCondition(n["not"]);
    if (!ch) return ch;
    c.children.push_back(std::move(ch.value()));
    return c;
  }
  if (!n["field"] || !n["op"]) return err("condition needs 'field' and 'op' (or all/any/not)");
  c.field = n["field"].as<std::string>();
  c.op = n["op"].as<std::string>();
  if (!kOps.count(c.op)) return err("unknown op '" + c.op + "'");
  c.value = n["value"] ? yamlToJson(n["value"]) : nlohmann::json(true);
  if (c.op == "in" && !c.value.is_array()) return err("op 'in' needs a list");
  if (c.op == "exists" && !c.value.is_boolean()) return err("op 'exists' needs true/false");
  if ((c.op == "gt" || c.op == "gte" || c.op == "lt" || c.op == "lte") && !c.value.is_number()) return err("op '" + c.op + "' needs a number");
  if (c.op == "regex") {
    if (!c.value.is_string()) return err("op 'regex' needs a string");
    try {
      c.regex = std::make_shared<std::regex>(c.value.get<std::string>(), std::regex::ECMAScript | std::regex::optimize);
    } catch (const std::regex_error& e) {
      return err("invalid regex '" + c.value.get<std::string>() + "': " + e.what());
    }
  }
  if ((c.op == "startswith" || c.op == "endswith" || c.op == "contains") && !c.value.is_string() && !c.value.is_array()) {
    return err("op '" + c.op + "' needs a string or a list of strings");
  }
  return c;
}

std::vector<std::string> strList(const YAML::Node& n) {
  std::vector<std::string> out;
  if (!n || n.IsNull()) return out;
  if (n.IsScalar()) return {n.as<std::string>()};
  for (const auto& e : n) out.push_back(e.as<std::string>());
  return out;
}

bool contains(const std::vector<std::string>& v, const std::string& s) { return std::find(v.begin(), v.end(), s) != v.end(); }

}  // namespace

bool Condition::eval(const nlohmann::json& data) const {
  switch (kind) {
    case Kind::All: return std::all_of(children.begin(), children.end(), [&](const Condition& c) { return c.eval(data); });
    case Kind::Any: return std::any_of(children.begin(), children.end(), [&](const Condition& c) { return c.eval(data); });
    case Kind::Not: return !children[0].eval(data);
    case Kind::Leaf: break;
  }
  std::vector<nlohmann::json> vals;
  resolve(data, util::split(field, '.'), 0, vals);
  if (op == "exists") {
    const bool present = std::any_of(vals.begin(), vals.end(), [](const nlohmann::json& v) { return !v.is_null(); });
    return present == value.get<bool>();
  }
  return std::any_of(vals.begin(), vals.end(), [&](const nlohmann::json& v) { return leafMatches(*this, v); });
}

bool Rule::matches(const Observation& o, const std::vector<Identity>& drift_set) const {
  if (o.type != type) return false;
  if (!tags_any.empty() && !std::any_of(tags_any.begin(), tags_any.end(), [&](const std::string& t) { return contains(o.tags, t); })) return false;
  if (!std::all_of(tags_all.begin(), tags_all.end(), [&](const std::string& t) { return contains(o.tags, t); })) return false;
  auto drifting = [&](const std::string& facet) {
    return std::any_of(drift_set.begin(), drift_set.end(), [&](const Identity& i) { return i.facet == facet; });
  };
  if (drift == "any" ? drift_set.empty() : (!drift.empty() && !drifting(drift))) return false;
  if (std::any_of(drift_absent.begin(), drift_absent.end(), drifting)) return false;
  return std::all_of(where.begin(), where.end(), [&](const Condition& c) { return c.eval(o.data); });
}

Result<std::vector<Rule>> parseRules(const std::string& yaml_text, const std::string& source) {
  std::vector<Rule> rules;
  try {
    const YAML::Node root = YAML::Load(yaml_text);
    if (root.IsNull()) return rules;
    if (!root.IsSequence()) return err(source + ": top level must be a list of rules");
    for (const auto& n : root) {
      Rule r;
      r.source = source;
      r.id = n["id"] ? n["id"].as<std::string>() : "";
      const std::string where_am_i = source + ": rule '" + (r.id.empty() ? "?" : r.id) + "'";
      if (r.id.empty()) return err(source + ": rule without 'id'");
      r.title = n["title"] ? n["title"].as<std::string>() : "";
      if (r.title.empty()) return err(where_am_i + ": missing 'title'");
      const auto sev = parseSeverity(n["severity"] ? n["severity"].as<std::string>() : "");
      if (!sev) return err(where_am_i + ": invalid or missing 'severity'");
      r.severity = *sev;
      r.description = n["description"] ? n["description"].as<std::string>() : "";
      r.remediation = n["remediation"] ? n["remediation"].as<std::string>() : "";
      r.mitre = strList(n["mitre"]);
      r.cwe = strList(n["cwe"]);
      for (const auto& w : r.cwe) {
        if (!(util::startsWith(w, "CWE-") && util::allDigits(w.substr(std::min<size_t>(4, w.size()))) && w.size() > 4)) return err(where_am_i + ": invalid cwe '" + w + "' (expected CWE-<number>)");
      }

      const YAML::Node m = n["match"];
      if (!m || !m.IsMap()) return err(where_am_i + ": missing 'match'");
      r.type = m["type"] ? m["type"].as<std::string>() : "";
      if (!contains(knownObservationTypes(), r.type)) return err(where_am_i + ": unknown match.type '" + r.type + "'");
      r.tags_any = strList(m["tags_any"]);
      r.tags_all = strList(m["tags_all"]);
      r.drift = m["drift"] ? m["drift"].as<std::string>() : "";
      if (!r.drift.empty() && r.drift != "any" && !contains(knownFacets(), r.drift)) return err(where_am_i + ": unknown drift facet '" + r.drift + "'");
      r.drift_absent = strList(m["drift_absent"]);
      for (const auto& f : r.drift_absent) if (!contains(knownFacets(), f)) return err(where_am_i + ": unknown drift_absent facet '" + f + "'");
      if (m["where"]) {
        if (!m["where"].IsSequence()) return err(where_am_i + ": 'where' must be a list");
        for (const auto& c : m["where"]) {
          auto cond = parseCondition(c);
          if (!cond) return err(where_am_i + ": " + cond.error());
          r.where.push_back(std::move(cond.value()));
        }
      }
      if (r.tags_any.empty() && r.tags_all.empty() && r.drift.empty() && r.where.empty()) {
        return err(where_am_i + ": match has no condition (it would match every " + r.type + ")");
      }
      rules.push_back(std::move(r));
    }
  } catch (const YAML::Exception& e) {
    return err(source + ": yaml error: " + e.what());
  }
  return rules;
}

Result<std::vector<Rule>> loadRulesDir(const std::string& dir) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (dir.find_first_of("*?[") != std::string::npos) {
    return err("rules_dir must be a directory, not a pattern: '" + dir + "' (use the folder itself, e.g. " + dir.substr(0, dir.find_first_of("*?[") == 0 ? 0 : dir.rfind('/', dir.find_first_of("*?["))) +
               "; every .yaml file inside is loaded)");
  }
  if (!fs::is_directory(dir, ec)) return err("rules directory not found: " + dir);
  std::vector<fs::path> files;
  for (fs::recursive_directory_iterator it(dir, ec), end; it != end; it.increment(ec)) {
    if (ec) return err("cannot scan rules directory: " + ec.message());
    if (it->is_regular_file() && (it->path().extension() == ".yaml" || it->path().extension() == ".yml")) files.push_back(it->path());
  }
  std::sort(files.begin(), files.end());
  std::vector<Rule> all;
  std::set<std::string> ids;
  for (const auto& f : files) {
    std::ifstream in(f);
    if (!in) return err("cannot read " + f.string());
    std::ostringstream ss;
    ss << in.rdbuf();
    auto r = parseRules(ss.str(), f.string());
    if (!r) return err(r.error());
    for (auto& rule : r.value()) {
      if (!ids.insert(rule.id).second) return err(f.string() + ": duplicate rule id '" + rule.id + "'");
      all.push_back(std::move(rule));
    }
  }
  return all;
}

}  // namespace agent
