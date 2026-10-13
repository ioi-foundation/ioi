//! The gate's pinned inputs (deps.pin, clippy.toml) and its reviewed registries (the `.tsv` files
//! beside this crate), read strictly: an unknown line, a wrong field count or a repeated key is an
//! error, never a skip.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// One configuration the gate checks: a shipped feature set of ioi-node (or every feature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub name: String,
    /// `default` (no feature), `all` (`--all-features`) or the `package/feature` list.
    pub spec: ConfigSpec,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigSpec {
    Default,
    All,
    Features(Vec<String>),
}

impl Config {
    /// The cargo arguments selecting this configuration's features.
    pub fn cargo_args(&self) -> Vec<String> {
        match &self.spec {
            ConfigSpec::Default => Vec::new(),
            ConfigSpec::All => vec!["--all-features".to_string()],
            ConfigSpec::Features(list) => vec!["--features".to_string(), list.join(",")],
        }
    }
}

/// deps.pin: the deny list the review confirmed, the features of the inventoried packages, the
/// configurations, and the direct normal dependencies the review covers.
#[derive(Debug, Default)]
pub struct Pin {
    pub deny_list_sha256: String,
    /// `package feature`.
    pub features: BTreeSet<String>,
    pub configs: Vec<Config>,
    /// `package dependency version`.
    pub deps: BTreeSet<String>,
}

pub fn read_pin(text: &str) -> Result<Pin, String> {
    let mut pin = Pin::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["confirmed-deny-list-sha256", hash] => pin.deny_list_sha256 = hash.to_string(),
            ["feature", package, name] => {
                if !pin.features.insert(format!("{package} {name}")) {
                    return Err(format!("deps.pin repeats a feature line: {line}"));
                }
            }
            ["config", name, spec] => {
                if pin.configs.iter().any(|c| c.name == *name) {
                    return Err(format!("deps.pin repeats configuration {name}"));
                }
                let spec = match *spec {
                    "default" => ConfigSpec::Default,
                    "all" => ConfigSpec::All,
                    list => {
                        let features: Vec<String> = list.split(',').map(str::to_string).collect();
                        if features.iter().any(|f| f.split('/').count() != 2) {
                            return Err(format!(
                                "deps.pin configuration {name}: every feature is written package/feature: {list}"
                            ));
                        }
                        ConfigSpec::Features(features)
                    }
                };
                pin.configs.push(Config {
                    name: name.to_string(),
                    spec,
                });
            }
            ["dep", package, name, version] => {
                if !pin.deps.insert(format!("{package} {name} {version}")) {
                    return Err(format!("deps.pin repeats a dependency line: {line}"));
                }
            }
            _ => return Err(format!("deps.pin has an unknown line: {line}")),
        }
    }
    if pin.deny_list_sha256.is_empty() || pin.configs.is_empty() || pin.features.is_empty() {
        return Err(
            "deps.pin names no confirmed deny-list sha256, no configuration or no feature"
                .to_string(),
        );
    }
    Ok(pin)
}

/// One deny-list entry: its section (`types` or `methods`), its path and its reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub section: &'static str,
    pub path: String,
    pub reason: String,
}

/// clippy.toml's entries, one `{ path = "...", reason = "..." },` per line inside its section.
pub fn deny_list(text: &str) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let mut section = "";
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with("disallowed-types") {
            section = "types";
        } else if line.starts_with("disallowed-methods") {
            section = "methods";
        } else if let Some(rest) = line.strip_prefix("{ path = \"") {
            let (path, rest) = rest.split_once('"').ok_or_else(|| {
                format!("clippy.toml: an entry line does not close its path: {line}")
            })?;
            let reason = rest
                .strip_prefix(", reason = \"")
                .and_then(|r| r.strip_suffix("\" },"))
                .filter(|reason| !reason.contains('"'))
                .ok_or_else(|| {
                    format!("clippy.toml: an entry line is not `{{ path = \"...\", reason = \"...\" }},`: {line}")
                })?;
            if section.is_empty() {
                return Err(format!("clippy.toml: an entry outside any section: {line}"));
            }
            out.push(Entry {
                section,
                path: path.to_string(),
                reason: reason.to_string(),
            });
        } else if line.contains("path") {
            return Err(format!(
                "clippy.toml: a line naming a path is not one entry per line: {line}"
            ));
        }
    }
    Ok(out)
}

/// The configurations a registry row holds in: every configuration in which its target is
/// checked (`*`), or the named ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Configs {
    Every,
    Named(BTreeSet<String>),
}

impl Configs {
    pub fn parse(text: &str, known: &[Config]) -> Result<Configs, String> {
        if text == "*" {
            return Ok(Configs::Every);
        }
        let mut set = BTreeSet::new();
        for name in text.split(',') {
            if !known.iter().any(|c| c.name == name) {
                return Err(format!(
                    "names configuration {name:?}, which deps.pin does not pin"
                ));
            }
            if !set.insert(name.to_string()) {
                return Err(format!("repeats configuration {name:?}"));
            }
        }
        Ok(Configs::Named(set))
    }

    pub fn holds(&self, config: &str, target_checked: bool) -> bool {
        match self {
            Configs::Every => target_checked,
            Configs::Named(set) => set.contains(config),
        }
    }

    pub fn render(&self) -> String {
        match self {
            Configs::Every => "*".to_string(),
            Configs::Named(set) => set.iter().cloned().collect::<Vec<_>>().join(","),
        }
    }
}

/// A registry row: its key fields, the configurations it holds in, its count and its review label.
#[derive(Clone, Debug)]
pub struct Row {
    pub key: Vec<String>,
    pub configs: Configs,
    pub count: usize,
    pub label: String,
}

/// A registry: `key_fields` key columns, then configs, count and label. `#` lines are comments.
pub fn read_rows(
    name: &str,
    text: &str,
    key_fields: usize,
    known: &[Config],
) -> Result<Vec<Row>, String> {
    let mut out: Vec<Row> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != key_fields + 3 {
            return Err(format!(
                "{name}:{} has {} fields, not {}",
                number + 1,
                fields.len(),
                key_fields + 3
            ));
        }
        let configs = Configs::parse(fields[key_fields], known)
            .map_err(|error| format!("{name}:{} {error}", number + 1))?;
        let count = fields[key_fields + 1]
            .parse()
            .map_err(|_| format!("{name}:{} has no count", number + 1))?;
        let label = fields[key_fields + 2].to_string();
        if label.trim().is_empty() || label == "LABEL" {
            return Err(format!("{name}:{} has no review label", number + 1));
        }
        out.push(Row {
            key: fields[..key_fields].iter().map(|f| f.to_string()).collect(),
            configs,
            count,
            label,
        });
    }
    Ok(out)
}

/// Rows with a fixed number of tab-separated fields (no configs/count): hand-outs, mints,
/// prefixes.
pub fn read_table(
    name: &str,
    text: &str,
    fields_wanted: usize,
) -> Result<Vec<Vec<String>>, String> {
    let mut out: Vec<Vec<String>> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<String> = line.split('\t').map(str::to_string).collect();
        if fields.len() != fields_wanted {
            return Err(format!(
                "{name}:{} has {} fields, not {fields_wanted}",
                number + 1,
                fields.len()
            ));
        }
        out.push(fields);
    }
    Ok(out)
}

pub fn read_file(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
}

/// The differences, in one configuration, between what was found (key -> count) and the rows
/// that hold there, both ways. `checked(key)` says whether the key's target was checked in this
/// configuration. Two rows holding for the same key in one configuration are a registry error.
pub fn compare(
    config: &str,
    found: &BTreeMap<Vec<String>, usize>,
    rows: &[Row],
    checked: &dyn Fn(&[String]) -> bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut expected: BTreeMap<&Vec<String>, usize> = BTreeMap::new();
    for row in rows {
        if row.configs.holds(config, checked(&row.key))
            && expected.insert(&row.key, row.count).is_some()
        {
            out.push(format!(
                "REGISTRY: two rows hold for one key in {config}: {}",
                row.key.join("\t")
            ));
        }
    }
    for (key, count) in found {
        match expected.get(key) {
            None => out.push(format!(
                "UNREGISTERED [{config}]: {} x{count}",
                key.join("\t")
            )),
            Some(want) if want != count => out.push(format!(
                "CHANGED [{config}]: {} x{count} (registered x{want})",
                key.join("\t")
            )),
            Some(_) => {}
        }
    }
    for (key, want) in &expected {
        if !found.contains_key(*key) {
            out.push(format!(
                "GONE [{config}] (registered x{want}, not found): {}",
                key.join("\t")
            ));
        }
    }
    out
}

/// The registry rows that describe `per_config` (config -> key -> count) exactly: one `*` row per
/// key found with one count in every configuration where its target is checked, otherwise one row
/// per distinct count naming its configurations.
pub fn rows_for(
    configs: &[Config],
    per_config: &BTreeMap<String, BTreeMap<Vec<String>, usize>>,
    checked: &dyn Fn(&str, &[String]) -> bool,
) -> Vec<(Vec<String>, Configs, usize)> {
    let mut keys: BTreeSet<&Vec<String>> = BTreeSet::new();
    for found in per_config.values() {
        keys.extend(found.keys());
    }
    let mut out = Vec::new();
    for key in keys {
        let mut by_count: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        let mut where_checked = BTreeSet::new();
        for config in configs {
            let Some(found) = per_config.get(&config.name) else {
                continue;
            };
            if checked(&config.name, key) {
                where_checked.insert(config.name.clone());
            }
            if let Some(count) = found.get(key) {
                by_count
                    .entry(*count)
                    .or_default()
                    .insert(config.name.clone());
            }
        }
        if by_count.len() == 1 {
            let (count, names) = by_count.iter().next().expect("one count");
            if *names == where_checked {
                out.push((key.clone(), Configs::Every, *count));
                continue;
            }
        }
        for (count, names) in by_count {
            out.push((key.clone(), Configs::Named(names), count));
        }
    }
    out
}
