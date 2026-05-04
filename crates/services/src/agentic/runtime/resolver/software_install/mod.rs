mod product_metadata;

use ioi_types::app::agentic::{
    HostDiscoverySnapshot, InstallSourceCandidate, ResolvedInstallPlan, SoftwareInstallRequestFrame,
};
use product_metadata::current_product_install_identity;
use std::env;
use std::process::Command;

const INSTALL_RESOLVER_FETCH_TIMEOUT_SECS: &str = "6";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedInstallTarget {
    pub display_name: String,
    pub canonical_id: String,
    pub target_kind: String,
    pub platform: String,
    pub architecture: String,
    pub source_kind: String,
    pub manager: String,
    pub package_id: String,
    pub installer_url: Option<String>,
    pub source_discovery_url: Option<String>,
    pub requires_elevation: bool,
    pub verification_command: Option<Vec<String>>,
    pub launch_target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InstallResolutionPlan {
    Resolved(ResolvedInstallTarget),
    Unsupported(ResolvedInstallTarget),
    Ambiguous {
        target_text: String,
        candidates: Vec<String>,
    },
    Unresolved(ResolvedInstallTarget),
}

pub(crate) trait HostDiscoveryProvider {
    fn snapshot(&self) -> HostDiscoverySnapshot;
}

pub(crate) trait PackageManagerProvider {
    fn exact_candidate(&self, manager: &str, package_id: &str) -> bool;
}

pub(crate) trait ProductMetadataProvider {
    fn current_product_target(&self, target_text: &str) -> Option<ResolvedInstallTarget>;
}

pub(crate) trait OfficialSourceProvider {
    fn official_source_url(&self, target_text: &str) -> Option<String>;
}

pub(crate) trait InstallHttpClient {
    fn fetch_text(&self, url: &str) -> Option<String>;
}

struct SystemHostDiscoveryProvider;
struct SystemPackageManagerProvider;
struct SystemProductMetadataProvider;
struct SystemOfficialSourceProvider;
struct SystemInstallHttpClient;

impl HostDiscoveryProvider for SystemHostDiscoveryProvider {
    fn snapshot(&self) -> HostDiscoverySnapshot {
        host_discovery_snapshot_from_system()
    }
}

impl PackageManagerProvider for SystemPackageManagerProvider {
    fn exact_candidate(&self, manager: &str, package_id: &str) -> bool {
        package_manager_has_exact_candidate_from_system(manager, package_id)
    }
}

impl ProductMetadataProvider for SystemProductMetadataProvider {
    fn current_product_target(&self, target_text: &str) -> Option<ResolvedInstallTarget> {
        current_product_target_from_metadata(target_text)
    }
}

impl OfficialSourceProvider for SystemOfficialSourceProvider {
    fn official_source_url(&self, target_text: &str) -> Option<String> {
        search_official_source_url_from_system(target_text)
    }
}

impl InstallHttpClient for SystemInstallHttpClient {
    fn fetch_text(&self, url: &str) -> Option<String> {
        fetch_text_with_system_tool_impl(url)
    }
}

pub(crate) fn supported_install_managers() -> &'static [&'static str] {
    &[
        "apt-get",
        "brew",
        "brew-cask",
        "pip",
        "npm",
        "pnpm",
        "cargo",
        "winget",
        "choco",
        "scoop",
        "yum",
        "dnf",
        "pacman",
        "zypper",
        "apk",
        "flatpak",
        "snap",
        "appimage",
        "manual",
        "self",
    ]
}

fn command_exists(command: &str) -> bool {
    let Some(paths) = env::var_os("PATH") else {
        return false;
    };
    let candidates = vec![
        command.to_string(),
        format!("{command}.exe"),
        format!("{command}.cmd"),
        format!("{command}.bat"),
    ];
    env::split_paths(&paths).any(|path| {
        candidates
            .iter()
            .map(|candidate| path.join(candidate))
            .any(|candidate| candidate.is_file())
    })
}

fn first_available_manager(candidates: &[&str], fallback: &str) -> String {
    candidates
        .iter()
        .copied()
        .find(|candidate| {
            let command = match *candidate {
                "brew-cask" => "brew",
                "apt-get" => "apt-get",
                other => other,
            };
            command_exists(command)
        })
        .unwrap_or(fallback)
        .to_string()
}

fn default_install_manager() -> String {
    match host_platform().as_str() {
        "macos" => first_available_manager(&["brew"], "brew"),
        "windows" => first_available_manager(&["winget", "choco", "scoop"], "winget"),
        _ => first_available_manager(
            &[
                "apt-get", "dnf", "yum", "pacman", "zypper", "apk", "flatpak", "snap",
            ],
            "apt-get",
        ),
    }
}

pub(crate) fn normalize_install_manager(raw: Option<&str>) -> String {
    let manager = raw
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(default_install_manager);
    match manager.as_str() {
        "auto" | "default" | "system" => default_install_manager(),
        "apt" | "apt-get" => "apt-get".to_string(),
        "brew" => "brew".to_string(),
        "cask" | "brew-cask" | "homebrew-cask" => "brew-cask".to_string(),
        "pip" | "pip3" => "pip".to_string(),
        "npm" => "npm".to_string(),
        "pnpm" => "pnpm".to_string(),
        "cargo" => "cargo".to_string(),
        "winget" => "winget".to_string(),
        "choco" | "chocolatey" => "choco".to_string(),
        "scoop" => "scoop".to_string(),
        "yum" => "yum".to_string(),
        "dnf" => "dnf".to_string(),
        "pacman" => "pacman".to_string(),
        "zypper" => "zypper".to_string(),
        "apk" => "apk".to_string(),
        "flatpak" => "flatpak".to_string(),
        "snap" => "snap".to_string(),
        "appimage" | "app-image" => "appimage".to_string(),
        "manual" | "official-installer" => "manual".to_string(),
        "self" => "self".to_string(),
        _ => manager,
    }
}

fn host_platform() -> String {
    if let Ok(output) = Command::new("uname").arg("-s").output() {
        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_ascii_lowercase();
            if value.contains("darwin") {
                return "macos".to_string();
            }
            if value.contains("linux") {
                return "linux".to_string();
            }
        }
    }
    for key in ["OS", "OSTYPE"] {
        if let Ok(value) = env::var(key) {
            let normalized = value.trim().to_ascii_lowercase();
            if normalized.contains("windows") {
                return "windows".to_string();
            }
            if normalized.contains("darwin") || normalized.contains("mac") {
                return "macos".to_string();
            }
            if normalized.contains("linux") {
                return "linux".to_string();
            }
        }
    }
    "unknown".to_string()
}

fn host_architecture() -> String {
    if let Ok(output) = Command::new("uname").arg("-m").output() {
        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                return value;
            }
        }
    }
    for key in ["PROCESSOR_ARCHITECTURE", "HOSTTYPE"] {
        if let Ok(value) = env::var(key) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return value;
            }
        }
    }
    "unknown".to_string()
}

pub(crate) fn host_discovery_snapshot() -> HostDiscoverySnapshot {
    SystemHostDiscoveryProvider.snapshot()
}

fn host_discovery_snapshot_from_system() -> HostDiscoverySnapshot {
    let available_managers = supported_install_managers()
        .iter()
        .filter_map(|manager| {
            let binary = match *manager {
                "brew-cask" => "brew",
                "manual" | "self" => return Some((*manager).to_string()),
                "appimage" => {
                    if command_exists("curl") || command_exists("wget") {
                        return Some((*manager).to_string());
                    }
                    return None;
                }
                other => other,
            };
            command_exists(binary).then(|| (*manager).to_string())
        })
        .collect();
    let elevation = if command_exists("sudo") {
        Some("sudo".to_string())
    } else {
        None
    };
    HostDiscoverySnapshot {
        platform: host_platform(),
        architecture: host_architecture(),
        available_managers,
        elevation,
    }
}

pub(crate) fn install_source_candidate_from_target(
    target: &ResolvedInstallTarget,
) -> InstallSourceCandidate {
    InstallSourceCandidate {
        source_kind: target.source_kind.clone(),
        manager: target.manager.clone(),
        package_id: target.package_id.clone(),
        installer_url: target.installer_url.clone(),
        source_discovery_url: target.source_discovery_url.clone(),
        provenance: target
            .source_discovery_url
            .as_deref()
            .unwrap_or("resolver_provider")
            .to_string(),
    }
}

pub(crate) fn target_from_resolved_plan(plan: &ResolvedInstallPlan) -> ResolvedInstallTarget {
    ResolvedInstallTarget {
        display_name: plan.display_name.clone(),
        canonical_id: plan.canonical_id.clone(),
        target_kind: plan.target_kind.clone(),
        platform: plan.host.platform.clone(),
        architecture: plan.host.architecture.clone(),
        source_kind: plan.source.source_kind.clone(),
        manager: plan.source.manager.clone(),
        package_id: plan.source.package_id.clone(),
        installer_url: plan.source.installer_url.clone(),
        source_discovery_url: plan.source.source_discovery_url.clone(),
        requires_elevation: plan.requires_elevation,
        verification_command: plan.verification_command.clone(),
        launch_target: plan.launch_target.clone(),
    }
}

fn canonical_package_key(package: &str) -> String {
    package
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn generic_resolved_target(package: &str, manager: String) -> ResolvedInstallTarget {
    ResolvedInstallTarget {
        display_name: package.to_string(),
        canonical_id: canonical_package_key(package),
        target_kind: "package".to_string(),
        platform: host_platform(),
        architecture: host_architecture(),
        source_kind: "package_manager".to_string(),
        requires_elevation: manager_requires_elevation(&manager),
        manager,
        package_id: package.to_string(),
        installer_url: None,
        source_discovery_url: None,
        verification_command: None,
        launch_target: None,
    }
}

fn unknown_resolved_target(package: &str) -> ResolvedInstallTarget {
    ResolvedInstallTarget {
        display_name: package.to_string(),
        canonical_id: canonical_package_key(package),
        target_kind: "unknown".to_string(),
        platform: host_platform(),
        architecture: host_architecture(),
        source_kind: "unresolved".to_string(),
        requires_elevation: false,
        manager: String::new(),
        package_id: String::new(),
        installer_url: None,
        source_discovery_url: None,
        verification_command: None,
        launch_target: None,
    }
}

fn current_product_target(package: &str) -> Option<ResolvedInstallTarget> {
    SystemProductMetadataProvider.current_product_target(package)
}

fn current_product_target_from_metadata(package: &str) -> Option<ResolvedInstallTarget> {
    let key = canonical_package_key(package);
    let identity = current_product_install_identity();
    if !identity
        .aliases
        .iter()
        .any(|alias| canonical_package_key(alias) == key)
    {
        return None;
    }
    Some(ResolvedInstallTarget {
        display_name: identity.display_name.clone(),
        canonical_id: identity.canonical_id.clone(),
        target_kind: "current_product".to_string(),
        platform: host_platform(),
        architecture: host_architecture(),
        source_kind: "current_app".to_string(),
        manager: "self".to_string(),
        package_id: identity.canonical_id,
        installer_url: None,
        source_discovery_url: None,
        requires_elevation: false,
        verification_command: None,
        launch_target: Some(identity.display_name),
    })
}

fn slugify_package_id(target: &str, separator: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in target.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push_str(separator);
            last_was_sep = true;
        }
    }
    out.trim_matches(|ch| separator.contains(ch)).to_string()
}

fn manager_package_id_for_target(target: &str, manager: &str) -> String {
    match manager {
        "npm" => target.trim().to_string(),
        "pip" | "cargo" | "pnpm" => slugify_package_id(target, "-"),
        "brew-cask" => slugify_package_id(target, "-"),
        "flatpak" => target.trim().to_string(),
        "winget" | "choco" | "scoop" => target.trim().to_string(),
        _ => slugify_package_id(target, "-"),
    }
}

fn inferred_verification_command(
    package_id: &str,
    target_kind: Option<&str>,
) -> Option<Vec<String>> {
    if matches!(target_kind, Some("desktop_app" | "editor_extension")) {
        return None;
    }
    let binary = package_id
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(package_id)
        .trim()
        .to_string();
    if binary.is_empty() {
        None
    } else {
        Some(vec![binary, "--version".to_string()])
    }
}

fn explicit_manager_target(
    request: &SoftwareInstallRequestFrame,
    manager: String,
) -> ResolvedInstallTarget {
    let package_id = manager_package_id_for_target(&request.target_text, &manager);
    let mut target = generic_resolved_target(&package_id, manager);
    target.display_name = request.target_text.trim().to_string();
    target.target_kind = request
        .target_kind
        .clone()
        .unwrap_or_else(|| "package".to_string());
    target.verification_command =
        inferred_verification_command(&target.package_id, request.target_kind.as_deref());
    target
}

fn auto_discovery_managers_for_host() -> Vec<&'static str> {
    match host_platform().as_str() {
        "macos" => vec!["brew", "brew-cask"],
        "windows" => vec!["winget", "choco", "scoop"],
        _ => vec![
            "apt-get", "dnf", "yum", "pacman", "zypper", "apk", "flatpak", "snap",
        ],
    }
}

fn manager_probe_binary(manager: &str) -> &str {
    match manager {
        "apt-get" => "apt-cache",
        "brew-cask" => "brew",
        other => other,
    }
}

fn manager_exact_probe(manager: &str, package_id: &str) -> Option<(String, Vec<String>)> {
    let pkg = package_id.trim();
    if pkg.is_empty() {
        return None;
    }
    let args = match manager {
        "apt-get" => vec![
            "show".to_string(),
            "--no-all-versions".to_string(),
            pkg.to_string(),
        ],
        "dnf" | "yum" => vec!["info".to_string(), pkg.to_string()],
        "pacman" => vec!["-Si".to_string(), pkg.to_string()],
        "zypper" => vec!["info".to_string(), pkg.to_string()],
        "apk" => vec!["info".to_string(), "-a".to_string(), pkg.to_string()],
        "flatpak" => vec![
            "remote-info".to_string(),
            "flathub".to_string(),
            pkg.to_string(),
        ],
        "snap" => vec!["info".to_string(), pkg.to_string()],
        "brew" => vec!["info".to_string(), "--formula".to_string(), pkg.to_string()],
        "brew-cask" => vec!["info".to_string(), "--cask".to_string(), pkg.to_string()],
        "winget" => vec![
            "search".to_string(),
            "--exact".to_string(),
            "--id".to_string(),
            pkg.to_string(),
        ],
        "choco" => vec!["search".to_string(), "--exact".to_string(), pkg.to_string()],
        "scoop" => vec!["search".to_string(), pkg.to_string()],
        _ => return None,
    };
    Some((manager_probe_binary(manager).to_string(), args))
}

fn package_manager_has_exact_candidate(manager: &str, package_id: &str) -> bool {
    SystemPackageManagerProvider.exact_candidate(manager, package_id)
}

fn package_manager_has_exact_candidate_from_system(manager: &str, package_id: &str) -> bool {
    let Some((binary, args)) = manager_exact_probe(manager, package_id) else {
        return false;
    };
    if !command_exists(&binary) {
        return false;
    }
    Command::new(binary)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some()
}

fn package_id_candidates_for_auto(target: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    for candidate in [
        target.trim().to_string(),
        slugify_package_id(target, "-"),
        slugify_package_id(target, ""),
    ] {
        let candidate = candidate.trim().to_string();
        if candidate.is_empty() || candidates.iter().any(|seen| seen == &candidate) {
            continue;
        }
        candidates.push(candidate);
    }
    candidates
}

fn discover_package_manager_candidates(
    request: &SoftwareInstallRequestFrame,
) -> Vec<ResolvedInstallTarget> {
    let mut candidates = Vec::new();
    for manager in auto_discovery_managers_for_host() {
        for package_id in package_id_candidates_for_auto(&request.target_text) {
            if !package_manager_has_exact_candidate(manager, &package_id) {
                continue;
            }
            let mut target = generic_resolved_target(&package_id, manager.to_string());
            target.display_name = request.target_text.trim().to_string();
            target.target_kind = request
                .target_kind
                .clone()
                .unwrap_or_else(|| "package".to_string());
            target.verification_command =
                inferred_verification_command(&target.package_id, request.target_kind.as_deref());
            candidates.push(target);
        }
    }
    candidates
}

fn fetch_text_with_system_tool(url: &str) -> Option<String> {
    SystemInstallHttpClient.fetch_text(url)
}

fn fetch_text_with_system_tool_impl(url: &str) -> Option<String> {
    let output = if command_exists("curl") {
        Command::new("curl")
            .args([
                "-fsSL",
                "--compressed",
                "--max-time",
                INSTALL_RESOLVER_FETCH_TIMEOUT_SECS,
                "-A",
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) AutopilotInstallResolver/1.0",
                "-H",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "-H",
                "Accept-Language: en-US,en;q=0.9",
                url,
            ])
            .output()
            .ok()?
    } else if command_exists("wget") {
        Command::new("wget")
            .args([
                "-qO-",
                "--timeout=6",
                "--user-agent=Mozilla/5.0 AppleWebKit/537.36 AutopilotInstallResolver/1.0",
                "--header=Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "--header=Accept-Language: en-US,en;q=0.9",
                url,
            ])
            .output()
            .ok()?
    } else {
        return None;
    };
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).to_string())
}

fn compact_target_tokens(target: &str) -> Vec<String> {
    target
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|term| term.len() > 1)
        .map(|term| term.to_ascii_lowercase())
        .collect()
}

fn html_entity_decode_basic(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn query_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|seen| seen == &value) {
        values.push(value);
    }
}

fn url_from_candidate(raw: &str, base_url: &str) -> Option<String> {
    let decoded = html_entity_decode_basic(raw.trim());
    if decoded.is_empty() || decoded.starts_with('#') || decoded.starts_with("javascript:") {
        return None;
    }

    let absolute = if decoded.starts_with("//") {
        format!("https:{decoded}")
    } else if decoded.starts_with('/') {
        let base = url::Url::parse(base_url).ok()?;
        base.join(&decoded).ok()?.to_string()
    } else {
        decoded
    };

    let parsed = url::Url::parse(&absolute).ok()?;
    if parsed
        .host_str()
        .unwrap_or_default()
        .contains("duckduckgo.com")
    {
        if let Some((_, uddg)) = parsed.query_pairs().find(|(key, _)| key == "uddg") {
            return Some(uddg.into_owned());
        }
    }

    Some(parsed.to_string())
}

fn extract_links_from_text(text: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();
    for token in text.split(['"', '\'', '<', '>', ' ', '\n', '\r', '\t', '(', ')', ',']) {
        let Some(url) = url_from_candidate(token, base_url) else {
            continue;
        };
        push_unique(&mut links, url);
    }

    for marker in ["href=", "src=", "url=", "downloadUrl"] {
        let mut rest = text;
        while let Some((_, after_marker)) = rest.split_once(marker) {
            let trimmed = after_marker.trim_start_matches([' ', ':', '=']);
            let quote = trimmed.chars().next().unwrap_or_default();
            if matches!(quote, '"' | '\'') {
                if let Some(end) = trimmed[1..].find(quote) {
                    if let Some(url) = url_from_candidate(&trimmed[1..1 + end], base_url) {
                        push_unique(&mut links, url);
                    }
                    rest = &trimmed[1 + end..];
                    continue;
                }
            }
            rest = trimmed;
        }
    }

    links
}

fn is_search_or_asset_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return true;
    };
    let host = parsed.host_str().unwrap_or_default();
    if [
        "duckduckgo.com",
        "bing.com",
        "google.com",
        "brave.com",
        "yahoo.com",
        "w3.org",
    ]
    .iter()
    .any(|blocked| host.ends_with(blocked))
    {
        return true;
    }
    let path = parsed.path().to_ascii_lowercase();
    path.ends_with(".css")
        || path.ends_with(".js")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".gif")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
}

fn url_matches_target(url: &str, target: &str) -> bool {
    let compact_target = canonical_package_key(target);
    if compact_target.is_empty() {
        return false;
    }
    let compact_url = canonical_package_key(url);
    if compact_url.contains(&compact_target) {
        return true;
    }
    let tokens = compact_target_tokens(target);
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|token| compact_url.contains(&canonical_package_key(token)))
}

fn source_page_matches_target(target: &str, source_url: &str, html: &str) -> bool {
    if !url_matches_target(source_url, target) && !url_matches_target(html, target) {
        return false;
    }
    let lower = html.to_ascii_lowercase();
    lower.contains("softwareapplication")
        || lower.contains("downloadurl")
        || lower.contains("download")
        || lower.contains("appimage")
        || lower.contains("installer")
}

fn query_derived_source_candidates(target: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let compact = canonical_package_key(target);
    let dashed = slugify_package_id(target, "-");
    for stem in [compact, dashed] {
        if stem.is_empty() {
            continue;
        }
        for tld in ["com", "ai", "app", "dev", "io", "org", "net"] {
            let origin = format!("https://{stem}.{tld}");
            push_unique(&mut candidates, format!("{origin}/download"));
            push_unique(&mut candidates, format!("{origin}/downloads"));
            push_unique(&mut candidates, origin);
        }
    }
    candidates
}

fn search_engine_source_candidates(target: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let queries = [
        format!("{target} official download"),
        format!("\"{target}\" official download"),
    ];
    for query in queries {
        let encoded = query_encode(&query);
        for endpoint in [
            format!("https://duckduckgo.com/html/?q={encoded}"),
            format!("https://lite.duckduckgo.com/lite/?q={encoded}"),
            format!("https://www.bing.com/search?format=rss&q={encoded}"),
        ] {
            let Some(html) = fetch_text_with_system_tool(&endpoint) else {
                continue;
            };
            for link in extract_links_from_text(&html, &endpoint) {
                if is_search_or_asset_url(&link) || !url_matches_target(&link, target) {
                    continue;
                }
                push_unique(&mut candidates, link);
            }
        }
    }
    candidates
}

fn search_official_source_url(target: &str) -> Option<String> {
    SystemOfficialSourceProvider.official_source_url(target)
}

fn search_official_source_url_from_system(target: &str) -> Option<String> {
    let mut candidates = query_derived_source_candidates(target);
    for candidate in search_engine_source_candidates(target) {
        push_unique(&mut candidates, candidate);
    }

    for candidate in candidates.into_iter().take(48) {
        if is_search_or_asset_url(&candidate) {
            continue;
        }
        let Some(html) = fetch_text_with_system_tool(&candidate) else {
            continue;
        };
        if source_page_matches_target(target, &candidate, &html) {
            return Some(candidate);
        }
    }

    None
}

fn appimage_installer_url_from_html(source_url: &str, source_html: &str) -> Option<String> {
    let normalized = source_html.replace(['\\', '\n', '\r'], "");
    for link in extract_links_from_text(&normalized, source_url) {
        if link.contains(".AppImage") {
            return Some(link);
        }
    }

    let origin = url::Url::parse(source_url).ok()?;
    let origin = format!(
        "{}://{}",
        origin.scheme(),
        origin.host_str().unwrap_or_default()
    );
    let route_prefix = normalized
        .split('"')
        .find(|part| part.starts_with("/download/") && part.ends_with('/'))?;
    Some(format!(
        "{}{}linux/{}?format=AppImage",
        origin,
        route_prefix,
        download_artifact_architecture(&host_architecture())
    ))
}

fn internal_download_pages(source_url: &str, source_html: &str) -> Vec<String> {
    extract_links_from_text(source_html, source_url)
        .into_iter()
        .filter(|link| {
            let same_origin = match (url::Url::parse(source_url), url::Url::parse(link)) {
                (Ok(source), Ok(candidate)) => source.host_str() == candidate.host_str(),
                _ => false,
            };
            same_origin && link.to_ascii_lowercase().contains("download")
        })
        .collect()
}

fn discover_appimage_candidate(target: &str, source_url: &str) -> Option<ResolvedInstallTarget> {
    let source_html = fetch_text_with_system_tool(source_url)?;
    let installer_url =
        appimage_installer_url_from_html(source_url, &source_html).or_else(|| {
            for download_page in internal_download_pages(source_url, &source_html) {
                let Some(download_html) = fetch_text_with_system_tool(&download_page) else {
                    continue;
                };
                if let Some(url) = appimage_installer_url_from_html(&download_page, &download_html)
                {
                    return Some(url);
                }
            }
            None
        })?;
    let display_name = target.trim().to_string();
    let canonical_id = slugify_package_id(&display_name, "-");
    let appimage_name = format!(
        "{}.AppImage",
        display_name
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("-")
    );
    Some(ResolvedInstallTarget {
        display_name: display_name.clone(),
        canonical_id,
        target_kind: "desktop_app".to_string(),
        platform: host_platform(),
        architecture: host_architecture(),
        source_kind: "appimage".to_string(),
        manager: "appimage".to_string(),
        package_id: appimage_name,
        installer_url: Some(installer_url),
        source_discovery_url: Some(source_url.to_string()),
        requires_elevation: false,
        verification_command: Some(vec![
            "sh".to_string(),
            "-lc".to_string(),
            format!(
                "test -x \"$HOME/.local/bin/{}\" || test -x \"$HOME/.local/bin/{}\"",
                display_name
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join("-")
                    + ".AppImage",
                slugify_package_id(&display_name, "-")
            ),
        ]),
        launch_target: Some(display_name),
    })
}

pub(crate) fn resolve_install_plan_for_request(
    request: &SoftwareInstallRequestFrame,
) -> Result<InstallResolutionPlan, String> {
    let target_text = request.target_text.trim();
    if target_text.is_empty() {
        return Err(
            "ERROR_CLASS=MissingDependency Software install target cannot be empty.".to_string(),
        );
    }
    let requested_manager = request.manager_preference.as_deref();
    let manager_was_auto = requested_manager
        .map(|manager| manager.trim().to_ascii_lowercase())
        .filter(|manager| !manager.is_empty())
        .map(|manager| matches!(manager.as_str(), "auto" | "default" | "system"))
        .unwrap_or(true);
    let manager = normalize_install_manager(requested_manager);
    if !supported_install_managers().contains(&manager.as_str()) {
        return Err(format!(
            "ERROR_CLASS=ToolUnavailable Unsupported package manager '{}'. Supported managers: {}.",
            manager,
            supported_install_managers().join(", ")
        ));
    }

    if let Some(target) = current_product_target(target_text) {
        return Ok(InstallResolutionPlan::Unsupported(target));
    }

    if !manager_was_auto {
        return Ok(InstallResolutionPlan::Resolved(explicit_manager_target(
            request, manager,
        )));
    }

    let package_manager_candidates = discover_package_manager_candidates(request);
    if package_manager_candidates.len() == 1 {
        return Ok(InstallResolutionPlan::Resolved(
            package_manager_candidates
                .into_iter()
                .next()
                .expect("len checked"),
        ));
    }
    if package_manager_candidates.len() > 1 {
        return Ok(InstallResolutionPlan::Ambiguous {
            target_text: target_text.to_string(),
            candidates: package_manager_candidates
                .into_iter()
                .map(|target| format!("{} via {}", target.package_id, target.manager))
                .collect(),
        });
    }

    if host_platform() == "linux" {
        if let Some(source_url) = search_official_source_url(target_text) {
            if let Some(target) = discover_appimage_candidate(target_text, &source_url) {
                return Ok(InstallResolutionPlan::Resolved(target));
            }
        }
    }

    Ok(InstallResolutionPlan::Unresolved(unknown_resolved_target(
        target_text,
    )))
}

#[cfg(test)]
pub(crate) fn resolve_install_target(
    package: &str,
    requested_manager: Option<&str>,
) -> Result<ResolvedInstallTarget, String> {
    let request = SoftwareInstallRequestFrame {
        target_text: package.to_string(),
        target_kind: None,
        manager_preference: requested_manager.map(str::to_string),
        launch_after_install: None,
        provenance: Some("test".to_string()),
    };
    match resolve_install_plan_for_request(&request)? {
        InstallResolutionPlan::Resolved(target)
        | InstallResolutionPlan::Unsupported(target)
        | InstallResolutionPlan::Unresolved(target) => Ok(target),
        InstallResolutionPlan::Ambiguous {
            target_text,
            candidates,
        } => Err(format!(
            "ERROR_CLASS=InstallerResolutionRequired Install target '{}' is ambiguous. Candidates: {}.",
            target_text,
            candidates.join(", ")
        )),
    }
}

fn manager_requires_elevation(manager: &str) -> bool {
    matches!(
        manager,
        "apt-get" | "yum" | "dnf" | "pacman" | "zypper" | "apk" | "snap"
    )
}

fn download_artifact_architecture(architecture: &str) -> String {
    match architecture {
        "x86_64" | "amd64" => "x64".to_string(),
        "aarch64" => "arm64".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_decodes_search_redirect_links_without_app_specific_targets() {
        let html = r#"
            <a class="result__a" href="/l/?kh=-1&amp;uddg=https%3A%2F%2Facmestudio.ai%2Fdownload">Download</a>
            <a href="https://duckduckgo.com/y.js">asset</a>
        "#;
        let links = extract_links_from_text(html, "https://duckduckgo.com/html/?q=acme+studio");

        assert!(links.contains(&"https://acmestudio.ai/download".to_string()));
        assert!(links
            .iter()
            .any(|link| url_matches_target(link, "acme studio")));
    }

    #[test]
    fn provider_extracts_download_script_links_without_app_specific_targets() {
        let html = r#"
            <script src="/_next/static/chunks/app/(dynamic)/download/page.js"></script>
        "#;
        let links = extract_links_from_text(html, "https://acmestudio.ai/download");

        assert!(links.contains(
            &"https://acmestudio.ai/_next/static/chunks/app/(dynamic)/download/page.js".to_string()
        ));
    }

    #[test]
    fn provider_derives_appimage_download_route_from_download_script() {
        let script = r#"
            function build(B,P){return "/download/latest/".concat(B,"/").concat(P)}
            params.set("format","AppImage");
        "#;
        let installer = appimage_installer_url_from_html(
            "https://acmestudio.ai/_next/static/chunks/app/(dynamic)/download/page.js",
            script,
        )
        .expect("appimage route from script");

        assert!(installer.starts_with("https://acmestudio.ai/download/latest/linux/"));
        assert!(installer.ends_with("?format=AppImage"));
    }

    #[test]
    fn provider_derives_appimage_download_route_from_official_page_metadata() {
        let html = r#"
            <script>
                let href = "/download/latest/".concat(os, "/").concat(arch) + "?format=AppImage";
            </script>
            <script type="application/ld+json">
                {"@type":"SoftwareApplication","name":"Acme Studio","downloadUrl":"https://acmestudio.ai/download"}
            </script>
        "#;

        assert!(source_page_matches_target(
            "acme studio",
            "https://acmestudio.ai/download",
            html
        ));
        let installer = appimage_installer_url_from_html("https://acmestudio.ai/download", html)
            .expect("appimage route");

        assert!(installer.starts_with("https://acmestudio.ai/download/latest/linux/"));
        assert!(installer.ends_with("?format=AppImage"));
    }

    #[test]
    fn provider_extracts_direct_appimage_link_from_download_page() {
        let html = r#"
            <a href="https://downloads.example.dev/releases/Acme-Studio-x64.AppImage">AppImage</a>
        "#;
        let installer = appimage_installer_url_from_html("https://acmestudio.ai/download", html)
            .expect("direct appimage");

        assert_eq!(
            installer,
            "https://downloads.example.dev/releases/Acme-Studio-x64.AppImage"
        );
    }
}
