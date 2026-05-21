use super::*;

pub(crate) fn env_text(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn string_value(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

pub(crate) fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .collect()
}

pub(crate) fn supported_remote_uri(raw: &str) -> Option<Url> {
    let url = Url::parse(raw.trim()).ok()?;
    match url.scheme() {
        "http" | "https" | "file" => Some(url),
        _ => None,
    }
}

pub(crate) fn normalized_location_text(raw: &str) -> String {
    let trimmed = raw.trim();
    if supported_remote_uri(trimmed).is_some() {
        return trimmed.to_string();
    }
    slash_path(Path::new(trimmed))
}

pub(crate) fn local_path_from_supported_uri(
    url: &Url,
    source: &str,
) -> Result<Option<PathBuf>, String> {
    if url.scheme() != "file" {
        return Ok(None);
    }
    url.to_file_path()
        .map(Some)
        .map_err(|_| format!("Failed to decode {} file URL '{}'.", source, url))
}

pub(crate) fn remote_text_client() -> Result<Client, String> {
    Client::builder()
        .redirect(RedirectPolicy::limited(5))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| format!("Failed to create marketplace HTTP client: {error}"))
}

pub(crate) fn read_text_from_location(location: &str, source: &str) -> Result<String, String> {
    if let Some(url) = supported_remote_uri(location) {
        if let Some(path) = local_path_from_supported_uri(&url, source)? {
            return fs::read_to_string(&path).map_err(|error| {
                format!("Failed to read {} ({}): {}", source, path.display(), error)
            });
        }
        let client = remote_text_client()?;
        let response = client
            .get(url.clone())
            .send()
            .map_err(|error| format!("Failed to fetch {} ({}): {}", source, url, error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "Failed to fetch {} ({}): HTTP {}.",
                source,
                url,
                status.as_u16()
            ));
        }
        return response.text().map_err(|error| {
            format!(
                "Failed to read {} response body ({}): {}",
                source, url, error
            )
        });
    }

    fs::read_to_string(location)
        .map_err(|error| format!("Failed to read {} ({}): {}", source, location, error))
}

pub(crate) fn read_bytes_from_location(location: &str, source: &str) -> Result<Vec<u8>, String> {
    if let Some(url) = supported_remote_uri(location) {
        if let Some(path) = local_path_from_supported_uri(&url, source)? {
            return fs::read(&path).map_err(|error| {
                format!("Failed to read {} ({}): {}", source, path.display(), error)
            });
        }
        let client = remote_text_client()?;
        let response = client
            .get(url.clone())
            .send()
            .map_err(|error| format!("Failed to fetch {} ({}): {}", source, url, error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "Failed to fetch {} ({}): HTTP {}.",
                source,
                url,
                status.as_u16()
            ));
        }
        return response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|error| {
                format!(
                    "Failed to read {} response bytes ({}): {}",
                    source, url, error
                )
            });
    }

    fs::read(location)
        .map_err(|error| format!("Failed to read {} ({}): {}", source, location, error))
}

pub(crate) fn normalize_sha256_hex(raw: &str, source: &str) -> Result<String, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    let normalized = normalized
        .strip_prefix("sha256:")
        .unwrap_or(normalized.as_str());
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "Invalid sha256 value for {}. Expected 64 hex characters.",
            source
        ));
    }
    Ok(normalized.to_string())
}

pub(crate) fn decode_signature_material(raw: &str, source: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{} is empty.", source));
    }
    if trimmed.len() % 2 == 0 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex::decode(trimmed)
            .map_err(|error| format!("Failed to decode {} as hex: {}", source, error));
    }
    BASE64_STANDARD
        .decode(trimmed)
        .map_err(|error| format!("Failed to decode {} as base64: {}", source, error))
}

pub(crate) fn collect_plugin_package_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(current)
        .map_err(|error| format!("Failed to read {}: {}", current.display(), error))?;
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();

    for path in paths {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if path.is_dir() {
            if IGNORED_PACKAGE_COPY_DIRS.contains(&file_name) {
                continue;
            }
            collect_plugin_package_files(root, &path, files)?;
            continue;
        }
        if path.is_file() {
            let relative = path.strip_prefix(root).map_err(|error| {
                format!(
                    "Failed to derive a relative package path for {}: {}",
                    path.display(),
                    error
                )
            })?;
            files.push(relative.to_path_buf());
        }
    }

    Ok(())
}

pub(crate) fn compute_plugin_package_digest_sha256(source_root: &Path) -> Result<String, String> {
    let mut relative_files = Vec::new();
    collect_plugin_package_files(source_root, source_root, &mut relative_files)?;
    relative_files.sort_by(|left, right| slash_path(left).cmp(&slash_path(right)));

    let mut preimage = Vec::new();
    for relative_path in relative_files {
        let absolute_path = source_root.join(&relative_path);
        let bytes = fs::read(&absolute_path)
            .map_err(|error| format!("Failed to read {}: {}", absolute_path.display(), error))?;
        let relative_text = slash_path(&relative_path);
        preimage.extend_from_slice(b"FILE\n");
        preimage.extend_from_slice(relative_text.as_bytes());
        preimage.extend_from_slice(b"\nSIZE\n");
        preimage.extend_from_slice(bytes.len().to_string().as_bytes());
        preimage.extend_from_slice(b"\nDATA\n");
        preimage.extend_from_slice(&bytes);
        preimage.extend_from_slice(b"\nEND\n");
    }

    sha256(&preimage).map(hex::encode).map_err(|error| {
        format!(
            "Failed to compute sha256 package digest for {}: {}",
            source_root.display(),
            error
        )
    })
}

pub(crate) fn extract_plugin_archive(bytes: &[u8], destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|error| format!("Failed to create {}: {}", destination.display(), error))?;
    let cursor = Cursor::new(bytes.to_vec());
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|error| format!("Failed to open plugin package archive: {}", error))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("Failed to read plugin package archive entry: {}", error))?;
        let Some(enclosed_path) = entry.enclosed_name().map(PathBuf::from) else {
            return Err("Plugin package archive contains an unsafe entry path.".to_string());
        };
        let output_path = destination.join(&enclosed_path);
        if entry.is_dir() {
            fs::create_dir_all(&output_path).map_err(|error| {
                format!("Failed to create {}: {}", output_path.display(), error)
            })?;
            continue;
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Failed to create {}: {}", parent.display(), error))?;
        }
        let mut output = fs::File::create(&output_path)
            .map_err(|error| format!("Failed to create {}: {}", output_path.display(), error))?;
        let mut buffer = Vec::new();
        entry.read_to_end(&mut buffer).map_err(|error| {
            format!(
                "Failed to read archive entry '{}': {}",
                enclosed_path.display(),
                error
            )
        })?;
        output
            .write_all(&buffer)
            .map_err(|error| format!("Failed to write {}: {}", output_path.display(), error))?;
    }
    Ok(())
}

pub(crate) fn discovered_plugin_roots(
    root: &Path,
    matches: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if root.join(".codex-plugin/plugin.json").exists() {
        matches.push(root.to_path_buf());
    }
    let entries = fs::read_dir(root)
        .map_err(|error| format!("Failed to read {}: {}", root.display(), error))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if IGNORED_PACKAGE_COPY_DIRS
            .iter()
            .any(|ignored| ignored == &name)
        {
            continue;
        }
        discovered_plugin_roots(&path, matches)?;
    }
    Ok(())
}

pub(crate) fn find_plugin_root_in_extracted_archive(root: &Path) -> Result<PathBuf, String> {
    let mut matches = Vec::new();
    discovered_plugin_roots(root, &mut matches)?;
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [match_root] => Ok(match_root.clone()),
        [] => Err("Plugin package archive does not contain '.codex-plugin/plugin.json'.".to_string()),
        _ => Err("Plugin package archive contains multiple plugin roots and cannot be installed deterministically.".to_string()),
    }
}

pub(crate) fn with_extracted_plugin_archive<T>(
    archive_location: &str,
    source: &str,
    handler: impl FnOnce(&Path) -> Result<T, String>,
) -> Result<T, String> {
    let archive_bytes = read_bytes_from_location(archive_location, source)?;
    let staging_root =
        env::temp_dir().join(format!("autopilot-plugin-archive-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        extract_plugin_archive(&archive_bytes, &staging_root)?;
        let plugin_root = find_plugin_root_in_extracted_archive(&staging_root)?;
        handler(&plugin_root)
    })();
    let _ = fs::remove_dir_all(&staging_root);
    result
}

pub(crate) fn compute_plugin_package_digest_sha256_from_archive(
    archive_location: &str,
) -> Result<String, String> {
    with_extracted_plugin_archive(
        archive_location,
        "plugin marketplace package archive",
        compute_plugin_package_digest_sha256,
    )
}
