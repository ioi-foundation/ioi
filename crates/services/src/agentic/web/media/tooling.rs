fn media_tool_home() -> PathBuf {
    if let Ok(raw) = std::env::var(MEDIA_TOOL_HOME_ENV) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed)
                .join(".cache")
                .join("ioi")
                .join("media_tooling");
        }
    }

    std::env::temp_dir().join("ioi_media_tooling")
}

async fn ensure_managed_ytdlp_provider(tool_home: &Path) -> Result<ManagedYtDlpProvider> {
    let asset_name = select_ytdlp_asset_name()?;
    let expected_sha = fetch_expected_ytdlp_sha(asset_name).await?;
    let binary_dir = tool_home.join("bin");
    fs::create_dir_all(&binary_dir)?;
    let binary_path = binary_dir.join(asset_name);

    let needs_download = fs::read(&binary_path)
        .map(|bytes| sha256_hex(&bytes) != expected_sha)
        .unwrap_or(true);
    if needs_download {
        let asset_url = format!(
            "https://github.com/yt-dlp/yt-dlp/releases/download/{}/{}",
            YTDLP_PROVIDER_VERSION, asset_name
        );
        let client = reqwest::Client::builder()
            .redirect(redirect::Policy::limited(5))
            .timeout(Duration::from_secs(45))
            .build()
            .context("ERROR_CLASS=SynthesisFailed failed to initialize yt-dlp download client")?;
        let bytes = client
            .get(asset_url)
            .send()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to download yt-dlp asset")?
            .error_for_status()
            .context("ERROR_CLASS=SynthesisFailed yt-dlp asset request returned error status")?
            .bytes()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to read yt-dlp asset bytes")?;
        let observed_sha = sha256_hex(&bytes);
        if observed_sha != expected_sha {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing managed yt-dlp checksum mismatch expected={} observed={}",
                expected_sha,
                observed_sha
            ));
        }
        persist_downloaded_asset(&binary_path, &bytes, true)?;
    }

    Ok(ManagedYtDlpProvider {
        binary_path,
        asset_name,
        version: YTDLP_PROVIDER_VERSION,
    })
}

async fn ensure_managed_ffmpeg_provider(tool_home: &Path) -> Result<ManagedFfmpegProvider> {
    let asset = select_ffmpeg_asset()?;
    let expected_sha = fetch_expected_ffmpeg_sha(asset.asset_name).await?;
    let provider_root = tool_home.join("ffmpeg").join(FFMPEG_PROVIDER_VERSION);
    let archive_path = provider_root.join(asset.asset_name);
    let extract_root = provider_root.join("extract");
    let checksum_pin = provider_root.join("sha256.pin");
    let mut needs_download = true;
    if let Ok(bytes) = fs::read(&archive_path) {
        needs_download = sha256_hex(&bytes) != expected_sha;
    }
    fs::create_dir_all(&provider_root)?;
    if needs_download {
        let asset_url = format!(
            "https://github.com/BtbN/FFmpeg-Builds/releases/download/{}/{}",
            FFMPEG_PROVIDER_VERSION, asset.asset_name
        );
        let client = reqwest::Client::builder()
            .redirect(redirect::Policy::limited(5))
            .timeout(Duration::from_secs(FFMPEG_DOWNLOAD_TIMEOUT_SECS))
            .build()
            .context("ERROR_CLASS=SynthesisFailed failed to initialize ffmpeg download client")?;
        let bytes = client
            .get(asset_url)
            .send()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to download ffmpeg asset")?
            .error_for_status()
            .context("ERROR_CLASS=SynthesisFailed ffmpeg asset request returned error status")?
            .bytes()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to read ffmpeg asset bytes")?;
        let observed_sha = sha256_hex(&bytes);
        if observed_sha != expected_sha {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing managed ffmpeg checksum mismatch expected={} observed={}",
                expected_sha,
                observed_sha
            ));
        }
        persist_downloaded_asset(&archive_path, &bytes, false)?;
        if extract_root.exists() {
            fs::remove_dir_all(&extract_root)?;
        }
    }

    let pin_matches = fs::read_to_string(&checksum_pin)
        .ok()
        .map(|raw| raw.trim().eq_ignore_ascii_case(&expected_sha))
        .unwrap_or(false);
    let binaries_ready = locate_ffmpeg_binary(&extract_root, "ffmpeg").and_then(|ffmpeg_path| {
        locate_ffmpeg_binary(&extract_root, "ffprobe")
            .map(|ffprobe_path| (ffmpeg_path, ffprobe_path))
    });

    let (ffmpeg_path, ffprobe_path) = if pin_matches {
        binaries_ready.ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing managed ffmpeg extraction missing binaries under {}",
                extract_root.display()
            )
        })?
    } else {
        if extract_root.exists() {
            fs::remove_dir_all(&extract_root)?;
        }
        fs::create_dir_all(&extract_root)?;
        extract_ffmpeg_archive(&archive_path, &extract_root, asset.archive_kind)?;
        let ffmpeg_path = locate_ffmpeg_binary(&extract_root, "ffmpeg").ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing extracted ffmpeg archive did not contain ffmpeg binary."
            )
        })?;
        let ffprobe_path = locate_ffmpeg_binary(&extract_root, "ffprobe").ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing extracted ffmpeg archive did not contain ffprobe binary."
            )
        })?;
        fs::write(&checksum_pin, format!("{}\n", expected_sha)).with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to write ffmpeg checksum pin {}",
                checksum_pin.display()
            )
        })?;
        (ffmpeg_path, ffprobe_path)
    };

    Ok(ManagedFfmpegProvider {
        ffmpeg_path,
        ffprobe_path,
        version: FFMPEG_PROVIDER_VERSION,
    })
}

async fn ensure_managed_whisper_model(tool_home: &Path) -> Result<ManagedWhisperModel> {
    let model_dir = tool_home.join("models");
    fs::create_dir_all(&model_dir)?;
    let model_path = model_dir.join(WHISPER_MODEL_FILE_NAME);
    let expected_sha = fetch_expected_model_sha().await?;
    let needs_download = fs::read(&model_path)
        .map(|bytes| sha256_hex(&bytes) != expected_sha)
        .unwrap_or(true);
    if needs_download {
        let client = reqwest::Client::builder()
            .redirect(redirect::Policy::limited(5))
            .timeout(Duration::from_secs(MODEL_DOWNLOAD_TIMEOUT_SECS))
            .build()
            .context("ERROR_CLASS=SynthesisFailed failed to initialize whisper model client")?;
        let bytes = client
            .get(WHISPER_MODEL_URL)
            .send()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to download whisper model")?
            .error_for_status()
            .context("ERROR_CLASS=SynthesisFailed whisper model request returned error status")?
            .bytes()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to read whisper model bytes")?;
        let observed_sha = sha256_hex(&bytes);
        if observed_sha != expected_sha {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing whisper model checksum mismatch expected={} observed={}",
                expected_sha,
                observed_sha
            ));
        }
        persist_downloaded_asset(&model_path, &bytes, false)?;
    }

    Ok(ManagedWhisperModel {
        model_path,
        model_id: WHISPER_MODEL_ID,
        revision: WHISPER_MODEL_REVISION,
    })
}

fn persist_downloaded_asset(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal asset path had no parent {}",
            path.display()
        ));
    };
    fs::create_dir_all(parent)?;
    let temp_path = path.with_extension("download");
    fs::write(&temp_path, bytes)?;
    #[cfg(unix)]
    if executable {
        let mut perms = fs::metadata(&temp_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&temp_path, perms)?;
    }
    fs::rename(&temp_path, path)?;
    Ok(())
}

fn select_ytdlp_asset_name() -> Result<&'static str> {
    match std::env::consts::OS {
        "linux" => Ok("yt-dlp"),
        "windows" => Ok("yt-dlp.exe"),
        "macos" => Ok("yt-dlp_macos"),
        other => Err(anyhow!(
            "ERROR_CLASS=SynthesisFailed unsupported managed yt-dlp host os '{}'",
            other
        )),
    }
}

fn select_ffmpeg_asset() -> Result<ManagedFfmpegAsset> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok(ManagedFfmpegAsset {
            asset_name: "ffmpeg-N-123196-gba38fa206e-linux64-gpl.tar.xz",
            archive_kind: FfmpegArchiveKind::TarXz,
        }),
        ("linux", "aarch64") => Ok(ManagedFfmpegAsset {
            asset_name: "ffmpeg-N-123196-gba38fa206e-linuxarm64-gpl.tar.xz",
            archive_kind: FfmpegArchiveKind::TarXz,
        }),
        ("windows", "x86_64") => Ok(ManagedFfmpegAsset {
            asset_name: "ffmpeg-N-123196-gba38fa206e-win64-gpl.zip",
            archive_kind: FfmpegArchiveKind::Zip,
        }),
        ("windows", "aarch64") => Ok(ManagedFfmpegAsset {
            asset_name: "ffmpeg-N-123196-gba38fa206e-winarm64-gpl.zip",
            archive_kind: FfmpegArchiveKind::Zip,
        }),
        (os, arch) => Err(anyhow!(
            "ERROR_CLASS=SynthesisFailed unsupported managed ffmpeg host os='{}' arch='{}'",
            os,
            arch
        )),
    }
}

async fn fetch_expected_ytdlp_sha(asset_name: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize checksum client")?;
    let sums = client
        .get(YTDLP_SUMS_URL)
        .send()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to fetch yt-dlp checksum manifest")?
        .error_for_status()
        .context("ERROR_CLASS=SynthesisFailed yt-dlp checksum manifest returned error status")?
        .text()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to read yt-dlp checksum manifest")?;
    sums.lines()
        .find_map(|line| parse_sha256sum_line(line, asset_name))
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing checksum manifest did not contain asset '{}'",
                asset_name
            )
        })
}

async fn fetch_expected_ffmpeg_sha(asset_name: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize ffmpeg checksum client")?;
    let sums = client
        .get(FFMPEG_SUMS_URL)
        .send()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to fetch ffmpeg checksum manifest")?
        .error_for_status()
        .context("ERROR_CLASS=SynthesisFailed ffmpeg checksum manifest returned error status")?
        .text()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to read ffmpeg checksum manifest")?;
    sums.lines()
        .find_map(|line| parse_sha256sum_line(line, asset_name))
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing ffmpeg checksum manifest did not contain asset '{}'",
                asset_name
            )
        })
}

async fn fetch_expected_model_sha() -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize whisper metadata client")?;
    let response = client
        .head(WHISPER_MODEL_URL)
        .send()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to fetch whisper model metadata")?;
    response
        .headers()
        .get("x-linked-etag")
        .or_else(|| response.headers().get(header::ETAG))
        .and_then(parse_header_hex_sha256)
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing whisper model metadata did not expose a sha256 etag"
            )
        })
}

fn parse_sha256sum_line(line: &str, asset_name: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let sha = parts.next()?;
    let name = parts.next()?.trim_start_matches('*');
    (name == asset_name).then(|| sha.to_ascii_lowercase())
}

fn parse_header_hex_sha256(value: &header::HeaderValue) -> Option<String> {
    let parsed = value
        .to_str()
        .ok()?
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase();
    (parsed.len() == 64 && parsed.chars().all(|ch| ch.is_ascii_hexdigit())).then_some(parsed)
}

fn extract_ffmpeg_archive(
    archive_path: &Path,
    extract_root: &Path,
    kind: FfmpegArchiveKind,
) -> Result<()> {
    match kind {
        FfmpegArchiveKind::TarXz => {
            let file = File::open(archive_path).with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to open ffmpeg archive {}",
                    archive_path.display()
                )
            })?;
            let decoder = XzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            archive.unpack(extract_root).with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to unpack ffmpeg archive {}",
                    archive_path.display()
                )
            })?;
        }
        FfmpegArchiveKind::Zip => {
            let file = File::open(archive_path).with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to open ffmpeg archive {}",
                    archive_path.display()
                )
            })?;
            let mut archive = ZipArchive::new(file).with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to inspect ffmpeg zip archive {}",
                    archive_path.display()
                )
            })?;
            for idx in 0..archive.len() {
                let mut entry = archive.by_index(idx)?;
                let out_path = extract_root.join(entry.name());
                if entry.name().ends_with('/') {
                    fs::create_dir_all(&out_path)?;
                    continue;
                }
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&out_path)?;
                std::io::copy(&mut entry, &mut outfile)?;
            }
        }
    }
    Ok(())
}

fn locate_ffmpeg_binary(extract_root: &Path, stem: &str) -> Option<PathBuf> {
    let expected = if cfg!(windows) {
        format!("{}.exe", stem)
    } else {
        stem.to_string()
    };
    WalkDir::new(extract_root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().to_path_buf())
        .find(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case(&expected))
        })
}

fn prepare_run_dir(tool_home: &Path) -> Result<PathBuf> {
    let run_dir = tool_home.join("run");
    if run_dir.exists() {
        fs::remove_dir_all(&run_dir)?;
    }
    fs::create_dir_all(run_dir.join("cache"))?;
    Ok(run_dir)
}
