// src/tranco.rs
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::path::Path;
use std::time::Duration;
use zip::ZipArchive;

const MAX_DOWNLOAD_SIZE_BYTES: u64 = 25 * 1024 * 1024;

pub const EMBEDDED_FALLBACK: &[&str] = &[
    "google.com",
    "youtube.com",
    "facebook.com",
    "wikipedia.org",
    "amazon.com",
    "reddit.com",
    "netflix.com",
    "bing.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "cloudflare.com",
    "archlinux.org",
    "ubuntu.com",
    "example.com",
];

pub async fn get_or_download_tranco(file_path: &str, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }

    let path = Path::new(file_path);

    if path.exists() {
        if let Ok(domains) = load_from_file(path, limit) {
            if domains.len() >= limit {
                tracing::info!(
                    path = file_path,
                    count = domains.len(),
                    "[TRANCO] Using local domain list file"
                );
                return domains;
            }
        }
    }

    tracing::info!(limit, "[TRANCO] Downloading Tranco Top 1M list archive...");
    match download_and_extract(limit).await {
        Ok(domains) => {
            tracing::info!(
                count = domains.len(),
                "[TRANCO] Extracted domains; saving to disk"
            );
            if let Ok(mut f) = File::create(path) {
                for d in &domains {
                    let _ = writeln!(f, "{}", d);
                }
            }
            domains
        }
        Err(err) => {
            tracing::warn!(error = %err, "[TRANCO] Download failed; using built-in fallback domain list");
            EMBEDDED_FALLBACK
                .iter()
                .take(limit)
                .map(|s| s.to_string())
                .collect()
        }
    }
}

fn load_from_file(path: &Path, limit: usize) -> std::io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut domains = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let domain = trimmed
            .split_once(',')
            .map(|(_, d)| d.trim())
            .unwrap_or(trimmed);
        if !domain.is_empty() {
            domains.push(domain.to_string());
            if domains.len() >= limit {
                break;
            }
        }
    }
    Ok(domains)
}

async fn download_and_extract(
    limit: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("doh-server-tranco-updater/1.0")
        .build()?;

    let resp = client
        .get("https://tranco-list.eu/top-1m.csv.zip")
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(format!("Server returned HTTP {}", resp.status()).into());
    }

    if let Some(content_len) = resp.content_length() {
        if content_len > MAX_DOWNLOAD_SIZE_BYTES {
            return Err("Tranco download payload exceeds size limit".into());
        }
    }

    let bytes = resp.bytes().await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;

    let mut domains = Vec::new();
    if archive.len() > 0 {
        let mut file = archive.by_index(0)?;
        let reader = BufReader::new(&mut file);
        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let domain = trimmed
                .split_once(',')
                .map(|(_, d)| d.trim())
                .unwrap_or(trimmed);
            if !domain.is_empty() {
                domains.push(domain.to_string());
                if domains.len() >= limit {
                    break;
                }
            }
        }
    }

    Ok(domains)
}
