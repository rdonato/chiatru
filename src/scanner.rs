use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{debug, warn};

use crate::types::{GrypeOutput, ScanResult, Vulnerability};

/// Check that grype is installed and available
pub fn check_grype() -> Result<String> {
    let output = Command::new("grype")
        .arg("version")
        .output()
        .context("grype not found. Install with: brew install grype")?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Scan a docker-archive tar file with grype and return parsed vulnerabilities.
///
/// This invokes `grype <tar_path> -o json` and parses the JSON output.
pub fn scan_tar(tar_path: &Path, image_name: &str) -> Result<ScanResult> {
    debug!("Scanning with grype: {}", tar_path.display());

    let output = Command::new("grype")
        .arg(tar_path.to_str().unwrap_or_default())
        .args(["-o", "json", "--quiet"])
        .output()
        .context("Failed to execute grype")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // grype may return non-zero for scan errors but still produce output
        if output.stdout.is_empty() {
            bail!("grype scan failed for {}: {}", image_name, stderr.trim());
        }
        warn!(
            "grype reported warnings for {}: {}",
            image_name,
            stderr.trim()
        );
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let grype_output: GrypeOutput = serde_json::from_str(&json_str)
        .with_context(|| format!("Failed to parse grype JSON output for {}", image_name))?;

    let vulnerabilities: Vec<Vulnerability> = grype_output
        .matches
        .iter()
        .map(Vulnerability::from_grype_match)
        .collect();

    Ok(ScanResult {
        image: image_name.to_string(),
        vulnerabilities,
    })
}
