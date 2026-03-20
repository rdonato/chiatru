mod cluster;
mod registry;
mod report;
mod scanner;
mod types;

use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;
use tracing::{error, info, warn};

use crate::registry::ImagePuller;
use crate::types::ScanResult;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "rosa-vuln-scan",
    about = "ROSA cluster image vulnerability scanner",
    long_about = "Scans container images in ROSA non-system namespaces using native OCI \
                  pulling and grype. Outputs a CSV report with namespace, pod, image, \
                  and full vulnerability details.\n\n\
                  Prerequisites:\n  \
                  - oc login active\n  \
                  - grype installed\n  \
                  - aws cli installed (for ECR images)\n  \
                  - Port-forward for internal registry images:\n    \
                    oc port-forward svc/image-registry -n openshift-image-registry 5000:5000"
)]
struct Cli {
    /// Pause in seconds between image downloads
    #[arg(long, default_value_t = 5)]
    sleep: u64,

    /// Output CSV filename
    #[arg(long, short, default_value_t = default_output_filename())]
    output: String,

    /// List images without scanning
    #[arg(long)]
    dry_run: bool,

    /// Skip automatic ECR login (use if already authenticated)
    #[arg(long)]
    skip_ecr_login: bool,

    /// Comma-separated list of namespaces to scan (default: all non-system)
    #[arg(long, value_delimiter = ',')]
    namespace: Option<Vec<String>>,

    /// Log verbosity: info, debug, trace
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn default_output_filename() -> String {
    format!("grype-report-{}.csv", Local::now().format("%Y%m%d-%H%M%S"))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new(
            "%Y-%m-%d %H:%M:%S".to_string(),
        ))
        .init();

    info!("==========================================");
    info!("ROSA Image Vulnerability Scanner (Rust)");
    info!("==========================================");
    info!("Sleep between images: {}s", cli.sleep);
    info!("Output file: {}", cli.output);
    info!("");

    // --- Prerequisites ---
    let user = cluster::get_current_user()?;
    info!("Logged in as: {}", user);

    if let Ok(version) = scanner::check_grype() {
        info!("grype version: {}", version);
    }

    // --- Phase 1: Collect pod-image mappings ---
    let ns_filter = cli.namespace.as_deref();
    let pod_images = cluster::get_pod_images(ns_filter)?;
    let unique = cluster::unique_images(&pod_images);

    info!("Pod-image entries: {}", pod_images.len());
    info!("Unique images: {}", unique.len());

    // --- Detect and authenticate registries ---
    let ecr_registries = cluster::detect_ecr_registries(&unique);
    if !ecr_registries.is_empty() {
        info!("ECR registries detected:");
        for (reg, region) in &ecr_registries {
            info!("  - {} ({})", reg, region);
        }
    }

    let has_internal = unique.iter().any(|i| cluster::is_internal_registry(i));
    if has_internal {
        info!("Internal registry images detected (ensure port-forward is running)");
    }

    // --- Dry run ---
    if cli.dry_run {
        info!("");
        info!("DRY RUN — images that would be scanned:");
        info!("------------------------------------------");
        for img in &unique {
            info!("  {}", img);
        }
        info!("------------------------------------------");
        info!("DRY RUN complete.");
        return Ok(());
    }

    // --- Initialize puller ---
    let mut puller = ImagePuller::new()?;

    if !cli.skip_ecr_login {
        for (reg, region) in &ecr_registries {
            if let Err(e) = puller.login_ecr(reg, region) {
                warn!("ECR login failed for {}: {}", reg, e);
            }
        }
    }

    // --- Phase 2: Scan images one at a time ---
    let work_dir = TempDir::new().context("Failed to create temp directory")?;
    let mut scan_results: HashMap<String, ScanResult> = HashMap::new();
    let total = unique.len();
    let mut scanned = 0usize;
    let mut failed = 0usize;

    info!("");
    info!("Starting scan of {} unique images...", total);
    info!("");

    for (i, image) in unique.iter().enumerate() {
        let current = i + 1;
        info!("[{}/{}] Processing: {}", current, total, image);

        // Pull image
        let pull_result = puller.pull_and_save(image, work_dir.path()).await;

        let tar_path = match pull_result {
            Ok((path, size)) => {
                let size_mb = size / (1024 * 1024);
                info!("  Downloaded: {}MB", size_mb);
                path
            }
            Err(e) => {
                error!("  Pull failed: {}", e);
                failed += 1;
                maybe_sleep(current, total, cli.sleep).await;
                continue;
            }
        };

        // Scan with grype
        match scanner::scan_tar(&tar_path, image) {
            Ok(result) => {
                info!("  Found {} vulnerabilities", result.vulnerabilities.len());
                scan_results.insert(image.clone(), result);
                scanned += 1;
            }
            Err(e) => {
                error!("  Scan failed: {}", e);
                failed += 1;
            }
        }

        // Delete tar immediately — keep disk usage minimal
        registry::cleanup_tar(&tar_path);

        // Refresh credentials periodically
        if current % 50 == 0 {
            info!("Refreshing OCP credentials...");
            if let Err(e) = puller.refresh_ocp_credentials() {
                warn!("Failed to refresh OCP creds: {}", e);
            }
        }
        if current % 200 == 0 && !cli.skip_ecr_login && !ecr_registries.is_empty() {
            info!("Refreshing ECR credentials...");
            puller.refresh_ecr_credentials(&ecr_registries);
        }

        // Sleep between images
        maybe_sleep(current, total, cli.sleep).await;
    }

    info!("");
    info!("==========================================");
    info!(
        "Scan complete: {} scanned, {} failed, {} total",
        scanned, failed, total
    );
    info!("==========================================");
    info!("");

    // --- Phase 3: Build report ---
    let output_path = PathBuf::from(&cli.output);
    let summary = report::build_csv_report(&output_path, &pod_images, &scan_results)?;

    info!("==========================================");
    info!("REPORT SUMMARY");
    info!("==========================================");
    info!("Output file:      {}", cli.output);
    info!("Total CSV rows:   {}", summary.total_rows);
    info!("Pod-image combos: {}", summary.total_pod_images);
    info!("Vuln rows:        {}", summary.vuln_rows);
    info!("Clean images:     {}", summary.clean_images);
    info!("Failed images:    {}", summary.images_failed);
    info!("==========================================");

    Ok(())
}

async fn maybe_sleep(current: usize, total: usize, sleep_secs: u64) {
    if current < total && sleep_secs > 0 {
        info!("  Sleeping {}s...", sleep_secs);
        tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
    }
}
