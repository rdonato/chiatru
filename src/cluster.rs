use anyhow::{bail, Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

use crate::types::PodImage;

/// System namespace patterns to exclude
const SYSTEM_NS_PREFIXES: &[&str] = &["openshift-", "kube-", "redhat-", "rosa-"];
const SYSTEM_NS_EXACT: &[&str] = &["default"];

static MAX_OC_RETRIES: AtomicU32 = AtomicU32::new(5);

/// Configure maximum number of retries for oc commands
pub fn set_oc_max_retries(max_retries: u32) {
    MAX_OC_RETRIES.store(max_retries, Ordering::SeqCst);
}

fn is_system_namespace(ns: &str) -> bool {
    SYSTEM_NS_EXACT.contains(&ns) || SYSTEM_NS_PREFIXES.iter().any(|p| ns.starts_with(p))
}

/// Run an oc command and return stdout, with retry/backoff on transient failures.
fn run_oc(args: &[&str]) -> Result<String> {
    const BASE_DELAY_MS: u64 = 1000;
    let max_retries = std::cmp::max(1, MAX_OC_RETRIES.load(Ordering::SeqCst));

    let mut last_err = None;

    for attempt in 1..=max_retries {
        let output_result = Command::new("oc").args(args).output();

        match output_result {
            Ok(output) => {
                if output.status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
                }

                let stderr = String::from_utf8_lossy(&output.stderr);
                let message = stderr.trim();

                warn!(
                    "oc {} failed (attempt {}/{}): {}",
                    args.join(" "),
                    attempt,
                    max_retries,
                    message
                );

                if attempt == max_retries {
                    bail!(
                        "oc {} failed after {} attempts: {}",
                        args.join(" "),
                        max_retries,
                        message
                    );
                }

                if message.contains("Unauthorized")
                    || message.contains("unable to connect")
                    || message.contains("connection refused")
                    || message.contains("TLS handshake")
                {
                    warn!("Connection-related issue detected in oc command; please run `oc login` in a separate terminal and retry.");
                }

                let delay = Duration::from_millis(BASE_DELAY_MS * 2_u64.pow(attempt - 1));
                info!("Retrying in {:?}...", delay);
                thread::sleep(delay);

                last_err = Some(anyhow::anyhow!("oc command failed: {}", message));
            }
            Err(e) => {
                warn!(
                    "Failed to execute oc command on attempt {}/{}: {}",
                    attempt, max_retries, e
                );

                if attempt == max_retries {
                    return Err(e).context("Failed to execute oc command after retries");
                }

                let delay = Duration::from_millis(BASE_DELAY_MS * 2_u64.pow(attempt - 1));
                info!("Retrying in {:?}...", delay);
                thread::sleep(delay);

                last_err = Some(e.into());
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("oc command failed without output")))
}

/// Get current logged-in user
pub fn get_current_user() -> Result<String> {
    run_oc(&["whoami"]).context("Not logged in to OpenShift")
}

/// Get current authentication token
pub fn get_auth_token() -> Result<String> {
    run_oc(&["whoami", "-t"]).context("Failed to get OCP auth token")
}

/// Collect all pod-image mappings from the cluster.
///
/// If `namespaces` is Some, only those namespaces are queried.
/// Otherwise, all non-system namespaces are included.
pub fn get_pod_images(namespaces: Option<&[String]>) -> Result<Vec<PodImage>> {
    let mut pod_images = Vec::new();

    let jsonpath = concat!(
        "{range .items[*]}",
        "{.metadata.namespace}{\"|\"}",
        "{.metadata.name}{\"|\"}",
        "{range .spec.containers[*]}{.image}{\",\"}{end}",
        "{\"\\n\"}",
        "{end}"
    );

    let raw = match namespaces {
        Some(ns_list) => {
            let mut all_output = String::new();
            for ns in ns_list {
                info!("Querying namespace: {}", ns);
                match run_oc(&[
                    "get",
                    "pods",
                    "-n",
                    ns,
                    "-o",
                    &format!("jsonpath={}", jsonpath),
                ]) {
                    Ok(output) => {
                        all_output.push_str(&output);
                        all_output.push('\n');
                    }
                    Err(e) => warn!("Failed to query namespace {}: {}", ns, e),
                }
            }
            all_output
        }
        None => {
            info!("Querying all namespaces...");
            run_oc(&[
                "get",
                "pods",
                "--all-namespaces",
                "-o",
                &format!("jsonpath={}", jsonpath),
            ])?
        }
    };

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, '|').collect();
        if parts.len() < 3 {
            continue;
        }

        let ns = parts[0].trim();
        let pod = parts[1].trim();
        let images_str = parts[2].trim();

        // Skip system namespaces (when querying all)
        if namespaces.is_none() && is_system_namespace(ns) {
            continue;
        }

        // Split comma-separated images (multi-container pods)
        for img in images_str.split(',') {
            let img = img.trim();
            if img.is_empty() {
                continue;
            }
            pod_images.push(PodImage {
                namespace: ns.to_string(),
                pod: pod.to_string(),
                image: img.to_string(),
            });
        }
    }

    pod_images.sort_by(|a, b| a.image.cmp(&b.image));
    info!("Found {} pod-image entries", pod_images.len());

    Ok(pod_images)
}

/// Extract unique images from pod-image list
pub fn unique_images(pod_images: &[PodImage]) -> Vec<String> {
    let unique: HashSet<&str> = pod_images.iter().map(|pi| pi.image.as_str()).collect();
    let mut images: Vec<String> = unique.into_iter().map(String::from).collect();
    images.sort();
    images
}

/// Detect unique ECR registries from image list.
/// Returns Vec of (registry_hostname, region).
pub fn detect_ecr_registries(images: &[String]) -> Vec<(String, String)> {
    let re = Regex::new(r"(\d+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com)").unwrap();
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for img in images {
        if let Some(caps) = re.captures(img) {
            let registry = caps[1].to_string();
            let region = caps[2].to_string();
            if seen.insert(registry.clone()) {
                result.push((registry, region));
            }
        }
    }

    result
}

/// Check if an image is from the internal OpenShift registry
pub fn is_internal_registry(image: &str) -> bool {
    image.contains("image-registry.openshift-image-registry.svc")
}
