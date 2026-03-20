use anyhow::{bail, Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::process::Command;
use tracing::{info, warn};

use crate::types::PodImage;

/// System namespace patterns to exclude
const SYSTEM_NS_PREFIXES: &[&str] = &["openshift-", "kube-", "redhat-", "rosa-"];
const SYSTEM_NS_EXACT: &[&str] = &["default"];

fn is_system_namespace(ns: &str) -> bool {
    SYSTEM_NS_EXACT.contains(&ns) || SYSTEM_NS_PREFIXES.iter().any(|p| ns.starts_with(p))
}

/// Run an oc command and return stdout
fn run_oc(args: &[&str]) -> Result<String> {
    let output = Command::new("oc")
        .args(args)
        .output()
        .context("Failed to execute oc command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("oc {} failed: {}", args.join(" "), stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
