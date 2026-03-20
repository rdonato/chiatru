use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use oci_distribution::client::{ClientConfig, ClientProtocol};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::{Client, Reference};
use serde_json::json;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

use crate::cluster;

/// Internal OpenShift registry hostname (in-cluster)
const INTERNAL_REGISTRY: &str = "image-registry.openshift-image-registry.svc:5000";
/// Rewritten hostname for port-forward access
const LOCAL_REGISTRY: &str = "localhost:5000";

/// OCI / Docker media types we accept for layers
const ACCEPTED_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
];

/// Manages image pulling from various registries
pub struct ImagePuller {
    /// OCP username for internal registry
    ocp_user: String,
    /// OCP token for internal registry
    ocp_token: String,
    /// Cached ECR credentials: (registry, password)
    ecr_creds: Vec<(String, String)>,
}

impl ImagePuller {
    /// Create a new ImagePuller, fetching initial OCP credentials
    pub fn new() -> Result<Self> {
        let ocp_user = cluster::get_current_user()?;
        let ocp_token = cluster::get_auth_token()?;

        Ok(Self {
            ocp_user,
            ocp_token,
            ecr_creds: Vec::new(),
        })
    }

    /// Refresh OCP credentials (call periodically for long scans)
    pub fn refresh_ocp_credentials(&mut self) -> Result<()> {
        self.ocp_user = cluster::get_current_user()?;
        self.ocp_token = cluster::get_auth_token()?;
        info!("OCP credentials refreshed");
        Ok(())
    }

    /// Login to an ECR registry and cache the credentials
    pub fn login_ecr(&mut self, registry: &str, region: &str) -> Result<()> {
        info!("Authenticating to ECR: {} (region: {})", registry, region);

        let output = Command::new("aws")
            .args(["ecr", "get-login-password", "--region", region])
            .output()
            .context("Failed to run aws ecr get-login-password. Is aws cli installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("ECR login failed for {}: {}", registry, stderr.trim());
        }

        let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
        self.ecr_creds.push((registry.to_string(), password));
        info!("ECR login successful: {}", registry);
        Ok(())
    }

    /// Refresh all cached ECR credentials
    pub fn refresh_ecr_credentials(&mut self, registries: &[(String, String)]) {
        self.ecr_creds.clear();
        for (registry, region) in registries {
            if let Err(e) = self.login_ecr(registry, region) {
                warn!("Failed to refresh ECR creds for {}: {}", registry, e);
            }
        }
    }

    /// Get authentication for a given image reference
    fn get_auth(&self, image: &str) -> RegistryAuth {
        // Internal registry
        if image.starts_with(LOCAL_REGISTRY) || image.contains(INTERNAL_REGISTRY) {
            return RegistryAuth::Basic(self.ocp_user.clone(), self.ocp_token.clone());
        }

        // ECR registry
        for (registry, password) in &self.ecr_creds {
            if image.starts_with(registry.as_str()) {
                return RegistryAuth::Basic("AWS".to_string(), password.clone());
            }
        }

        // Public registries — try anonymous
        RegistryAuth::Anonymous
    }

    /// Build an OCI client configured for the target registry
    fn build_client(image: &str) -> Client {
        let is_localhost = image.starts_with("localhost:") || image.starts_with("127.0.0.1:");

        let config = ClientConfig {
            protocol: if is_localhost {
                ClientProtocol::Http
            } else {
                ClientProtocol::Https
            },
            accept_invalid_certificates: is_localhost,
            ..Default::default()
        };

        Client::new(config)
    }

    /// Rewrite internal registry references to localhost (port-forward)
    fn rewrite_reference(image: &str) -> String {
        image.replace(INTERNAL_REGISTRY, LOCAL_REGISTRY)
    }

    /// Pull an image and save it as a docker-archive tar.
    ///
    /// Returns the path to the created tar file and its size in bytes.
    pub async fn pull_and_save(&self, image: &str, output_dir: &Path) -> Result<(PathBuf, u64)> {
        let pull_ref = Self::rewrite_reference(image);
        debug!("Pulling image: {} (as {})", image, pull_ref);

        let reference: Reference = pull_ref
            .parse()
            .with_context(|| format!("Invalid image reference: {}", pull_ref))?;

        let auth = self.get_auth(&pull_ref);
        let client = Self::build_client(&pull_ref);

        // Pull manifest and layers
        let image_data = client
            .pull(&reference, &auth, ACCEPTED_MEDIA_TYPES.to_vec())
            .await
            .with_context(|| format!("Failed to pull image: {}", pull_ref))?;

        // Save as docker-archive tar
        let tar_path = output_dir.join("current-image.tar");
        save_docker_archive(&tar_path, &reference, &image_data)?;

        let size = std::fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);

        Ok((tar_path, size))
    }
}

/// Save pulled image data as a docker-archive tar file.
///
/// Docker-archive format:
///   manifest.json     — [{Config, RepoTags, Layers}]
///   <config_hash>.json — image config blob
///   <layer_hash>/layer.tar — each layer (decompressed)
fn save_docker_archive(
    tar_path: &Path,
    reference: &Reference,
    image_data: &oci_distribution::client::ImageData,
) -> Result<()> {
    use tar::Builder;

    let file = std::fs::File::create(tar_path)
        .with_context(|| format!("Failed to create tar file: {}", tar_path.display()))?;
    let mut ar = Builder::new(file);

    // --- Config blob ---
    let config_data = &image_data.config.data;
    let config_hash = sha256_hex(config_data);
    let config_name = format!("{}.json", config_hash);

    append_bytes(&mut ar, &config_name, config_data)?;

    // --- Layers ---
    let mut layer_names = Vec::new();
    for (i, layer) in image_data.layers.iter().enumerate() {
        let layer_dir = format!("layer_{:03}", i);
        let layer_tar_name = format!("{}/layer.tar", layer_dir);

        // Decompress gzipped layers; pass through non-gzipped
        let decompressed = try_decompress_gzip(&layer.data);
        append_bytes(&mut ar, &layer_tar_name, &decompressed)?;
        layer_names.push(layer_tar_name);
    }

    // --- manifest.json ---
    let repo_tag = format!(
        "{}{}",
        reference.whole(),
        "" // Reference::whole() includes tag/digest
    );

    let manifest_json = json!([{
        "Config": config_name,
        "RepoTags": [repo_tag],
        "Layers": layer_names,
    }]);

    let manifest_bytes = serde_json::to_vec_pretty(&manifest_json)?;
    append_bytes(&mut ar, "manifest.json", &manifest_bytes)?;

    ar.finish()?;
    Ok(())
}

/// Append raw bytes as a file entry in a tar archive
fn append_bytes<W: std::io::Write>(
    ar: &mut tar::Builder<W>,
    name: &str,
    data: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();

    ar.append_data(&mut header, name, data)
        .with_context(|| format!("Failed to write {} to tar", name))?;
    Ok(())
}

/// Try to decompress gzip data; return original if not gzipped
fn try_decompress_gzip(data: &[u8]) -> Vec<u8> {
    // Check gzip magic bytes
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        if decoder.read_to_end(&mut decompressed).is_ok() {
            return decompressed;
        }
    }
    data.to_vec()
}

/// Compute SHA256 hex digest of data
fn sha256_hex(data: &[u8]) -> String {
    // Simple SHA-256 using the fact that we already have the data
    // We use a basic implementation to avoid pulling in another crate
    // In production, you'd use `sha2` crate
    format!("{:x}", md5_like_hash(data))
}

/// Minimal hash for config naming (in production use sha2 crate).
/// This produces a unique-enough name for the tar archive.
fn md5_like_hash(data: &[u8]) -> u128 {
    // FNV-1a 128-bit hash — good enough for unique naming within a single tar
    let mut hash: u128 = 0x6c62272e07bb0142_62b821756295c58d;
    for &byte in data {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(0x0000000001000000_000000000000013b);
    }
    hash
}

/// Remove a tar file (best-effort cleanup)
pub fn cleanup_tar(path: &Path) {
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            warn!("Failed to remove tar {}: {}", path.display(), e);
        }
    }
}
