use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Cluster types
// ---------------------------------------------------------------------------

/// A pod running in the cluster with its container image
#[derive(Debug, Clone, Serialize)]
pub struct PodImage {
    pub namespace: String,
    pub pod: String,
    pub image: String,
}

// ---------------------------------------------------------------------------
// Grype JSON output types (subset of fields we care about)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GrypeOutput {
    #[serde(default)]
    pub matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeMatch {
    pub vulnerability: GrypeVulnerability,
    pub artifact: GrypeArtifact,
}

#[derive(Debug, Deserialize)]
pub struct GrypeVulnerability {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default, rename = "dataSource")]
    pub data_source: String,
    #[serde(default)]
    pub fix: GrypeFix,
    #[serde(default)]
    pub cvss: Vec<GrypeCvss>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GrypeFix {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeCvss {
    #[serde(default)]
    pub metrics: GrypeCvssMetrics,
}

#[derive(Debug, Default, Deserialize)]
pub struct GrypeCvssMetrics {
    #[serde(default, rename = "baseScore")]
    pub base_score: f64,
}

#[derive(Debug, Deserialize)]
pub struct GrypeArtifact {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default, rename = "type")]
    pub pkg_type: String,
}

// ---------------------------------------------------------------------------
// Scan result
// ---------------------------------------------------------------------------

/// Result of scanning a single image
#[derive(Debug)]
pub struct ScanResult {
    pub image: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Flattened vulnerability ready for CSV output
#[derive(Debug, Clone, Serialize)]
pub struct Vulnerability {
    pub vuln_id: String,
    pub severity: String,
    pub data_source: String,
    pub package_name: String,
    pub package_version: String,
    pub package_type: String,
    pub fix_state: String,
    pub fix_versions: String,
    pub cvss_score: String,
    pub urls: String,
    pub description: String,
}

impl Vulnerability {
    pub fn from_grype_match(m: &GrypeMatch) -> Self {
        let max_cvss = m
            .vulnerability
            .cvss
            .iter()
            .map(|c| c.metrics.base_score)
            .fold(f64::NEG_INFINITY, f64::max);

        let cvss_str = if max_cvss.is_finite() {
            format!("{:.1}", max_cvss)
        } else {
            String::new()
        };

        // Truncate and sanitize description for CSV
        let desc = m
            .vulnerability
            .description
            .replace(['\n', '\r', '"'], " ")
            .chars()
            .take(200)
            .collect();

        Self {
            vuln_id: m.vulnerability.id.clone(),
            severity: m.vulnerability.severity.clone(),
            data_source: m.vulnerability.data_source.clone(),
            package_name: m.artifact.name.clone(),
            package_version: m.artifact.version.clone(),
            package_type: m.artifact.pkg_type.clone(),
            fix_state: m.vulnerability.fix.state.clone(),
            fix_versions: m.vulnerability.fix.versions.join(";"),
            cvss_score: cvss_str,
            urls: m.vulnerability.urls.join(";"),
            description: desc,
        }
    }
}

// ---------------------------------------------------------------------------
// CSV row — final report output
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CsvRow {
    pub namespace: String,
    pub pod: String,
    pub image: String,
    pub vulnerability_id: String,
    pub severity: String,
    pub data_source: String,
    pub package_name: String,
    pub package_version: String,
    pub package_type: String,
    pub fix_state: String,
    pub fix_versions: String,
    pub cvss_score: String,
    pub urls: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Registry classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum _RegistryKind {
    /// Internal OpenShift image registry (needs port-forward + OCP token)
    Internal,
    /// AWS ECR (needs aws ecr get-login-password)
    Ecr { registry: String, region: String },
    /// Public or pre-authenticated registry (docker.io, quay.io, ghcr.io, etc.)
    Public,
}
