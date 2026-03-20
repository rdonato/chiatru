use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

use crate::types::{CsvRow, PodImage, ScanResult};

/// Summary statistics for the report
#[derive(Debug, Default)]
pub struct ReportSummary {
    pub total_rows: usize,
    pub total_pod_images: usize,
    pub vuln_rows: usize,
    pub clean_images: usize,
    pub _images_scanned: usize,
    pub images_failed: usize,
}

/// Build the final CSV report by joining pod-image mappings with scan results.
///
/// Each pod-image combination gets one row per vulnerability found.
/// Images with no vulnerabilities get a single "NONE" row.
pub fn build_csv_report(
    output_path: &Path,
    pod_images: &[PodImage],
    scan_results: &HashMap<String, ScanResult>,
) -> Result<ReportSummary> {
    info!("Building CSV report: {}", output_path.display());

    let mut writer = csv::Writer::from_path(output_path)
        .with_context(|| format!("Failed to create CSV file: {}", output_path.display()))?;

    // Write header
    writer.write_record([
        "Namespace",
        "Pod",
        "Image",
        "Vulnerability_ID",
        "Severity",
        "Data_Source",
        "Package_Name",
        "Package_Version",
        "Package_Type",
        "Fix_State",
        "Fix_Versions",
        "CVSS_Score",
        "URLs",
        "Description",
    ])?;

    let mut summary = ReportSummary {
        total_pod_images: pod_images.len(),
        _images_scanned: scan_results.values().filter(|r| !r.vulnerabilities.is_empty() || scan_results.contains_key(&r.image)).count(),
        ..Default::default()
    };

    for pi in pod_images {
        if let Some(result) = scan_results.get(&pi.image) {
            if result.vulnerabilities.is_empty() {
                // Clean image — no vulnerabilities found
                let row = CsvRow {
                    namespace: pi.namespace.clone(),
                    pod: pi.pod.clone(),
                    image: pi.image.clone(),
                    vulnerability_id: "NONE".to_string(),
                    severity: "NONE".to_string(),
                    data_source: String::new(),
                    package_name: String::new(),
                    package_version: String::new(),
                    package_type: String::new(),
                    fix_state: String::new(),
                    fix_versions: String::new(),
                    cvss_score: String::new(),
                    urls: String::new(),
                    description: "No vulnerabilities found".to_string(),
                };
                writer.serialize(&row)?;
                summary.total_rows += 1;
                summary.clean_images += 1;
            } else {
                for vuln in &result.vulnerabilities {
                    let row = CsvRow {
                        namespace: pi.namespace.clone(),
                        pod: pi.pod.clone(),
                        image: pi.image.clone(),
                        vulnerability_id: vuln.vuln_id.clone(),
                        severity: vuln.severity.clone(),
                        data_source: vuln.data_source.clone(),
                        package_name: vuln.package_name.clone(),
                        package_version: vuln.package_version.clone(),
                        package_type: vuln.package_type.clone(),
                        fix_state: vuln.fix_state.clone(),
                        fix_versions: vuln.fix_versions.clone(),
                        cvss_score: vuln.cvss_score.clone(),
                        urls: vuln.urls.clone(),
                        description: vuln.description.clone(),
                    };
                    writer.serialize(&row)?;
                    summary.total_rows += 1;
                    summary.vuln_rows += 1;
                }
            }
        } else {
            // Image was not scanned (failed to pull or scan)
            let row = CsvRow {
                namespace: pi.namespace.clone(),
                pod: pi.pod.clone(),
                image: pi.image.clone(),
                vulnerability_id: "ERROR".to_string(),
                severity: "UNKNOWN".to_string(),
                data_source: String::new(),
                package_name: String::new(),
                package_version: String::new(),
                package_type: String::new(),
                fix_state: String::new(),
                fix_versions: String::new(),
                cvss_score: String::new(),
                urls: String::new(),
                description: "Image could not be scanned".to_string(),
            };
            writer.serialize(&row)?;
            summary.total_rows += 1;
            summary.images_failed += 1;
        }
    }

    writer.flush()?;

    Ok(summary)
}
