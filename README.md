# Chiatru - ROSA Image Vulnerability Scanner (Rust)

A native Rust CLI tool that scans all container images running in ROSA non-system namespaces for vulnerabilities. Uses **oci-distribution** for native image pulling (replacing skopeo) and **grype** as a subprocess for vulnerability scanning.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   chiatru (Rust)                    │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ cluster.rs   │  │ registry.rs  │  │scanner.rs │  │
│  │              │  │              │  │           │  │
│  │ oc get pods  │  │ oci-dist     │  │ grype CLI │  │
│  │ (subprocess) │  │ (native)     │  │ (subproc) │  │
│  │              │  │              │  │           │  │
│  │ • Pod list   │  │ • Auth       │  │ • Scan    │  │
│  │ • OCP token  │  │ • Pull       │  │ • JSON    │  │
│  │ • Namespace  │  │ • Save tar   │  │ • Parse   │  │
│  └──────────────┘  └──────────────┘  └───────────┘  │
│                                                     │
│  ┌──────────────┐  ┌──────────────────────────────┐ │
│  │ report.rs    │  │ types.rs                     │ │
│  │ CSV output   │  │ Serde types for grype JSON   │ │
│  └──────────────┘  └──────────────────────────────┘ │
└─────────────────────────────────────────────────────┘

Native Rust:  Image pulling, CSV generation, orchestration, JSON parsing
Subprocess:   oc (cluster queries), grype (scanning), aws (ECR auth)
```

## Prerequisites

- **Rust toolchain**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **grype**: `brew install grype`
- **oc**: OpenShift CLI, logged in to target cluster
- **aws cli**: For ECR authentication (if images are on ECR)
- **Port-forward** (for internal registry images only):
  ```bash
  oc port-forward svc/image-registry -n openshift-image-registry 5000:5000
  ```

## Build

```bash
cd chiatru
cargo build --release
```

The binary will be at `target/release/chiatru`.

## Releases

This project uses GitHub Actions for automated builds and releases.

### Creating a Release

1. **Tag a version** (replace `1.0.0` with your version):
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions will automatically**:
   - Build binaries for multiple platforms:
     - Linux (AMD64, ARM64)
     - macOS (AMD64, ARM64)
     - Windows (AMD64)
   - Create release archives (.tar.gz for Unix, .zip for Windows)
   - Publish a GitHub release with all binaries

### Manual Trigger

You can also trigger a build manually from the GitHub Actions tab without creating a tag.

## Usage

```bash
# Dry run — list images without scanning
./target/release/chiatru --dry-run

# Scan all non-system namespaces
./target/release/chiatru --sleep 10 --output company-vuln-report.csv

# Scan specific namespaces
./target/release/chiatru --namespace sos-dev,b2x-prod --output targeted-report.csv

# Skip automatic ECR login (if already authenticated)
./target/release/chiatru --skip-ecr-login --output report.csv

# Verbose logging
./target/release/chiatru --log-level debug --output report.csv
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--sleep` | 5 | Seconds to pause between image downloads |
| `--output, -o` | `grype-report-<timestamp>.csv` | Output CSV filename |
| `--dry-run` | false | List images without scanning |
| `--skip-ecr-login` | false | Skip automatic ECR authentication |
| `--namespace` | all non-system | Comma-separated namespaces to scan |
| `--log-level` | info | Logging: info, debug, trace |

## Output

### CSV columns

| Column | Description |
|--------|-------------|
| Namespace | Kubernetes namespace |
| Pod | Pod name |
| Image | Full image reference |
| Vulnerability_ID | CVE or advisory ID |
| Severity | Critical, High, Medium, Low, Negligible |
| Data_Source | Vulnerability database source |
| Package_Name | Affected package |
| Package_Version | Installed version |
| Package_Type | Package type (deb, rpm, java-archive, go-module, etc.) |
| Fix_State | fixed, not-fixed, wont-fix, unknown |
| Fix_Versions | Versions that fix the vulnerability |
| CVSS_Score | Highest CVSS base score |
| URLs | Reference URLs |
| Description | Vulnerability description (truncated to 200 chars) |

### Special rows

- `Vulnerability_ID = NONE` → Image scanned, no vulnerabilities found
- `Vulnerability_ID = ERROR` → Image could not be pulled or scanned

## Disk Usage

Only one image is on disk at any time. The downloaded tar is deleted immediately
after grype finishes scanning, before the next image is downloaded.

## Multi-Registry Support

The tool handles three registry types automatically:

1. **Internal OpenShift registry** (`image-registry.openshift-image-registry.svc:5000`)
   - Rewrites to `localhost:5000` (port-forward)
   - Authenticates with OCP token
   - Skips TLS verification

2. **AWS ECR** (`<account>.dkr.ecr.<region>.amazonaws.com`)
   - Auto-detects registries from image list
   - Authenticates via `aws ecr get-login-password`
   - Refreshes credentials every 200 images

3. **Public registries** (docker.io, quay.io, ghcr.io, etc.)
   - Uses anonymous access by default

## Comparison with Bash Script

| Feature | Bash script | Rust binary |
|---------|-------------|-------------|
| macOS Bash compat | Bash 3.x workarounds | N/A (compiled) |
| Error handling | `set -euo pipefail` | `Result<T>` + `anyhow` |
| Image pulling | skopeo (subprocess) | oci-distribution (native) |
| Grype scanning | subprocess | subprocess |
| JSON parsing | jq (subprocess) | serde (native) |
| CSV generation | bash string concat | csv crate (proper escaping) |
| Type safety | None | Full |
| Credential refresh | Every N images | Every N images |
| Performance | Sequential | Sequential (same) |

## Troubleshooting

**ECR auth fails**: Ensure `aws sts get-caller-identity` works and you have
ECR pull permissions.

**Internal registry unreachable**: Verify port-forward is running:
```bash
oc port-forward svc/image-registry -n openshift-image-registry 5000:5000
```

**TLS errors on localhost**: The tool skips TLS verification for localhost
automatically. If you still get errors, check that the port-forward is on
port 5000.

**grype not found**: Install with `brew install grype` or download from
https://github.com/anchore/grype/releases

**oci-distribution compile error**: If the crate API has changed, check
https://crates.io/crates/oci-distribution for the latest docs and adjust
`src/registry.rs` accordingly.
