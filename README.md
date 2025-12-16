
# sbomdelta

`sbomdelta` is a lightweight CLI tool that explains **why** vulnerability counts differ between:

- an **upstream upstream base image** (Ubuntu, Alpine, Debian, etc.)
- a **provider hardened image**

Instead of only reporting CVEs, it answers the real question:

> *“What actually changed between these two images that caused CVEs to appear or disappear?”*

## Why sbomdelta ?

Traditional scanners show only:

```text
Upstream image: 50 CVEs  
Hardened image: 20 CVEs
```

But they cannot explain:

- Were CVEs removed because packages were removed?
- Were new CVEs added because hardened added new packages?
- Are some CVEs false positives due to distro backport?
- Which packages are responsible for which CVE delta?

sbomdelta solves this by combining:

1. **SBOM Comparision**: real package difference
2. **Vulnerability Comparision**: real CVE difference
3. **Optional backport ignore file**: suppress distro false positives

## What sbomdelta computes

### 1. Package Delta

How the ingredient list changed:

| Case                      | Interpretation                |
|--------------------------|-------------------------------|
| Upstream → not in hardened | Package removed (risk reduced) |
| Not in upstream → hardened | New package added (new risk)   |
| Present in both          | Stable package surface        |

### 2. CVE Delta

For every `(package + CVE)`:

| Status               | Meaning                                   |
|---------------------|-------------------------------------------|
| `ONLY_UPSTREAM`     | CVE eliminated (patch or package removed) |
| `ONLY_HARDENED`     | New CVE introduced                         |
| `BOTH_SAME_SEVERITY`| No change                                  |
| `BOTH_DIFF_SEVERITY`| Severity increased/decreased               |

### 3. Backport Handling (Optional)

Many distros patch CVEs *without* changing version numbers.

Provide a backport file and sbomdelta will:

- Remove those CVEs from delta 
- Treat them as false positives
- Report how many were suppressed

## Usage and Examples

### Basic Usage (No Backport File)

```bash
sbomdelta eval \                                   
--up-sbom=testdata/upstream-sbom.cdx.json \           
--hd-sbom=testdata/hardend-sbom.cdx.json \           
--up-vuln=testdata/upstream-vuln.trivy.json \           
--hd-vuln=testdata/hardend-vuln.trivy.json  
```

### With Backport Suppression

```bash
sbomdelta eval \                                   
--up-sbom=testdata/upstream-sbom.cdx.json \           
--hd-sbom=testdata/hardend-sbom.cdx.json \           
--up-vuln=testdata/upstream-vuln.trivy.json \           
--hd-vuln=testdata/hardend-vuln.trivy.json  \
--bc-vuln backports.json
```

### Run from Go Source

```bash
go run main.go eval \                                  
--up-sbom=testdata/upstream-sbom.cdx.json \           
--hd-sbom=testdata/hardend-sbom.cdx.json \           
--up-vuln=testdata/upstream-vuln.trivy.json \           
--hd-vuln=testdata/hardend-vuln.trivy.json  
```

## Flags Reference

| Flag        | Description                        |
| ----------- | ---------------------------------- |
| `--up-sbom` | Upstream SBOM JSON                 |
| `--hd-sbom` | Hardened SBOM JSON                 |
| `--up-vuln` | Upstream vulnerability report      |
| `--hd-vuln` | Hardened vulnerability report      |
| `--bc-vuln` | (Optional) Backport exception file |

## Example output

```bash

=== Raw Vulnerability Counts ===
  Upstream total CVEs:   3
  Hardened total CVEs:   3

=== Package Delta (What Actually Changed) ===
  Packages removed in hardened: 2
  Packages added in hardened:   2
  Packages common in both:      1

=== Impact of Package Changes on CVEs ===
  CVEs removed because packages disappeared: 2
  CVEs added because packages appeared:      2
  CVEs on common packages:                   1

=== CVE Delta (Root-Cause Breakdown) ===
  Only in upstream:  2
  Only in hardened:  2
  Present in both:   1
  High/Crit removed: 1
  High/Crit added:   1

=== Vulnerability Delta Detail ===
PACKAGE@VERSION                          CVE                STATUS                 UPSTREAM   HARDENED  
---------------------------------------------------------------------------------------------------------
curl@7.80.0                              CVE-2024-2222      ONLY_UPSTREAM          MEDIUM     -         
curl@7.88.0                              CVE-2024-2222      ONLY_HARDENED          -          LOW       
jq@1.6                                   CVE-2024-4444      ONLY_HARDENED          -          HIGH      
openssl@1.0.2                            CVE-2024-1111      ONLY_UPSTREAM          HIGH       -         
zlib@1.2.11                              CVE-2024-3333      BOTH_SAME_SEVERITY     LOW        LOW       
```

## Other SBOM Open Source Tools

Interlynk provides a comprehensive suite of SBOM tools:

- [**SBOM Assembler**](https://github.com/interlynk-io/sbomasm) - Complete SBOM toolkit (Merging/Enriching/Signing and Editing)
- [**SBOM Explorer**](https://github.com/interlynk-io/sbomex) - Search and download from public repositories  
- [**SBOM Search Tool**](https://github.com/interlynk-io/sbomgr) - Context-aware repository search
- [**SBOM Seamless Transfer**](https://github.com/interlynk-io/sbommv) - Transfer between systems
- [**SBOM Benchmark**](https://www.sbombenchmark.dev) - Repository of SBOM quality scores

## Blog Posts

- [Stop Comparing CVE Counts: How SBOM deltas explain upstream vs hardened image security](https://sbom-insights.dev/posts/upstream-vs-hardened-image-cves-why-numbers-dont-match/)

## Contact

- ❓ [Community Slack](https://join.slack.com/t/sbomqa/shared_invite/zt-2jzq1ttgy-4IGzOYBEtHwJdMyYj~BACA)
- 💬 [Live Chat](https://www.interlynk.io/#hs-chat-open)
- 📧 [Email](mailto:hello@interlynk.io)
- 🐛 [GitHub Issues](https://github.com/interlynk-io/sbomdelta/issues)
- 🐦 [Follow us on X](https://twitter.com/InterlynkIo)

## Stargazers

If sbomdelta helps you in explainaing why vulnerability counts differ between "upstream" & "hardened" images.., please ⭐ this repository!

[![Stargazers](https://starchart.cc/interlynk-io/sbomdelta.svg)](https://starchart.cc/interlynk-io/sbomdelta)

---

**sbomdelta** - sbomdelta is a lightweight CLI tool that explains why vulnerability counts differ between "upstream" & "hardened" images..

Made with ❤️ by [Interlynk.io](https://www.interlynk.io)
