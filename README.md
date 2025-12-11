
# 📦 sbomdelta — Vulnerability Delta Between Upstream & Hardened Images

`sbomdelta` is a **CLI tool written in Go** that calculates the **true vulnerability delta** between:

- An **official upstream base image** (Ubuntu, Alpine, Debian, etc.)
- A **provider hardened image**

It works by comparing:

1. **Package differences**
2. **CVE differences**
3. **Backported fixes (false positives from scanners)**

## Why This Tool Exists

When comparing:

- `ubuntu:22.04`
  vs
- `hardened-provider:22.04`

You may see:

- CVEs disappear because **packages were removed**
- CVEs disappear because of **backported fixes**
- CVEs appear because **new packages were added**
- CVEs appear in both images but with **different severities**
- CVEs that scanners flag but are actually **already patched by the distro**

❗ **Regular vulnerability scanners cannot explain these deltas correctly.**

This tool answers:

- ✅ *Which CVEs were really eliminated?*
- ✅ *Which are new regressions?*
- ✅ *Which are fake results due to backports?*
- ✅ *Which packages caused the delta?*

## What sbomdelta Measures

The delta is calculated in **three dimensions**:

### 1️⃣ Package Delta

| Case                                 | Meaning                          |
| ------------------------------------ | -------------------------------- |
| Package present in **upstream only** | ✔️ Attack surface **reduced**    |
| Package present in **hardened only** | ⚠️ New attack surface introduced |
| Package present in **both**          | Neutral                          |

### 2️⃣ CVE Delta

For every `(package + CVE)` pair:

| Status               | Meaning                        |
| -------------------- | ------------------------------ |
| `ONLY_UPSTREAM`      | ✅ Vulnerability mitigated      |
| `ONLY_HARDENED`      | ❌ New vulnerability introduced |
| `BOTH_SAME_SEVERITY` | ⚠️ No security improvement     |
| `BOTH_DIFF_SEVERITY` | ⚠️ Severity changed            |

### 3️⃣ Backport Delta (False Positives)

Many Linux distros **patch CVEs without changing versions**.

Scanners report:

```
CVE-XXXX present ❌
```

But distro says:

```
CVE-XXXX already fixed ✅
```

This causes **false positives**.

If you provide an optional **backport exception file**, sbomdelta will:

✅ Detect them
✅ Remove them from delta calculation
✅ Report how many false positives were found

## Supported Input Formats

### SBOM Formats

| Format         | Supported |
| -------------- | --------- |
| CycloneDX JSON | ✅         |
| SPDX JSON      | ✅         |

### Vulnerability Scanner Formats

| Scanner    | Supported |
| ---------- | --------- |
| Trivy JSON | ✅         |
| Grype JSON | ✅         |

### 🔍 Backport Exception File (Optional)

| Type       | Supported |
| ---------- | --------- |
| Trivy JSON | ✅         |
| Grype JSON | ✅         |

Used to suppress **backported CVEs**

## 🧠 How the Delta is Computed

High-level data flow:

```text
Upstream Image  → SBOM → Vulnerabilities
Hardened Image  → SBOM → Vulnerabilities
Backport File   → Optional Suppression

→ Package Delta
→ CVE Delta
→ Backport Delta
→ Final Metrics + Colored Report
```

## 🧱 Project Structure

```bash
.
├── cmd
│   └── root.go
├── main.go
├── pkg
│   ├── delta        # Core delta logic
│   ├── internal     # Internal types & helpers
│   ├── reporter     # Colored CLI output
│   ├── sbom         # CycloneDX & SPDX loaders
│   ├── vuln         # Trivy & Grype loaders
│   └── types        # Shared enums + configs
└── README.md
```

## 🚀 CLI Usage

### Basic Usage (No Backport File)

```bash
sbomdelta eval \
  --up-sbom upstream.cdx.json \
  --hd-sbom hardened.cdx.json \
  --up-vuln upstream-trivy.json \
  --hd-vuln hardened-trivy.json
```

### With Backport Suppression

```bash
sbomdelta eval \
  --up-sbom upstream.cdx.json \
  --hd-sbom hardened.cdx.json \
  --up-vuln upstream-trivy.json \
  --hd-vuln hardened-trivy.json \
  --bc-vuln backports.json
```

### Run from Go Source

```bash
go run main.go eval \
  --up-sbom upstream.cdx.json \
  --hd-sbom hardened.cdx.json \
  --up-vuln upstream.json \
  --hd-vuln hardened.json \
  --bc-vuln backports.json
```

## 🎯 Flags Reference

| Flag        | Description                        |
| ----------- | ---------------------------------- |
| `--up-sbom` | Upstream SBOM JSON                 |
| `--hd-sbom` | Hardened SBOM JSON                 |
| `--up-vuln` | Upstream vulnerability report      |
| `--hd-vuln` | Hardened vulnerability report      |
| `--bc-vuln` | (Optional) Backport exception file |

## Output

### Summary Metrics

- Removed packages
- Added packages
- Total upstream CVEs
- Total hardened CVEs
- CVEs eliminated
- New CVEs introduced
- High/Critical reductions
- High/Critical regressions
- False positives due to backports

### Detailed Delta Table (Colorized)

| PACKAGE@VER | CVE           | STATUS          | UPSTREAM | HARDENED |
| ----------- | ------------- | --------------- | -------- | -------- |
| openssl@3.0 | CVE-2024-1234 | ONLY_UPSTREAM ✅ | HIGH     | –        |
| curl@8.1    | CVE-2023-9876 | ONLY_HARDENED ❌ | –        | CRITICAL |
| bash@5.2    | CVE-2022-5555 | BOTH_SAME ⚠️    | MEDIUM   | MEDIUM   |
