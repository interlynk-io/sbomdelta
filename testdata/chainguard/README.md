# How to reproduce it ?

```bash
syft node:20-alpine -o cyclonedx-json > upstream-sbom.cdx.json
syft cgr.dev/chainguard/node:latest -o cyclonedx-json > hardened-sbom.cdx.json

trivy image -q --format json --scanners vuln node:20-alpine > upstream-vuln.trivy.json
trivy image -q --format json --scanners vuln cgr.dev/chainguard/node:latest > hardened-vuln.trivy.json
```

## sbomdelta

```bash
go run main.go eval \                                                               
  --up-sbom=testdata/chainguard/upstream-sbom.cdx.json \
  --hd-sbom=testdata/chainguard/hardened-sbom.cdx.json \
  --up-vuln=testdata/chainguard/upstream-vuln.trivy.json \
  --hd-vuln=testdata/chainguard/hardened-vuln.trivy.json
```

o/p:

```text
=== SBOM / Vulnerability Delta Summary ===

Packages:
  Removed in hardened: 430
  Added in hardened:   1648
  Common:              69

CVEs:
  Upstream total:   3
  Hardened total:   0
  Only upstream:    3
  Only hardened:    0
  Present in both:  0
  High/Crit removed:2
  High/Crit new:    0

=== Vulnerability Delta Detail ===
PACKAGE@VERSION                          CVE                  STATUS                 UPSTREAM   HARDENED  
--------------------------------------------------------------------------------------------------------------
brace-expansion@2.0.1                    CVE-2025-5889        ONLY_UPSTREAM LOW                  
cross-spawn@7.0.3                        CVE-2024-21538       ONLY_UPSTREAM HIGH                 
glob@10.4.2                              CVE-2025-64756       ONLY_UPSTREAM HIGH                 
```
