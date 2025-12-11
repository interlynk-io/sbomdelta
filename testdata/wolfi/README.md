# Steps

```bash
syft ubuntu:22.04 -o cyclonedx-json > upstream-sbom.cdx.json
syft cgr.dev/chainguard/wolfi-base:latest -o cyclonedx-json > hardened-sbom.cdx.json

trivy image -q --format json --scanners vuln ubuntu:22.04 > upstream-vuln.trivy.json
trivy image -q --format json --scanners vuln cgr.dev/chainguard/wolfi-base:latest > hardened-vuln.trivy.json
```

## sbomdelta

```bash
go run main.go eval \
  --up-sbom=testdata/wolfi/upstream-sbom.cdx.json \
  --hd-sbom=testdata/wolfi/hardened-sbom.cdx.json \
  --up-vuln=testdata/wolfi/upstream-vuln.trivy.json \
  --hd-vuln=testdata/wolfi/hardened-vuln.trivy.json
```

o/p:

```text
=== SBOM / Vulnerability Delta Summary ===

Packages:
  Removed in hardened: 2378
  Added in hardened:   81
  Common:              15

CVEs:
  Upstream total:   26
  Hardened total:   0
  Only upstream:    26
  Only hardened:    0
  Present in both:  0
  High/Crit removed:0
  High/Crit new:    0

=== Vulnerability Delta Detail ===
PACKAGE@VERSION                          CVE                  STATUS                 UPSTREAM   HARDENED  
--------------------------------------------------------------------------------------------------------------
coreutils@8.32-4.1ubuntu1.2              CVE-2016-2781        ONLY_UPSTREAM LOW                  
gcc-12-base@12.3.0-1ubuntu1~22.04.2      CVE-2022-27943       ONLY_UPSTREAM LOW                  
gpgv@2.2.27-3ubuntu2.4                   CVE-2022-3219        ONLY_UPSTREAM LOW                  
libgcc-s1@12.3.0-1ubuntu1~22.04.2        CVE-2022-27943       ONLY_UPSTREAM LOW                  
libgcrypt20@1.9.4-3ubuntu3               CVE-2024-2236        ONLY_UPSTREAM LOW                  
libncurses6@6.3-2ubuntu0.1               CVE-2023-50495       ONLY_UPSTREAM LOW                  
libncursesw6@6.3-2ubuntu0.1              CVE-2023-50495       ONLY_UPSTREAM LOW                  
libpam-modules-bin@1.4.0-11ubuntu2.6     CVE-2025-8941        ONLY_UPSTREAM MEDIUM               
libpam-modules@1.4.0-11ubuntu2.6         CVE-2025-8941        ONLY_UPSTREAM MEDIUM               
libpam-runtime@1.4.0-11ubuntu2.6         CVE-2025-8941        ONLY_UPSTREAM MEDIUM               
libpam0g@1.4.0-11ubuntu2.6               CVE-2025-8941        ONLY_UPSTREAM MEDIUM               
libpcre2-8-0@10.39-3ubuntu0.1            CVE-2022-41409       ONLY_UPSTREAM LOW                  
libpcre3@2:8.39-13ubuntu0.22.04.1        CVE-2017-11164       ONLY_UPSTREAM LOW                  
libssl3@3.0.2-0ubuntu1.20                CVE-2024-41996       ONLY_UPSTREAM LOW                  
libstdc++6@12.3.0-1ubuntu1~22.04.2       CVE-2022-27943       ONLY_UPSTREAM LOW                  
libsystemd0@249.11-0ubuntu3.17           CVE-2023-7008        ONLY_UPSTREAM LOW                  
libtinfo6@6.3-2ubuntu0.1                 CVE-2023-50495       ONLY_UPSTREAM LOW                  
libudev1@249.11-0ubuntu3.17              CVE-2023-7008        ONLY_UPSTREAM LOW                  
libzstd1@1.4.8+dfsg-3build1              CVE-2022-4899        ONLY_UPSTREAM LOW                  
login@1:4.8.1-2ubuntu2.2                 CVE-2023-29383       ONLY_UPSTREAM LOW                  
login@1:4.8.1-2ubuntu2.2                 CVE-2024-56433       ONLY_UPSTREAM LOW                  
ncurses-base@6.3-2ubuntu0.1              CVE-2023-50495       ONLY_UPSTREAM LOW                  
ncurses-bin@6.3-2ubuntu0.1               CVE-2023-50495       ONLY_UPSTREAM LOW                  
passwd@1:4.8.1-2ubuntu2.2                CVE-2023-29383       ONLY_UPSTREAM LOW                  
passwd@1:4.8.1-2ubuntu2.2                CVE-2024-56433       ONLY_UPSTREAM LOW                  
tar@1.34+dfsg-1ubuntu0.1.22.04.2         CVE-2025-45582       ONLY_UPSTREAM MEDIUM               

```
