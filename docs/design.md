# How sbomdelta Works

The delta is computed across **three dimensions**:

## 1. Package Delta

(From **SBOM comparison** — the ground truth of installed software)

| Condition                | Meaning                                |
| ------------------------ | -------------------------------------- |
| Present in upstream only | Package was **removed** in hardened    |
| Present in hardened only | Package was **introduced** in hardened |
| Present in both          | Package **unchanged**                  |

This directly influences CVEs:

* **Removed packages → removed CVEs**
* **Added packages → new CVEs**
* **Common packages → shared CVEs**

## 2. CVE Delta

(From scanner results mapped to package keys)

For every `(package, version, CVE)` pair:

| Status               | Meaning                         |
| -------------------- | ------------------------------- |
| `ONLY_UPSTREAM`      | Vulnerability no longer present |
| `ONLY_HARDENED`      | New vulnerability introduced    |
| `BOTH_SAME_SEVERITY` | No improvement                  |
| `BOTH_DIFF_SEVERITY` | Severity changed                |

This reveals whether the hardened image **actually improved security**.

## 3. Backport Delta

(Optional. Helps identify **false positives**.)

Linux distros often patch a CVE **without changing the version number**.

If you provide a backport exception file (Trivy/Grype JSON):

* sbomdelta suppresses those CVEs
* reports how many false positives were found

## Linking Package Delta → CVE Delta

sbomdelta explicitly computes:

| Insight                        | Meaning                                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------------------- |
| **CVEs from removed packages** | These disappeared because hardened removed the package—not because scanner says “fixed.” |
| **CVEs from added packages**   | Hardened introduced new components that brought new CVEs.                                |
| **CVEs on common packages**    | True CVEs that exist in both images; unaffected by hardening.                            |

This is the missing context scanners lack.
