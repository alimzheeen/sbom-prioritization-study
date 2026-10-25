# SBOM-based vulnerability prioritization — small-scale empirical study

Supplementary material for *Research Methods and Tools, Assignment 4* (Astana IT University).
Research topic: **SBOM-Based Identification and Prioritization of Vulnerable Software Dependencies in Financial Organizations**.

**Research question.** For vulnerabilities found through SBOM analysis of finance-related open-source applications, does an exploitation-aware ranking (CVSS + EPSS + CISA KEV) prioritize exploited vulnerabilities better than a ranking by CVSS alone?

## Data

| Application | Domain | Release analysed | Ecosystems |
|---|---|---|---|
| Ghostfolio 2.114.0 | Wealth management | 10 Oct 2024 | npm |
| Actual Budget 24.10.1 | Personal budgeting | 8 Oct 2024 | npm (yarn) |
| Firefly III 6.1.21 | Personal finance manager | 29 Sep 2024 | Composer + npm |
| Akaunting 3.1.12 | Accounting | 9 Oct 2024 | Composer + npm |
| Invoice Ninja 5.10.33 | Invoicing and payments | 10 Oct 2024 | Composer + npm |

- `data/lockfiles/` – lockfiles and manifests taken from the release tags on GitHub
- `data/sbom/` – CycloneDX 1.5 SBOMs generated with cdxgen 11.11.0
- Vulnerability data: GitHub Advisory Database (reviewed advisories, commit `514b2dae7d`, 17 Oct 2026)
- CVSS, EPSS, CISA KEV and public-exploit flags: [cvss-bt](https://github.com/t0sche/cvss-bt) snapshots of 15 Oct 2025 (T0, commit `32fa4a1`) and 16 Oct 2026 (commit `cadc4ae`)

## Code

| Script | What it does |
|---|---|
| `code/match_vulns.py` | Matches every npm/Composer component in an SBOM against advisory version ranges |
| `code/validate_npm_audit.py` | Compares the matcher with `npm audit` (reference scanner) |
| `code/enrich.py` | Adds CVSS, EPSS, KEV and exploit evidence at T0 and now |
| `code/analyze.py` | Experiment: alert volume, CVSS-only vs combined ranking, temporal validation, figures |

Run everything: `pip install -r requirements.txt && bash run_all.sh`

## Results

`results/table_*.csv`, `results/fig*.png`, `results/findings_final.csv` (one row per finding).
