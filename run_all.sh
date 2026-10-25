#!/usr/bin/env bash
# Reproduce the whole experiment (Linux/macOS or Git Bash on Windows).
# Requirements: git, Node.js 18+, Python 3.10+, pip install -r requirements.txt
set -euo pipefail
mkdir -p ext results

# 1) (optional) regenerate SBOMs from the lockfiles with cdxgen 11.11.0
#    npx @cyclonedx/cdxgen@11.11.0 -t js -t php --no-install-deps --spec-version 1.5 \
#        -o data/sbom/<app>.cdx.json data/lockfiles/<app>
#    (The SBOMs used in the report are already in data/sbom/.)

# 2) GitHub Advisory Database, reviewed advisories (snapshot of 17 Oct 2026, commit 514b2dae7d)
if [ ! -d ext/advisory-database ]; then
  git clone --filter=blob:none --sparse https://github.com/github/advisory-database.git ext/advisory-database
  git -C ext/advisory-database sparse-checkout set advisories/github-reviewed
  git -C ext/advisory-database checkout 514b2dae7d
fi

# 3) CVSS + EPSS + CISA KEV snapshots (cvss-bt dataset): T0 = 15 Oct 2025, NOW = 16 Oct 2026
if [ ! -f ext/cvssbt_now.csv ]; then
  git clone --filter=blob:none --no-checkout https://github.com/t0sche/cvss-bt.git ext/cvss-bt
  git -C ext/cvss-bt show 32fa4a1:cvss-bt.csv > ext/cvssbt_t0.csv
  git -C ext/cvss-bt show cadc4ae:cvss-bt.csv > ext/cvssbt_now.csv
fi

python code/match_vulns.py data/sbom ext/advisory-database/advisories/github-reviewed results/findings_raw.csv
python code/enrich.py results/findings_raw.csv ext/cvssbt_t0.csv ext/cvssbt_now.csv results/findings_enriched.csv
python code/analyze.py results/findings_enriched.csv data/sbom results data/lockfiles | tee results/analysis_log.txt
python code/validate_npm_audit.py results/findings_raw.csv results/npm_audit results/table_validation.csv
