"""Enrich SBOM findings with CVSS, EPSS and CISA KEV data at two points in time.

Usage:
    python enrich.py <findings_raw.csv> <cvssbt_t0.csv> <cvssbt_now.csv> <out_csv>

T0  = snapshot of 15 Oct 2025 (used to RANK vulnerabilities)
NOW = snapshot of 16 Oct 2026 (used only to check what happened AFTER T0)
Data source: cvss-bt dataset (NVD CVSS + FIRST EPSS + CISA KEV + exploit sources).
"""
import sys

import pandas as pd
from cvss import CVSS3

COLS = ["cve", "base_score", "epss", "cisa_kev", "exploitdb", "metasploit", "nuclei", "poc_github", "published_date"]


def load_snapshot(path, tag):
    s = pd.read_csv(path, usecols=COLS, low_memory=False)
    s = s.drop_duplicates("cve")
    # EPSS percentile among ALL CVEs of that snapshot (0..1)
    s["epss_pct"] = s["epss"].rank(pct=True)
    for c in ["cisa_kev", "exploitdb", "metasploit", "nuclei", "poc_github"]:
        s[c] = s[c].astype(str).str.lower().eq("true")
    return s.rename(columns={c: f"{c}_{tag}" for c in s.columns if c != "cve"})


def ghsa_cvss(vector):
    try:
        return CVSS3(vector).scores()[0]
    except Exception:
        return None


def main(raw_csv, t0_csv, now_csv, out_csv):
    f = pd.read_csv(raw_csv)
    f = f.merge(load_snapshot(t0_csv, "t0"), on="cve", how="left")
    f = f.merge(load_snapshot(now_csv, "now"), on="cve", how="left")
    # CVSS at T0: NVD base score, otherwise the CVSS v3 vector from the GitHub advisory
    f["cvss_t0"] = f["base_score_t0"].fillna(f["ghsa_cvss3_vector"].map(ghsa_cvss))
    f["in_t0_snapshot"] = f["epss_t0"].notna()
    exploit = ["exploitdb", "metasploit", "nuclei"]
    f["weaponized_t0"] = f[[f"{c}_t0" for c in exploit]].fillna(False).any(axis=1)
    f["weaponized_now"] = f[[f"{c}_now" for c in exploit]].fillna(False).any(axis=1)
    f["kev_t0"] = f["cisa_kev_t0"].fillna(False)
    f["kev_now"] = f["cisa_kev_now"].fillna(False)
    # Ground truth: NEW exploitation evidence that appeared after T0
    f["new_exploitation_after_t0"] = (f["kev_now"] & ~f["kev_t0"]) | (f["weaponized_now"] & ~f["weaponized_t0"])
    f.to_csv(out_csv, index=False)
    print(f"findings={len(f)}  with CVE={f.cve.notna().sum()}  in T0 snapshot={f.in_t0_snapshot.sum()}")


if __name__ == "__main__":
    main(*sys.argv[1:5])
