"""Experiment: CVSS-only vs. exploitation-aware ranking of SBOM findings.

Usage:
    python analyze.py <findings_enriched.csv> <sbom_dir> <out_dir> <lockfile_dir>

Part A  alert volume and share of findings in development-only dependencies
Part B  ranking comparison with current data (Oct 2026)
Part C  temporal validation: rank with T0 data (Oct 2025), check exploitation that
        appeared after T0 (new CISA KEV entry or new Metasploit / Exploit-DB / Nuclei exploit)
"""
import glob
import json
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from cvss import CVSS3
from scipy import stats

W_CVSS, W_EPSS, W_KEV = 0.4, 0.4, 0.2   # weights of the combined score (fixed before the experiment)
PROJECTS = ["ghostfolio", "actual", "firefly-iii", "akaunting", "invoiceninja"]
LABEL = {"ghostfolio": "Ghostfolio", "actual": "Actual Budget", "firefly-iii": "Firefly III",
         "akaunting": "Akaunting", "invoiceninja": "Invoice Ninja"}


def dev_map(lock_dir, project):
    """(package, version) -> True if the package appears ONLY as a development dependency.

    Read directly from the lockfiles: npm package-lock.json ("dev": true) and
    composer.lock ("packages-dev"). yarn.lock has no such information (returns None).
    """
    d = os.path.join(lock_dir, project)
    flags = {}
    pl = os.path.join(d, "package-lock.json")
    if os.path.exists(pl):
        for path, meta in json.load(open(pl)).get("packages", {}).items():
            if not path or "node_modules/" not in path:
                continue
            name = path.rsplit("node_modules/", 1)[1]
            key = (name.lower(), meta.get("version", ""))
            is_dev = bool(meta.get("dev")) or bool(meta.get("devOptional"))
            flags[key] = flags.get(key, True) and is_dev
    cl = os.path.join(d, "composer.lock")
    if os.path.exists(cl):
        lock = json.load(open(cl))
        for section, is_dev in (("packages", False), ("packages-dev", True)):
            for pkg in lock.get(section, []):
                flags[(pkg["name"].lower(), pkg["version"])] = is_dev
    return flags if flags else None


def ghsa_cvss(v):
    try:
        return CVSS3(v).scores()[0]
    except Exception:
        return np.nan


def combined(cvss, epss_pct, kev):
    return W_CVSS * cvss / 10 + W_EPSS * epss_pct + W_KEV * kev.astype(float)


def auc(score, y):
    """Probability that a random positive is ranked above a random negative (ties = 0.5)."""
    pos, neg = score[y], score[~y]
    if len(pos) == 0 or len(neg) == 0:
        return np.nan
    u = stats.mannwhitneyu(pos, neg, alternative="greater")
    return u.statistic / (len(pos) * len(neg)), u.pvalue


def main(findings_csv, sbom_dir, out, lock_dir):
    os.makedirs(out, exist_ok=True)
    f = pd.read_csv(findings_csv)
    f["cvss_now"] = f["base_score_now"].fillna(f["ghsa_cvss3_vector"].map(ghsa_cvss))
    f["epss_pct_now"] = f["epss_pct_now"].fillna(0.0)          # no CVE / no EPSS -> lowest likelihood
    f["exploited_now"] = f["kev_now"] | f["weaponized_now"]
    f["dev_only"] = pd.Series([None] * len(f), dtype=object)
    for p in PROJECTS:
        m = dev_map(lock_dir, p)
        if m is None:
            continue
        idx = f.project == p
        f.loc[idx, "dev_only"] = [m.get((a.lower(), b), False) for a, b in zip(f.loc[idx, "package"], f.loc[idx, "version"])]

    # ---------------- Part A: alert volume ----------------
    rowsA = []
    for p in PROJECTS:
        sb = json.load(open(os.path.join(sbom_dir, f"{p}.cdx.json")))["components"]
        d = f[f.project == p]
        scope_known = p != "actual"   # yarn.lock carries no dev/prod information
        rowsA.append({
            "Project": LABEL[p], "Components": len(sb),
            "Vulnerable components": d.drop_duplicates(["package", "version"]).shape[0],
            "Findings": len(d),
            "Critical/High (CVSS >= 7)": int((d.cvss_now >= 7).sum()),
            "Dev-only findings": int(d.dev_only.astype(float).sum()) if scope_known else np.nan,
            "Dev-only share": round(d.dev_only.astype(float).mean(), 3) if scope_known else np.nan,
            "Exploited now (KEV or public exploit)": int(d.exploited_now.sum()),
        })
    A = pd.DataFrame(rowsA)
    A.to_csv(f"{out}/table_A_alerts.csv", index=False)
    print(A.to_string(index=False))

    # ---------------- Part B: ranking with current data ----------------
    rowsB = []
    for p in PROJECTS:
        d = f[f.project == p].copy()
        d["r_cvss"] = (-d.cvss_now.fillna(0)).rank(method="average")
        d["s_comb"] = combined(d.cvss_now.fillna(0), d.epss_pct_now, d.kev_now)
        d["r_comb"] = (-d.s_comb).rank(method="average")
        top_c = set(d.nsmallest(10, "r_cvss").index)
        top_m = set(d.nsmallest(10, "r_comb").index)
        e = d[d.exploited_now]
        rowsB.append({
            "Project": LABEL[p], "Findings": len(d), "Exploited": len(e),
            "Median rank of exploited (CVSS-only)": e.r_cvss.median(),
            "Median rank of exploited (combined)": e.r_comb.median(),
            "Items to review to cover all exploited (CVSS-only)": e.r_cvss.max(),
            "Items to review to cover all exploited (combined)": e.r_comb.max(),
            "Top-10 overlap": len(top_c & top_m),
            "Spearman rho between rankings": round(stats.spearmanr(d.r_cvss, d.r_comb)[0], 2),
        })
        f.loc[d.index, ["r_cvss", "r_comb"]] = d[["r_cvss", "r_comb"]]
    B = pd.DataFrame(rowsB)
    B.to_csv(f"{out}/table_B_ranking_now.csv", index=False)
    print(B.to_string(index=False))

    # ---------------- Part C: temporal validation ----------------
    t = f[f.in_t0_snapshot].copy()
    t["cvss_t0"] = t["cvss_t0"].fillna(0)
    t = t.sort_values("cvss_t0", ascending=False).drop_duplicates("cve")   # one row per CVE
    y = t["new_exploitation_after_t0"].to_numpy(bool)
    scores = {
        "CVSS only": t["cvss_t0"].to_numpy(),
        "EPSS only": t["epss_pct_t0"].to_numpy(),
        "Combined (CVSS+EPSS+KEV)": combined(t["cvss_t0"], t["epss_pct_t0"], t["kev_t0"]).to_numpy(),
    }
    rng = np.random.default_rng(42)
    pos_idx, neg_idx = np.where(y)[0], np.where(~y)[0]
    rowsC = []
    for name, s in scores.items():
        a, pv = auc(s, y)
        r = pd.Series(-s).rank(method="average").to_numpy()
        boot = []
        for _ in range(5000):   # stratified bootstrap
            i = np.concatenate([rng.choice(pos_idx, len(pos_idx)), rng.choice(neg_idx, len(neg_idx))])
            boot.append(auc(s[i], y[i])[0])
        rowsC.append({
            "Ranking": name, "AUC": round(a, 3),
            "95% CI": f"[{np.percentile(boot, 2.5):.2f}, {np.percentile(boot, 97.5):.2f}]",
            "p (AUC > 0.5)": round(pv, 4),
            "Ranks of exploited CVEs": ", ".join(str(int(v)) if v == int(v) else str(v) for v in sorted(r[y])),
            "Recall@20": round((r[y] <= 20).mean(), 2),
        })
        t[f"rank_{name}"] = r
    C = pd.DataFrame(rowsC)
    C.to_csv(f"{out}/table_C_temporal.csv", index=False)
    print(f"Temporal validation: {len(t)} unique CVEs known at T0, {y.sum()} with new exploitation after T0")
    print(C.to_string(index=False))
    t[t.new_exploitation_after_t0][["cve", "package", "cvss_t0", "epss_t0", "epss_pct_t0", "kev_t0", "kev_now",
                                    "weaponized_t0", "weaponized_now"] + [f"rank_{n}" for n in scores]] \
        .to_csv(f"{out}/table_C_positives.csv", index=False)
    f.to_csv(f"{out}/findings_final.csv", index=False)

    # ---------------- Figures ----------------
    plt.rcParams.update({"font.size": 9})
    # Fig 1: findings per project, production vs dev-only
    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    labels = [LABEL[p] for p in PROJECTS]
    prod = [((f.project == p) & (f.dev_only == False)).sum() for p in PROJECTS]
    dev = [((f.project == p) & (f.dev_only == True)).sum() for p in PROJECTS]
    unk = [(f.project == p).sum() if p == "actual" else 0 for p in PROJECTS]
    ax.barh(labels, prod, color="#2b6cb0", label="Production dependency")
    ax.barh(labels, dev, left=prod, color="#90cdf4", label="Development-only dependency")
    ax.barh(labels, unk, color="#cbd5e0", label="Scope unknown (yarn.lock)")
    ax.invert_yaxis()
    ax.set_xlabel("Vulnerability findings (component–advisory pairs)")
    ax.set_title("Findings per application by dependency scope")
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.45, -0.22), ncol=3)
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{out}/fig1_findings_scope.png", dpi=200, bbox_inches="tight")
    plt.close()

    # Fig 2: relative position (% of the list) of currently exploited vulnerabilities
    e = f[f.exploited_now].copy()
    n_per = f.groupby("project").size()
    e["pos_cvss"] = 100 * e.r_cvss / e.project.map(n_per)
    e["pos_comb"] = 100 * e.r_comb / e.project.map(n_per)
    g = e.groupby(["cve", "package"]).agg(pos_cvss=("pos_cvss", "median"), pos_comb=("pos_comb", "median"),
                                          apps=("project", "nunique")).reset_index()
    g["label"] = g["package"] + " · " + g["cve"] + " (" + g["apps"].astype(str) + " app" + np.where(g.apps > 1, "s", "") + ")"
    g = g.sort_values("pos_comb")
    fig, ax = plt.subplots(figsize=(6.4, 0.3 * len(g) + 1.3))
    yy = np.arange(len(g))
    ax.hlines(yy, g.pos_comb, g.pos_cvss, color="#a0aec0", lw=1.2)
    ax.scatter(g.pos_cvss, yy, color="#c05621", s=24, label="CVSS-only ranking", zorder=3)
    ax.scatter(g.pos_comb, yy, color="#2b6cb0", s=24, label="Combined ranking (CVSS+EPSS+KEV)", zorder=3)
    ax.set_yticks(yy)
    ax.set_yticklabels(g["label"], fontsize=7.5)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Median position in remediation list (% of findings, 0 = fix first)")
    ax.set_title("Currently exploited vulnerabilities: position in each ranking")
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.4, -0.16), ncol=2)
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{out}/fig2_exploited_ranks.png", dpi=200, bbox_inches="tight")
    plt.close()


if __name__ == "__main__":
    main(*sys.argv[1:5])
